import type { CredentialKind, NormalizedRow } from './normalize'
import { normalizeRow } from './normalize'
import { parseRawText } from './parse'

const OPENAI = 'openai'
const TYPE_OAUTH = 'oauth'
const TYPE_SETUP_TOKEN = 'setup-token'
const AUTH_AGENT = 'agentidentity'
const AUTH_PAT = 'personalaccesstoken'

function rec(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : undefined
}

function str(v: unknown): string {
  return typeof v === 'string' ? v.trim() : v == null ? '' : String(v).trim()
}

function decodeJwtPayload(token: string): Record<string, unknown> | undefined {
  const parts = token.split('.')
  if (parts.length < 2) return undefined
  try {
    const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4))
    const json = atob(b64 + pad)
    const value: unknown = JSON.parse(json)
    return rec(value)
  } catch {
    return undefined
  }
}

function jwtEmailAndAccount(token: string): { email: string; accountId: string; exp?: number } {
  const payload = decodeJwtPayload(token)
  if (!payload) return { email: '', accountId: '' }
  const auth = rec(payload['https://api.openai.com/auth'])
  const exp = typeof payload.exp === 'number' ? payload.exp : undefined
  return {
    email: str(payload.email),
    accountId: str(auth?.chatgpt_account_id ?? auth?.chatgptAccountId),
    exp,
  }
}

function toExpires(value: unknown, jwtExp?: number): string | undefined {
  if (value == null || value === '') {
    return jwtExp && jwtExp > 0 ? new Date(jwtExp * 1000).toISOString() : undefined
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value > 1e12 ? new Date(value).toISOString() : new Date(value * 1000).toISOString()
  }
  const text = str(value)
  if (!text) return undefined
  if (/^\d+$/.test(text)) {
    const n = Number(text)
    return n > 1e12 ? new Date(n).toISOString() : new Date(n * 1000).toISOString()
  }
  return text
}

function isEnvelope(obj: Record<string, unknown>): boolean {
  return Array.isArray(obj.accounts)
}

function isAccount(obj: Record<string, unknown>): boolean {
  return rec(obj.credentials) != null
}

function unwrapData(value: unknown): unknown {
  const obj = rec(value)
  if (!obj) return value
  const data = rec(obj.data)
  if (data && (Array.isArray(data.accounts) || rec(data.credentials))) return data
  return value
}

function collectAccounts(rows: unknown[]): unknown[] | { error: string } {
  if (rows.length === 1) {
    const inner = unwrapData(rows[0])
    const obj = rec(inner)
    if (obj && isEnvelope(obj)) return obj.accounts as unknown[]
    if (obj && isAccount(obj)) return [obj]
    return { error: 'sub2apiInvalid' }
  }
  const accounts: unknown[] = []
  for (const row of rows) {
    const inner = unwrapData(row)
    const obj = rec(inner)
    if (!obj) return { error: 'sub2apiInvalid' }
    if (isEnvelope(obj)) {
      accounts.push(...(obj.accounts as unknown[]))
      continue
    }
    if (isAccount(obj)) {
      accounts.push(obj)
      continue
    }
    return { error: 'sub2apiInvalid' }
  }
  return accounts
}

function flattenAccount(raw: Record<string, unknown>, kind: CredentialKind): Record<string, unknown> | 'skip' {
  const platform = str(raw.platform).toLowerCase()
  if (platform && platform !== OPENAI) return 'skip'

  const creds = rec(raw.credentials) ?? {}
  const extra = rec(raw.extra) ?? {}
  const type = str(raw.type).toLowerCase()
  const authMode = str(creds.auth_mode || creds.authMode).toLowerCase()
  const access = str(creds.access_token ?? creds.accessToken)
  const refresh = str(creds.refresh_token ?? creds.refreshToken)
  const isAgent = authMode === AUTH_AGENT
  const isPat = type === TYPE_SETUP_TOKEN || authMode === AUTH_PAT || access.startsWith('at-')
  const isOauth = !isPat && (type === TYPE_OAUTH || type === '' || Boolean(refresh) || Boolean(access))

  if (kind === 'codex-oauth') {
    if (isPat || isAgent || !isOauth) return 'skip'
  } else if (!isPat) {
    return 'skip'
  }

  const jwt = jwtEmailAndAccount(str(creds.id_token ?? creds.idToken) || access)
  const email = str(creds.email ?? extra.email ?? raw.email) || jwt.email
  const accountId = str(creds.chatgpt_account_id ?? creds.chatgptAccountId ?? creds.account_id ?? creds.accountId ?? extra.chatgpt_account_id) || jwt.accountId
  const expired = toExpires(creds.expires_at ?? creds.expiresAt, jwt.exp)
  const out: Record<string, unknown> = {
    email,
    account_id: accountId,
    access_token: access,
    refresh_token: refresh,
  }
  if (expired != null) out.expired = expired
  if (typeof raw.concurrency === 'number') out.max_concurrency = raw.concurrency
  return out
}

export function parseSub2ApiExport(text: string, kind: CredentialKind): { rows: NormalizedRow[]; parseError?: string } {
  const parsed = parseRawText(text)
  if (parsed.error) return { rows: [], parseError: parsed.error }
  const collected = collectAccounts(parsed.rows)
  if (!Array.isArray(collected)) return { rows: [], parseError: collected.error }
  if (collected.length === 0) return { rows: [], parseError: 'sub2apiNoMatch' }

  const rows: NormalizedRow[] = []
  for (const raw of collected) {
    const obj = rec(raw)
    if (!obj) {
      rows.push({ index: rows.length, raw, error: '行必须是 JSON 对象' })
      continue
    }
    const flat = flattenAccount(obj, kind)
    if (flat === 'skip') continue
    rows.push(normalizeRow(flat, kind, rows.length))
  }
  if (rows.length === 0) return { rows: [], parseError: 'sub2apiNoMatch' }
  return { rows }
}
