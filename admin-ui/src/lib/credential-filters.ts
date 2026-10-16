import type { BalanceResponse, CredentialStatusItem } from '@/types/api'

export type CredentialStatusFilter = 'all' | 'enabled' | 'disabled'

export interface CredentialFilters {
  status: CredentialStatusFilter
  /** 积分区间下限（含），空字符串表示不限 */
  balanceMin: string
  /** 积分区间上限（含），空字符串表示不限 */
  balanceMax: string
}

export const EMPTY_CREDENTIAL_FILTERS: CredentialFilters = {
  status: 'all',
  balanceMin: '',
  balanceMax: '',
}

function parseBound(value: string): number | null {
  const trimmed = value.trim()
  if (trimmed === '') return null
  const parsed = Number(trimmed)
  return Number.isFinite(parsed) ? parsed : null
}

/**
 * 账号剩余积分：优先用本页实时查询结果，其次用服务端缓存余额；都没有返回 null。
 * 与列表展示口径一致（剩余积分不低于 0）。
 */
export function remainingCredits(
  credential: CredentialStatusItem,
  balances: Map<number, BalanceResponse>
): number | null {
  const live = balances.get(credential.id)
  if (live) return Math.max(0, live.remaining)
  if (credential.balanceRemaining != null) return Math.max(0, credential.balanceRemaining)
  return null
}

export interface CredentialFilterResult {
  credentials: CredentialStatusItem[]
  /** 是否设置了有效的积分区间 */
  balanceActive: boolean
  /** 设置了积分区间但余额未知、因此被排除的账号数 */
  unknownBalanceExcluded: number
}

/** 按启用状态与积分区间过滤；设置积分区间时余额未知的账号会被排除并计数。 */
export function filterCredentials(
  credentials: CredentialStatusItem[],
  filters: CredentialFilters,
  balances: Map<number, BalanceResponse>
): CredentialFilterResult {
  const min = parseBound(filters.balanceMin)
  const max = parseBound(filters.balanceMax)
  const balanceActive = min !== null || max !== null
  let unknownBalanceExcluded = 0

  const result = credentials.filter(credential => {
    if (filters.status === 'enabled' && credential.disabled) return false
    if (filters.status === 'disabled' && !credential.disabled) return false
    if (!balanceActive) return true

    const remaining = remainingCredits(credential, balances)
    if (remaining === null) {
      unknownBalanceExcluded += 1
      return false
    }
    if (min !== null && remaining < min) return false
    if (max !== null && remaining > max) return false
    return true
  })

  return { credentials: result, balanceActive, unknownBalanceExcluded }
}
