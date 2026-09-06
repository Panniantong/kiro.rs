// 凭据状态响应
export interface CredentialsStatusResponse {
  total: number
  available: number
  currentId: number
  defaultRpm: number | null
  credentials: CredentialStatusItem[]
}

// 单个凭据状态
export interface CredentialStatusItem {
  id: number
  priority: number
  disabled: boolean
  failureCount: number
  isCurrent: boolean
  expiresAt: string | null
  authMethod: string | null
  hasProfileArn: boolean
  email?: string
  importNote?: string
  subscriptionTitle?: string
  refreshTokenHash?: string
  apiKeyHash?: string
  maskedApiKey?: string
  successCount: number
  lastUsedAt: string | null
  hasProxy: boolean
  proxyUrl?: string
  refreshFailureCount: number
  disabledReason?: string
  disabledAt?: string | null
  recoveryClass?: 'none' | 'never' | 'conditional' | 'manual'
  recoveryChecks?: string[]
  balanceState?: 'notChecked' | 'fresh' | 'stale' | 'failed'
  balanceCheckedAt?: string | null
  balanceSource?: 'cache' | 'upstream' | null
  balanceErrorClass?: string | null
  balanceRemaining?: number | null
  balanceUsageLimit?: number | null
  balanceNextResetAt?: number | null
  endpoint: string
  // 上游尝试 RPM 限流
  rpm: number | null
  effectiveRpm: number | null
  rpmFollowsDefault: boolean
  currentRpm: number
  inFlightRequests: number
  peakRpm1h: number
  throttled1h: number
  // AWS 侧超额状态（ENABLED / DISABLED；null/缺省 = 未知）
  overageStatus?: string | null
}

// 余额响应
export interface BalanceResponse {
  id: number
  subscriptionTitle: string | null
  currentUsage: number
  usageLimit: number
  remaining: number
  usagePercentage: number

  nextResetAt: number | null
  // 超额（overage）信息（单位均为次数；overageRate 为美元/次）
  overageStatus?: string | null
  currentOverages: number
  overageCap: number
  overageRate: number
}

export interface BatchBalanceRequest {
  ids: number[]
  forceRefresh?: boolean
}

export interface BalanceProbeResult {
  credentialId: number
  state: 'notChecked' | 'fresh' | 'stale' | 'failed'
  balance: BalanceResponse | null
  checkedAt: string | null
  source: 'cache' | 'upstream' | null
  errorClass: string | null
}

export interface BatchBalanceResponse {
  results: BalanceProbeResult[]
}

// 成功响应
export interface SuccessResponse {
  success: boolean
  message: string
}

// 错误响应
export interface AdminErrorResponse {
  error: {
    type: string
    message: string
  }
}

// 请求类型

export interface ProxyProbeSummary {
  state: 'notTested' | 'passed' | 'failed'
  egressIp: string | null
  expectedIp: string | null
  latencyMs: number | null
  failureClass: string | null
  testedAt: string
}

export interface ProxyPoolTestResponse extends ProxyProbeSummary {
  proxyUrl: string
}
export interface SetDisabledRequest {
  disabled: boolean
}

export interface SetPriorityRequest {
  priority: number
}

export interface SetCredentialProxyRequest {
  proxyUrl?: string
  proxyUsername?: string
  proxyPassword?: string
}

export interface BatchSetCredentialProxyRequest extends SetCredentialProxyRequest {
  ids: number[]
}

export interface CredentialProxyTestResponse {
  credentialId: number
  usesProxy: boolean
  usesCredentialProxy: boolean
  proxyUrl?: string
  egressIp: string
  testedAt: string
}

export interface BatchUpdateCredentialsRequest {
  ids: number[]
  importNote?: string
  priority?: number
}

// 添加凭据请求
export interface AddCredentialRequest {
  refreshToken?: string
  authMethod?: 'social' | 'idc' | 'api_key'
  clientId?: string
  clientSecret?: string
  priority?: number
  authRegion?: string
  apiRegion?: string
  machineId?: string
  email?: string
  proxyUrl?: string
  proxyUsername?: string
  proxyPassword?: string
  /** Omit to let eligible KIRO PRO+ accounts receive a pool proxy automatically. */
  assignProxyFromPool?: boolean
  kiroApiKey?: string
  endpoint?: string
  importNote?: string
}

export interface ProxyPoolEligibility {
  eligible: boolean
  subscriptionTitle?: string
  reason: string
}

// 添加凭据响应
export interface AddCredentialResponse {
  success: boolean
  message: string
  credentialId: number
  email?: string
  assignedProxyUrl?: string
  assignedProxyFromPool: boolean
  unknownCount: number
  proxyPoolEligibility?: ProxyPoolEligibility
}

export interface ProxyAssignedCredentialStatus {
  credentialId: number
  email?: string
  subscriptionTitle?: string
  remaining?: number
  usageLimit?: number
  balanceCachedAt?: number
  proxyProbeState: string
  accountProbeState: string
  recoveryState: string
  health: 'healthy' | 'abnormal' | 'unknown'
}

export interface ProxyPoolEntryStatus {
  proxyUrl: string
  assignedCredentialIds: number[]
  assignedCredentials: ProxyAssignedCredentialStatus[]
  assignedCount: number
  remainingSlots: number
  healthyCount: number
  abnormalCount: number
  unknownCount: number
  lastTest?: ProxyProbeSummary | null
}

export interface ProxyPoolResponse {
  maxAccountsPerProxy: number
  total: number
  totalCapacity: number
  assignedSlots: number
  availableSlots: number
  emptyProxyCount: number
  partialProxyCount: number
  fullProxyCount: number
  healthyAssignedCount: number
  abnormalAssignedCount: number
  unknownAssignedCount: number
  pendingCredentialCount: number
  unboundEnabledCount: number
  emptyReason?: string
  proxies: ProxyPoolEntryStatus[]
}

export interface ManualProxyOperationResponse {
  updatedCredentialIds: number[]
  failed: Array<{ credentialId: number; reason: string }>
  pendingCredentialIds: number[]
}

export interface ManualProxyBindRequest {
  proxyUrl: string
  credentialIds: number[]
}

export interface ManualProxyUnbindRequest {
  credentialIds: number[]
}

export interface AddProxyPoolEntriesRequest {
  proxies: SetCredentialProxyRequest[]
}

export interface RemoveProxyPoolEntriesRequest {
  proxyUrls: string[]
}

// RPM 限流请求
export interface SetRpmRequest {
  rpm: number | null
}

export interface BatchSetRpmRequest {
  ids: number[]
  rpm: number | null
}

export interface DefaultRpmResponse {
  defaultRpm: number | null
}

export interface SetDefaultRpmRequest {
  defaultRpm: number | null
}

export interface ProPlusProxyGateResponse {
  enabled: boolean
  maxAccountsPerProxy: number
}

export interface SetProPlusProxyGateRequest {
  enabled: boolean
  maxAccountsPerProxy: number
}

// CC Test 透传配置
export interface MaxRelayResponse {
  enabled: boolean
  baseUrl: string
  apiKey: string
}

export interface SetMaxRelayRequest {
  enabled: boolean
  baseUrl: string
  apiKey: string
}

export interface AccountLogAccount {
  id: number
  email?: string | null
  importNote?: string | null
  disabled: boolean
  disabledReason?: string | null
}

export interface AccountLogAccountSearchResponse {
  accounts: AccountLogAccount[]
}

export type AccountLogSeverity = 'info' | 'warn' | 'error'
export type AccountLogEventType =
  | 'request'
  | 'token_refresh'
  | 'balance'
  | 'credential_status'
  | 'proxy'
  | 'recovery_probe'
export type AccountLogOutcome = 'success' | 'failure' | 'retry' | 'pending'

export interface AccountLogItem {
  id: number
  createdAt: string
  eventType: AccountLogEventType
  severity: AccountLogSeverity
  outcome: AccountLogOutcome
  model: string | null
  apiType: string | null
  errorClass: string | null
  upstreamStatus: number | null
  latencyMs: number | null
  requestId: string | null
  message: string
  details: Record<string, unknown> | null
}

export interface CredentialLogsResponse {
  credentialId: number
  items: AccountLogItem[]
  nextCursor: string | null
  hasMore: boolean
}

export interface CredentialLogQuery {
  severity?: AccountLogSeverity
  eventType?: AccountLogEventType
  outcome?: AccountLogOutcome
  from?: string
  to?: string
  limit?: number
  before?: string
}
