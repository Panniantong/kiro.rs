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
  refreshTokenHash?: string
  apiKeyHash?: string
  maskedApiKey?: string
  successCount: number
  lastUsedAt: string | null
  hasProxy: boolean
  proxyUrl?: string
  refreshFailureCount: number
  disabledReason?: string
  endpoint: string
  // 上游尝试 RPM 限流
  rpm: number | null
  effectiveRpm: number | null
  rpmFollowsDefault: boolean
  currentRpm: number
  peakRpm1h: number
  throttled1h: number
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
export interface SetDisabledRequest {
  disabled: boolean
}

export interface SetPriorityRequest {
  priority: number
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
  proxyUrl?: string
  proxyUsername?: string
  proxyPassword?: string
  kiroApiKey?: string
  endpoint?: string
}

// 添加凭据响应
export interface AddCredentialResponse {
  success: boolean
  message: string
  credentialId: number
  email?: string
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

// 上游 Max 渠道透传配置
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
