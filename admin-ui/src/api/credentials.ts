import axios from 'axios'
import { storage } from '@/lib/storage'
import type {
  CredentialsStatusResponse,
  BalanceResponse,
  SuccessResponse,
  SetDisabledRequest,
  SetPriorityRequest,
  AddCredentialRequest,
  AddCredentialResponse,
  SetRpmRequest,
  BatchSetRpmRequest,
  DefaultRpmResponse,
  SetDefaultRpmRequest,
  MaxRelayResponse,
  SetMaxRelayRequest,
  AccountLogAccountSearchResponse,
  CredentialLogQuery,
  CredentialLogsResponse,
} from '@/types/api'

// 创建 axios 实例
const api = axios.create({
  baseURL: '/api/admin',
  headers: {
    'Content-Type': 'application/json',
  },
})

// 请求拦截器添加 API Key
api.interceptors.request.use((config) => {
  const apiKey = storage.getApiKey()
  if (apiKey) {
    config.headers['x-api-key'] = apiKey
  }
  return config
})

// 获取所有凭据状态
export async function getCredentials(): Promise<CredentialsStatusResponse> {
  const { data } = await api.get<CredentialsStatusResponse>('/credentials')
  return data
}

// 设置凭据禁用状态
export async function setCredentialDisabled(
  id: number,
  disabled: boolean
): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>(
    `/credentials/${id}/disabled`,
    { disabled } as SetDisabledRequest
  )
  return data
}

// 设置凭据优先级
export async function setCredentialPriority(
  id: number,
  priority: number
): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>(
    `/credentials/${id}/priority`,
    { priority } as SetPriorityRequest
  )
  return data
}

// 重置失败计数
export async function resetCredentialFailure(
  id: number
): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>(`/credentials/${id}/reset`)
  return data
}

// 强制刷新 Token
export async function forceRefreshToken(
  id: number
): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>(`/credentials/${id}/refresh`)
  return data
}

// 获取凭据余额
export async function getCredentialBalance(id: number): Promise<BalanceResponse> {
  const { data } = await api.get<BalanceResponse>(`/credentials/${id}/balance`)
  return data
}

// 添加新凭据
export async function addCredential(
  req: AddCredentialRequest
): Promise<AddCredentialResponse> {
  const { data } = await api.post<AddCredentialResponse>('/credentials', req)
  return data
}

// 删除凭据
export async function deleteCredential(id: number): Promise<SuccessResponse> {
  const { data } = await api.delete<SuccessResponse>(`/credentials/${id}`)
  return data
}

// 获取负载均衡模式
export async function getLoadBalancingMode(): Promise<{ mode: 'priority' | 'balanced' }> {
  const { data } = await api.get<{ mode: 'priority' | 'balanced' }>('/config/load-balancing')
  return data
}

// 设置负载均衡模式
export async function setLoadBalancingMode(mode: 'priority' | 'balanced'): Promise<{ mode: 'priority' | 'balanced' }> {
  const { data } = await api.put<{ mode: 'priority' | 'balanced' }>('/config/load-balancing', { mode })
  return data
}

// 设置单个凭据 RPM（rpm=null 跟随全局默认；0 不限制）
export async function setCredentialRpm(id: number, rpm: number | null): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>(
    `/credentials/${id}/rpm`,
    { rpm } as SetRpmRequest
  )
  return data
}

// 批量设置凭据 RPM
export async function batchSetCredentialRpm(ids: number[], rpm: number | null): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>(
    '/credentials/batch-rpm',
    { ids, rpm } as BatchSetRpmRequest
  )
  return data
}

// 获取全局默认 RPM
export async function getDefaultRpm(): Promise<DefaultRpmResponse> {
  const { data } = await api.get<DefaultRpmResponse>('/config/default-rpm')
  return data
}

// 设置全局默认 RPM
export async function setDefaultRpm(defaultRpm: number | null): Promise<DefaultRpmResponse> {
  const { data } = await api.put<DefaultRpmResponse>(
    '/config/default-rpm',
    { defaultRpm } as SetDefaultRpmRequest
  )
  return data
}

// 获取破甲模式
export async function getArmorBreaking(): Promise<{ enabled: boolean }> {
  const { data } = await api.get<{ enabled: boolean }>('/config/armor-breaking')
  return data
}

// 设置破甲模式
export async function setArmorBreaking(enabled: boolean): Promise<{ enabled: boolean }> {
  const { data } = await api.put<{ enabled: boolean }>('/config/armor-breaking', { enabled })
  return data
}

// 获取 CC Test 透传配置
export async function getMaxRelay(): Promise<MaxRelayResponse> {
  const { data } = await api.get<MaxRelayResponse>('/config/max-relay')
  return data
}

// 设置 CC Test 透传配置
export async function setMaxRelay(req: SetMaxRelayRequest): Promise<MaxRelayResponse> {
  const { data } = await api.put<MaxRelayResponse>('/config/max-relay', req)
  return data
}

// 搜索日志中心的账号候选
export async function searchLogAccounts(
  query: string
): Promise<AccountLogAccountSearchResponse> {
  const { data } = await api.get<AccountLogAccountSearchResponse>('/logs/accounts', {
    params: { query, limit: 20 },
  })
  return data
}

// 获取单个凭据的日志
export async function getCredentialLogs(
  id: number,
  params: CredentialLogQuery = {}
): Promise<CredentialLogsResponse> {
  const { data } = await api.get<CredentialLogsResponse>(`/credentials/${id}/logs`, {
    params: { ...params, limit: 100 },
  })
  return data
}
