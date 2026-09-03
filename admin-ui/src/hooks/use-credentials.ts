import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  getCredentials,
  setCredentialDisabled,
  setCredentialPriority,
  setCredentialProxy,
  testCredentialProxy,
  resetCredentialFailure,
  forceRefreshToken,
  getCredentialBalance,
  addCredential,
  deleteCredential,
  getLoadBalancingMode,
  setLoadBalancingMode,
  setCredentialRpm,
  batchSetCredentialRpm,
  batchUpdateCredentials,
  getDefaultRpm,
  setDefaultRpm,
  getArmorBreaking,
  setArmorBreaking,
  getProPlusProxyGate,
  setProPlusProxyGate,
  getMaxRelay,
  setMaxRelay,
  getProxyPool,
  testProxyPoolEntry,
  batchGetCredentialBalance,
} from '@/api/credentials'
import type {
  AddCredentialRequest,
  SetCredentialProxyRequest,
  SetMaxRelayRequest,
  SetProPlusProxyGateRequest,
} from '@/types/api'

// 查询凭据列表
export function useCredentials() {
  return useQuery({
    queryKey: ['credentials'],
    queryFn: getCredentials,
    refetchInterval: 30000, // 每 30 秒刷新一次
  })
}

export function useProxyPool() {
  return useQuery({
    queryKey: ['proxyPool'],
    queryFn: getProxyPool,
    refetchInterval: 30000,
  })
}

export function useTestProxyPoolEntry() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (proxyUrl: string) => testProxyPoolEntry(proxyUrl),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['proxyPool'] })
    },
  })
}

export function useBatchCredentialBalance() {
  return useMutation({
    mutationFn: ({ ids, forceRefresh = false }: { ids: number[]; forceRefresh?: boolean }) =>
      batchGetCredentialBalance(ids, forceRefresh),
  })
}

// 查询凭据余额
export function useCredentialBalance(id: number | null) {
  return useQuery({
    queryKey: ['credential-balance', id],
    queryFn: () => getCredentialBalance(id!),
    enabled: id !== null,
    retry: false, // 余额查询失败时不重试（避免重复请求被封禁的账号）
  })
}

// 设置禁用状态
export function useSetDisabled() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, disabled }: { id: number; disabled: boolean }) =>
      setCredentialDisabled(id, disabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] })
    },
  })
}

// 设置优先级
export function useSetPriority() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, priority }: { id: number; priority: number }) =>
      setCredentialPriority(id, priority),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] })
    },
  })
}

// 设置账号代理绑定
export function useSetCredentialProxy() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, req }: { id: number; req: SetCredentialProxyRequest }) =>
      setCredentialProxy(id, req),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] })
    },
  })
}

// 测试账号代理出口
export function useTestCredentialProxy() {
  return useMutation({
    mutationFn: (id: number) => testCredentialProxy(id),
  })
}

// 重置失败计数
export function useResetFailure() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: number) => resetCredentialFailure(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] })
    },
  })
}

// 强制刷新 Token
export function useForceRefreshToken() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: number) => forceRefreshToken(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] })
    },
  })
}

// 添加新凭据
export function useAddCredential() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (req: AddCredentialRequest) => addCredential(req),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] })
    },
  })
}

// 删除凭据
export function useDeleteCredential() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: number) => deleteCredential(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] })
    },
  })
}

// 获取负载均衡模式
export function useLoadBalancingMode() {
  return useQuery({
    queryKey: ['loadBalancingMode'],
    queryFn: getLoadBalancingMode,
  })
}

// 设置负载均衡模式
export function useSetLoadBalancingMode() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: setLoadBalancingMode,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['loadBalancingMode'] })
    },
  })
}

// 设置单个凭据 RPM
export function useSetRpm() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, rpm }: { id: number; rpm: number | null }) =>
      setCredentialRpm(id, rpm),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] })
    },
  })
}

// 批量设置凭据 RPM
export function useBatchSetRpm() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ ids, rpm }: { ids: number[]; rpm: number | null }) =>
      batchSetCredentialRpm(ids, rpm),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] })
    },
  })
}

// 批量更新凭据备注和/或优先级。
export function useBatchUpdateCredentials() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: batchUpdateCredentials,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] })
    },
  })
}

// 查询全局默认 RPM
export function useDefaultRpm() {
  return useQuery({
    queryKey: ['defaultRpm'],
    queryFn: getDefaultRpm,
  })
}

// 设置全局默认 RPM
export function useSetDefaultRpm() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (defaultRpm: number | null) => setDefaultRpm(defaultRpm),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['defaultRpm'] })
      queryClient.invalidateQueries({ queryKey: ['credentials'] })
    },
  })
}

// 获取破甲模式
export function useArmorBreaking() {
  return useQuery({
    queryKey: ['armorBreaking'],
    queryFn: getArmorBreaking,
  })
}

// 设置破甲模式
export function useSetArmorBreaking() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: setArmorBreaking,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['armorBreaking'] })
    },
  })
}

export function useProPlusProxyGate() {
  return useQuery({
    queryKey: ['proPlusProxyGate'],
    queryFn: getProPlusProxyGate,
  })
}

export function useSetProPlusProxyGate() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (req: SetProPlusProxyGateRequest) => setProPlusProxyGate(req),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['proPlusProxyGate'] })
      queryClient.invalidateQueries({ queryKey: ['credentials'] })
    },
  })
}

// 获取 CC Test 透传配置
export function useMaxRelay() {
  return useQuery({
    queryKey: ['maxRelay'],
    queryFn: getMaxRelay,
  })
}

// 设置 CC Test 透传配置
export function useSetMaxRelay() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (req: SetMaxRelayRequest) => setMaxRelay(req),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['maxRelay'] })
    },
  })
}
