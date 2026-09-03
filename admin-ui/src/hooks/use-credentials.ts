import { useInfiniteQuery, useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  getCredentials,
  setCredentialDisabled,
  setCredentialPriority,
  resetCredentialFailure,
  forceRefreshToken,
  getCredentialBalance,
  addCredential,
  deleteCredential,
  getLoadBalancingMode,
  setLoadBalancingMode,
  setCredentialRpm,
  batchSetCredentialRpm,
  getDefaultRpm,
  setDefaultRpm,
  getArmorBreaking,
  setArmorBreaking,
  getMaxRelay,
  setMaxRelay,
  searchLogAccounts,
  getCredentialLogs,
} from '@/api/credentials'
import type {
  AddCredentialRequest,
  CredentialLogQuery,
  SetMaxRelayRequest,
} from '@/types/api'

// 查询凭据列表
export function useCredentials() {
  return useQuery({
    queryKey: ['credentials'],
    queryFn: getCredentials,
    refetchInterval: 30000, // 每 30 秒刷新一次
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

// 搜索日志中心账号
export function useLogAccounts(query: string, enabled: boolean) {
  return useQuery({
    queryKey: ['log-accounts', query],
    queryFn: () => searchLogAccounts(query),
    enabled: enabled && query.trim().length > 0,
    retry: false,
  })
}

// 查询单个账号日志，按时间倒序分页
export function useCredentialLogs(
  id: number | null,
  filters: CredentialLogQuery,
  enabled: boolean
) {
  return useInfiniteQuery({
    queryKey: ['credential-logs', id, filters],
    queryFn: ({ pageParam }) =>
      getCredentialLogs(id!, {
        ...filters,
        ...(pageParam ? { before: pageParam } : {}),
      }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) =>
      lastPage.hasMore ? lastPage.nextCursor ?? undefined : undefined,
    enabled: enabled && id !== null,
    retry: false,
  })
}
