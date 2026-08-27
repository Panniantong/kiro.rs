import { useState, useEffect, useMemo, useRef } from 'react'
import { RefreshCw, LogOut, Moon, Sun, Server, Plus, Upload, FileUp, Trash2, RotateCcw, CheckCircle2, Gauge, Network, Activity, LayoutGrid, Table2, Shuffle, PencilLine } from 'lucide-react'
import { useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { storage } from '@/lib/storage'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { CredentialCard } from '@/components/credential-card'
import { CredentialCompactTable } from '@/components/credential-compact-table'
import { BalanceDialog } from '@/components/balance-dialog'
import { AddCredentialDialog } from '@/components/add-credential-dialog'
import { BatchImportDialog } from '@/components/batch-import-dialog'
import { BatchEditDialog } from '@/components/batch-edit-dialog'
import { KamImportDialog } from '@/components/kam-import-dialog'
import { BatchVerifyDialog, type VerifyResult } from '@/components/batch-verify-dialog'
import {
  useCredentials,
  useDeleteCredential,
  useResetFailure,
  useLoadBalancingMode,
  useSetLoadBalancingMode,
  useDefaultRpm,
  useSetDefaultRpm,
  useBatchSetRpm,
  useArmorBreaking,
  useSetArmorBreaking,
  useProPlusProxyGate,
  useSetProPlusProxyGate,
  useMaxRelay,
  useSetMaxRelay,
} from '@/hooks/use-credentials'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { getCredentialBalance, forceRefreshToken } from '@/api/credentials'
import { extractErrorMessage } from '@/lib/utils'
import type { BalanceResponse } from '@/types/api'

interface DashboardProps {
  onLogout: () => void
}

type CredentialViewMode = 'cards' | 'available-compact' | 'all-compact'

function getInitialCredentialView(): CredentialViewMode {
  const stored = storage.getCredentialView()
  return stored === 'available-compact' || stored === 'all-compact' ? stored : 'cards'
}

export function Dashboard({ onLogout }: DashboardProps) {
  const [selectedCredentialId, setSelectedCredentialId] = useState<number | null>(null)
  const [balanceDialogOpen, setBalanceDialogOpen] = useState(false)
  const [addDialogOpen, setAddDialogOpen] = useState(false)
  const [batchImportDialogOpen, setBatchImportDialogOpen] = useState(false)
  const [kamImportDialogOpen, setKamImportDialogOpen] = useState(false)
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set())
  const [verifyDialogOpen, setVerifyDialogOpen] = useState(false)
  const [batchEditDialogOpen, setBatchEditDialogOpen] = useState(false)
  const [verifying, setVerifying] = useState(false)
  const [verifyProgress, setVerifyProgress] = useState({ current: 0, total: 0 })
  const [verifyResults, setVerifyResults] = useState<Map<number, VerifyResult>>(new Map())
  const [balanceMap, setBalanceMap] = useState<Map<number, BalanceResponse>>(new Map())
  const [loadingBalanceIds, setLoadingBalanceIds] = useState<Set<number>>(new Set())
  const [queryingInfo, setQueryingInfo] = useState(false)
  const [queryInfoProgress, setQueryInfoProgress] = useState({ current: 0, total: 0 })
  const [batchRefreshing, setBatchRefreshing] = useState(false)
  const [batchRefreshProgress, setBatchRefreshProgress] = useState({ current: 0, total: 0 })
  const cancelVerifyRef = useRef(false)
  const [currentPage, setCurrentPage] = useState(1)
  const [viewMode, setViewMode] = useState<CredentialViewMode>(getInitialCredentialView)
  const itemsPerPage = 12
  const [darkMode, setDarkMode] = useState(() => {
    if (typeof window !== 'undefined') {
      return document.documentElement.classList.contains('dark')
    }
    return false
  })

  const queryClient = useQueryClient()
  const { data, isLoading, error, refetch } = useCredentials()
  const { mutate: deleteCredential } = useDeleteCredential()
  const { mutate: resetFailure } = useResetFailure()
  const { data: loadBalancingData, isLoading: isLoadingMode } = useLoadBalancingMode()
  const { mutate: setLoadBalancingMode, isPending: isSettingMode } = useSetLoadBalancingMode()
  const { data: defaultRpmData } = useDefaultRpm()
  const { mutate: setDefaultRpm, isPending: isSettingDefaultRpm } = useSetDefaultRpm()
  const batchSetRpm = useBatchSetRpm()
  const [editingDefaultRpm, setEditingDefaultRpm] = useState(false)
  const [defaultRpmValue, setDefaultRpmValue] = useState('')
  const { data: armorBreakingData, isLoading: isLoadingArmor } = useArmorBreaking()
  const { mutate: setArmorBreaking, isPending: isSettingArmor } = useSetArmorBreaking()
  const { data: proPlusProxyGateData } = useProPlusProxyGate()
  const { mutate: setProPlusProxyGate, isPending: isSettingProPlusProxyGate } = useSetProPlusProxyGate()
  const [proPlusProxyGateEnabled, setProPlusProxyGateEnabled] = useState(true)
  const [maxAccountsPerProxy, setMaxAccountsPerProxy] = useState('2')
  const { data: maxRelayData } = useMaxRelay()
  const { mutate: setMaxRelay, isPending: isSettingMaxRelay } = useSetMaxRelay()
  const [maxRelayEnabled, setMaxRelayEnabled] = useState(false)
  const [maxRelayBaseUrl, setMaxRelayBaseUrl] = useState('')
  const [maxRelayApiKey, setMaxRelayApiKey] = useState('')

  const sortedCredentials = useMemo(() => {
    return [...(data?.credentials || [])].sort((a, b) => {
      if (a.disabled !== b.disabled) return a.disabled ? 1 : -1
      if (a.isCurrent !== b.isCurrent) return a.isCurrent ? -1 : 1
      if (a.priority !== b.priority) return a.priority - b.priority
      return a.id - b.id
    })
  }, [data?.credentials])

  const enabledCredentials = sortedCredentials.filter(credential => !credential.disabled)
  const viewCredentials = viewMode === 'available-compact' ? enabledCredentials : sortedCredentials
  const totalPages = viewMode === 'cards' ? Math.ceil(sortedCredentials.length / itemsPerPage) : 1
  const startIndex = (currentPage - 1) * itemsPerPage
  const endIndex = startIndex + itemsPerPage
  const currentCredentials = viewMode === 'cards'
    ? sortedCredentials.slice(startIndex, endIndex)
    : viewCredentials
  const disabledCredentialCount = sortedCredentials.filter(credential => credential.disabled).length
  const globalCurrentRpm = enabledCredentials.reduce((sum, credential) => sum + credential.currentRpm, 0)
  const globalPeakRpm1h = enabledCredentials.reduce((sum, credential) => sum + credential.peakRpm1h, 0)
  const globalThrottled1h = enabledCredentials.reduce((sum, credential) => sum + credential.throttled1h, 0)
  const selectedDisabledCount = Array.from(selectedIds).filter(id => {
    const credential = data?.credentials.find(c => c.id === id)
    return Boolean(credential?.disabled)
  }).length

  // 当凭据列表变化时重置到第一页
  useEffect(() => {
    setCurrentPage(1)
  }, [data?.credentials.length])

  useEffect(() => {
    storage.setCredentialView(viewMode)
    setCurrentPage(1)
    setSelectedIds(new Set())
  }, [viewMode])

  // CC Test 透传配置加载后回填到本地表单
  useEffect(() => {
    if (maxRelayData) {
      setMaxRelayEnabled(maxRelayData.enabled)
      setMaxRelayBaseUrl(maxRelayData.baseUrl)
      setMaxRelayApiKey(maxRelayData.apiKey)
    }
  }, [maxRelayData])

  useEffect(() => {
    if (proPlusProxyGateData) {
      setProPlusProxyGateEnabled(proPlusProxyGateData.enabled)
      setMaxAccountsPerProxy(String(proPlusProxyGateData.maxAccountsPerProxy))
    }
  }, [proPlusProxyGateData])

  // 只保留当前仍存在的凭据缓存，避免删除后残留旧数据
  useEffect(() => {
    if (!data?.credentials) {
      setBalanceMap(new Map())
      setLoadingBalanceIds(new Set())
      return
    }

    const validIds = new Set(data.credentials.map(credential => credential.id))

    setBalanceMap(prev => {
      const next = new Map<number, BalanceResponse>()
      prev.forEach((value, id) => {
        if (validIds.has(id)) {
          next.set(id, value)
        }
      })
      return next.size === prev.size ? prev : next
    })

    setLoadingBalanceIds(prev => {
      if (prev.size === 0) {
        return prev
      }
      const next = new Set<number>()
      prev.forEach(id => {
        if (validIds.has(id)) {
          next.add(id)
        }
      })
      return next.size === prev.size ? prev : next
    })
  }, [data?.credentials])

  // 紧凑视图自动补齐可用凭据余额；四路并发，避免瞬间打爆上游。
  useEffect(() => {
    if (viewMode === 'cards' || !data?.credentials) return

    const ids = currentCredentials
      .filter(credential =>
        !credential.disabled &&
        !balanceMap.has(credential.id) &&
        !loadingBalanceIds.has(credential.id)
      )
      .map(credential => credential.id)

    if (ids.length === 0) return

    let cancelled = false

    const load = async () => {
      for (let index = 0; index < ids.length; index += 4) {
        if (cancelled) break
        const chunk = ids.slice(index, index + 4)

        setLoadingBalanceIds(prev => new Set([...prev, ...chunk]))
        const results = await Promise.allSettled(chunk.map(id => getCredentialBalance(id)))

        if (cancelled) break
        setBalanceMap(prev => {
          const next = new Map(prev)
          results.forEach((result, resultIndex) => {
            if (result.status === 'fulfilled') {
              next.set(chunk[resultIndex], result.value)
            }
          })
          return next
        })
        setLoadingBalanceIds(prev => {
          const next = new Set(prev)
          chunk.forEach(id => next.delete(id))
          return next
        })
      }
    }

    void load()
    return () => {
      cancelled = true
    }
  }, [viewMode, data?.credentials])

  const toggleDarkMode = () => {
    setDarkMode(!darkMode)
    document.documentElement.classList.toggle('dark')
  }

  const handleViewBalance = (id: number) => {
    setSelectedCredentialId(id)
    setBalanceDialogOpen(true)
  }

  const handleRefresh = () => {
    refetch()
    toast.success('已刷新凭据列表')
  }

  const handleLogout = () => {
    storage.removeApiKey()
    queryClient.clear()
    onLogout()
  }

  // 选择管理
  const toggleSelect = (id: number) => {
    setSelectedIds(previous => {
      const next = new Set(previous)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }

  const invertCurrentViewSelection = () => {
    setSelectedIds(previous => {
      const next = new Set(previous)
      currentCredentials.forEach(credential => {
        if (next.has(credential.id)) {
          next.delete(credential.id)
        } else {
          next.add(credential.id)
        }
      })
      return next
    })
  }

  const deselectAll = () => {
    setSelectedIds(new Set())
  }

  // 批量删除（仅删除已禁用项）
  const handleBatchDelete = async () => {
    if (selectedIds.size === 0) {
      toast.error('请先选择要删除的凭据')
      return
    }

    const disabledIds = Array.from(selectedIds).filter(id => {
      const credential = data?.credentials.find(c => c.id === id)
      return Boolean(credential?.disabled)
    })

    if (disabledIds.length === 0) {
      toast.error('选中的凭据中没有已禁用项')
      return
    }

    const skippedCount = selectedIds.size - disabledIds.length
    const skippedText = skippedCount > 0 ? `（将跳过 ${skippedCount} 个未禁用凭据）` : ''

    if (!confirm(`确定要删除 ${disabledIds.length} 个已禁用凭据吗？此操作无法撤销。${skippedText}`)) {
      return
    }

    let successCount = 0
    let failCount = 0

    for (const id of disabledIds) {
      try {
        await new Promise<void>((resolve, reject) => {
          deleteCredential(id, {
            onSuccess: () => {
              successCount++
              resolve()
            },
            onError: (err) => {
              failCount++
              reject(err)
            }
          })
        })
      } catch (error) {
        // 错误已在 onError 中处理
      }
    }

    const skippedResultText = skippedCount > 0 ? `，已跳过 ${skippedCount} 个未禁用凭据` : ''

    if (failCount === 0) {
      toast.success(`成功删除 ${successCount} 个已禁用凭据${skippedResultText}`)
    } else {
      toast.warning(`删除已禁用凭据：成功 ${successCount} 个，失败 ${failCount} 个${skippedResultText}`)
    }

    deselectAll()
  }

  // 批量恢复异常
  const handleBatchResetFailure = async () => {
    if (selectedIds.size === 0) {
      toast.error('请先选择要恢复的凭据')
      return
    }

    const failedIds = Array.from(selectedIds).filter(id => {
      const cred = data?.credentials.find(c => c.id === id)
      return cred && cred.failureCount > 0
    })

    if (failedIds.length === 0) {
      toast.error('选中的凭据中没有失败的凭据')
      return
    }

    let successCount = 0
    let failCount = 0

    for (const id of failedIds) {
      try {
        await new Promise<void>((resolve, reject) => {
          resetFailure(id, {
            onSuccess: () => {
              successCount++
              resolve()
            },
            onError: (err) => {
              failCount++
              reject(err)
            }
          })
        })
      } catch (error) {
        // 错误已在 onError 中处理
      }
    }

    if (failCount === 0) {
      toast.success(`成功恢复 ${successCount} 个凭据`)
    } else {
      toast.warning(`成功 ${successCount} 个，失败 ${failCount} 个`)
    }

    deselectAll()
  }

  // 批量刷新 Token
  const handleBatchForceRefresh = async () => {
    if (selectedIds.size === 0) {
      toast.error('请先选择要刷新的凭据')
      return
    }

    const enabledIds = Array.from(selectedIds).filter(id => {
      const cred = data?.credentials.find(c => c.id === id)
      return cred && !cred.disabled
    })

    if (enabledIds.length === 0) {
      toast.error('选中的凭据中没有启用的凭据')
      return
    }

    setBatchRefreshing(true)
    setBatchRefreshProgress({ current: 0, total: enabledIds.length })

    let successCount = 0
    let failCount = 0

    for (let i = 0; i < enabledIds.length; i++) {
      try {
        await forceRefreshToken(enabledIds[i])
        successCount++
      } catch {
        failCount++
      }
      setBatchRefreshProgress({ current: i + 1, total: enabledIds.length })
    }

    setBatchRefreshing(false)
    queryClient.invalidateQueries({ queryKey: ['credentials'] })

    if (failCount === 0) {
      toast.success(`成功刷新 ${successCount} 个凭据的 Token`)
    } else {
      toast.warning(`刷新 Token：成功 ${successCount} 个，失败 ${failCount} 个`)
    }

    deselectAll()
  }

  // 一键清除所有已禁用凭据
  const handleClearAll = async () => {
    if (!data?.credentials || data.credentials.length === 0) {
      toast.error('没有可清除的凭据')
      return
    }

    const disabledCredentials = data.credentials.filter(credential => credential.disabled)

    if (disabledCredentials.length === 0) {
      toast.error('没有可清除的已禁用凭据')
      return
    }

    if (!confirm(`确定要清除所有 ${disabledCredentials.length} 个已禁用凭据吗？此操作无法撤销。`)) {
      return
    }

    let successCount = 0
    let failCount = 0

    for (const credential of disabledCredentials) {
      try {
        await new Promise<void>((resolve, reject) => {
          deleteCredential(credential.id, {
            onSuccess: () => {
              successCount++
              resolve()
            },
            onError: (err) => {
              failCount++
              reject(err)
            }
          })
        })
      } catch (error) {
        // 错误已在 onError 中处理
      }
    }

    if (failCount === 0) {
      toast.success(`成功清除所有 ${successCount} 个已禁用凭据`)
    } else {
      toast.warning(`清除已禁用凭据：成功 ${successCount} 个，失败 ${failCount} 个`)
    }

    deselectAll()
  }

  // 查询当前页凭据信息（逐个查询，避免瞬时并发）
  const handleQueryCurrentPageInfo = async () => {
    if (currentCredentials.length === 0) {
      toast.error('当前页没有可查询的凭据')
      return
    }

    const ids = currentCredentials
      .filter(credential => !credential.disabled)
      .map(credential => credential.id)

    if (ids.length === 0) {
      toast.error('当前页没有可查询的启用凭据')
      return
    }

    setQueryingInfo(true)
    setQueryInfoProgress({ current: 0, total: ids.length })

    let successCount = 0
    let failCount = 0

    for (let i = 0; i < ids.length; i++) {
      const id = ids[i]

      setLoadingBalanceIds(prev => {
        const next = new Set(prev)
        next.add(id)
        return next
      })

      try {
        const balance = await getCredentialBalance(id)
        successCount++

        setBalanceMap(prev => {
          const next = new Map(prev)
          next.set(id, balance)
          return next
        })
      } catch (error) {
        failCount++
      } finally {
        setLoadingBalanceIds(prev => {
          const next = new Set(prev)
          next.delete(id)
          return next
        })
      }

      setQueryInfoProgress({ current: i + 1, total: ids.length })
    }

    setQueryingInfo(false)

    if (failCount === 0) {
      toast.success(`查询完成：成功 ${successCount}/${ids.length}`)
    } else {
      toast.warning(`查询完成：成功 ${successCount} 个，失败 ${failCount} 个`)
    }
  }

  // 批量验活
  const handleBatchVerify = async () => {
    if (selectedIds.size === 0) {
      toast.error('请先选择要验活的凭据')
      return
    }

    // 初始化状态
    setVerifying(true)
    cancelVerifyRef.current = false
    const ids = Array.from(selectedIds)
    setVerifyProgress({ current: 0, total: ids.length })

    let successCount = 0

    // 初始化结果，所有凭据状态为 pending
    const initialResults = new Map<number, VerifyResult>()
    ids.forEach(id => {
      initialResults.set(id, { id, status: 'pending' })
    })
    setVerifyResults(initialResults)
    setVerifyDialogOpen(true)

    // 开始验活
    for (let i = 0; i < ids.length; i++) {
      // 检查是否取消
      if (cancelVerifyRef.current) {
        toast.info('已取消验活')
        break
      }

      const id = ids[i]

      // 更新当前凭据状态为 verifying
      setVerifyResults(prev => {
        const newResults = new Map(prev)
        newResults.set(id, { id, status: 'verifying' })
        return newResults
      })

      try {
        const balance = await getCredentialBalance(id)
        successCount++

        // 更新为成功状态
        setVerifyResults(prev => {
          const newResults = new Map(prev)
          newResults.set(id, {
            id,
            status: 'success',
            usage: `${balance.currentUsage}/${balance.usageLimit}`
          })
          return newResults
        })
      } catch (error) {
        // 更新为失败状态
        setVerifyResults(prev => {
          const newResults = new Map(prev)
          newResults.set(id, {
            id,
            status: 'failed',
            error: extractErrorMessage(error)
          })
          return newResults
        })
      }

      // 更新进度
      setVerifyProgress({ current: i + 1, total: ids.length })

      // 添加延迟防止封号（最后一个不需要延迟）
      if (i < ids.length - 1 && !cancelVerifyRef.current) {
        await new Promise(resolve => setTimeout(resolve, 2000))
      }
    }

    setVerifying(false)

    if (!cancelVerifyRef.current) {
      toast.success(`验活完成：成功 ${successCount}/${ids.length}`)
    }
  }

  // 取消验活
  const handleCancelVerify = () => {
    cancelVerifyRef.current = true
    setVerifying(false)
  }

  // 切换负载均衡模式
  const handleToggleLoadBalancing = () => {
    const currentMode = loadBalancingData?.mode || 'priority'
    const newMode = currentMode === 'priority' ? 'balanced' : 'priority'

    setLoadBalancingMode(newMode, {
      onSuccess: () => {
        const modeName = newMode === 'priority' ? '优先级模式' : '均衡负载模式'
        toast.success(`已切换到${modeName}`)
      },
      onError: (error) => {
        toast.error(`切换失败: ${extractErrorMessage(error)}`)
      }
    })
  }

  // 保存全局默认 RPM
  const handleDefaultRpmSave = () => {
    const trimmed = defaultRpmValue.trim()
    let value: number | null
    if (trimmed === '') {
      value = null
    } else {
      const parsed = parseInt(trimmed, 10)
      if (isNaN(parsed) || parsed < 0) {
        toast.error('RPM 必须是非负整数；留空或 0 表示不限制')
        return
      }
      value = parsed
    }
    setDefaultRpm(value, {
      onSuccess: () => {
        toast.success('全局默认 RPM 已更新')
        setEditingDefaultRpm(false)
      },
      onError: (error) => {
        toast.error(`设置失败: ${extractErrorMessage(error)}`)
      }
    })
  }

  // 切换破甲模式
  const handleToggleArmorBreaking = () => {
    const newEnabled = !(armorBreakingData?.enabled ?? false)

    setArmorBreaking(newEnabled, {
      onSuccess: () => {
        toast.success(newEnabled ? '已开启破甲模式' : '已关闭破甲模式（最小满分版）')
      },
      onError: (error) => {
        toast.error(`切换失败: ${extractErrorMessage(error)}`)
      }
    })
  }

  const handleProPlusProxyGateSave = () => {
    const parsed = Number(maxAccountsPerProxy)
    if (!Number.isInteger(parsed) || parsed <= 0) {
      toast.error('每个代理账号数必须是大于 0 的整数')
      return
    }
    setProPlusProxyGate(
      { enabled: proPlusProxyGateEnabled, maxAccountsPerProxy: parsed },
      {
        onSuccess: () => {
          toast.success(proPlusProxyGateEnabled ? 'PRO+ 代理门禁已开启' : 'PRO+ 代理门禁已关闭')
        },
        onError: (error) => {
          toast.error(`保存失败: ${extractErrorMessage(error)}`)
        }
      }
    )
  }

  // 保存 CC Test 透传配置
  const handleMaxRelaySave = () => {
    const baseUrl = maxRelayBaseUrl.trim()
    const apiKey = maxRelayApiKey.trim()
    // 开启透传时要求 base_url 和 api_key 都填好，避免开了但配置不全
    if (maxRelayEnabled && (baseUrl === '' || apiKey === '')) {
      toast.error('开启 CC Test 透传前请填写 base_url 和 api_key')
      return
    }
    setMaxRelay(
      { enabled: maxRelayEnabled, baseUrl, apiKey },
      {
        onSuccess: () => {
          toast.success(maxRelayEnabled ? '已保存并开启 CC Test 透传' : '已保存（CC Test 透传关闭）')
        },
        onError: (error) => {
          toast.error(`保存失败: ${extractErrorMessage(error)}`)
        }
      }
    )
  }

  // 批量设置 RPM
  const handleBatchSetRpm = () => {
    if (selectedIds.size === 0) {
      toast.error('请先选择要设置的凭据')
      return
    }
    const ids = Array.from(selectedIds)
    const input = window.prompt(
      `为选中的 ${ids.length} 个凭据设置 RPM 上限：\n· 数字（如 10）= 每分钟最多 10 次上游尝试\n· 0 = 不限制\n· 留空 = 跟随全局默认`,
      ''
    )
    if (input === null) return // 取消
    const trimmed = input.trim()
    let rpm: number | null
    if (trimmed === '') {
      rpm = null
    } else {
      const parsed = parseInt(trimmed, 10)
      if (isNaN(parsed) || parsed < 0) {
        toast.error('RPM 必须是非负整数')
        return
      }
      rpm = parsed
    }
    batchSetRpm.mutate(
      { ids, rpm },
      {
        onSuccess: (res) => {
          toast.success(res.message)
          deselectAll()
        },
        onError: (error) => {
          toast.error(`批量设置失败: ${extractErrorMessage(error)}`)
        }
      }
    )
  }
  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
          <p className="text-muted-foreground">加载中...</p>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background p-4">
        <Card className="w-full max-w-md">
          <CardContent className="pt-6 text-center">
            <div className="text-red-500 mb-4">加载失败</div>
            <p className="text-muted-foreground mb-4">{(error as Error).message}</p>
            <div className="space-x-2">
              <Button onClick={() => refetch()}>重试</Button>
              <Button variant="outline" onClick={handleLogout}>重新登录</Button>
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-background">
      {/* 顶部导航 */}
      <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-14 items-center justify-between px-4 md:px-8">
          <div className="flex items-center gap-2">
            <Server className="h-5 w-5" />
            <span className="font-semibold">Kiro Admin</span>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={handleToggleLoadBalancing}
              disabled={isLoadingMode || isSettingMode}
              title="切换负载均衡模式"
            >
              {isLoadingMode ? '加载中...' : (loadBalancingData?.mode === 'priority' ? '优先级模式' : '均衡负载')}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleToggleArmorBreaking}
              disabled={isLoadingArmor || isSettingArmor}
              title="切换破甲模式（关=最小满分版；开=去除上游系统提示词与身份痕迹）"
            >
              {isLoadingArmor ? '加载中...' : (armorBreakingData?.enabled ? '破甲：开' : '破甲：关')}
            </Button>
            <Button variant="ghost" size="icon" onClick={toggleDarkMode}>
              {darkMode ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
            </Button>
            <Button variant="ghost" size="icon" onClick={handleRefresh}>
              <RefreshCw className="h-5 w-5" />
            </Button>
            <Button variant="ghost" size="icon" onClick={handleLogout}>
              <LogOut className="h-5 w-5" />
            </Button>
          </div>
        </div>
      </header>

      {/* 主内容 */}
      <main className="container mx-auto px-4 md:px-8 py-6">
        {/* 统计卡片 */}
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4 mb-6">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                凭据总数
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{data?.total || 0}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                可用凭据
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-600">{data?.available || 0}</div>
            </CardContent>
          </Card>
          <Card className="overflow-hidden border-sky-200/70 bg-gradient-to-br from-sky-50 to-background dark:border-sky-900 dark:from-sky-950/35">
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
                <Activity className="h-4 w-4 text-sky-600" />
                全局 RPM
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="font-mono text-2xl font-bold tabular-nums text-sky-700 dark:text-sky-300">
                {globalCurrentRpm}
              </div>
              <div className="mt-1 text-xs text-muted-foreground">
                近 1h 峰值 {globalPeakRpm1h} · 本地被限 {globalThrottled1h}
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                当前活跃
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold flex items-center gap-2">
                #{data?.currentId || '-'}
                <Badge variant="success">活跃</Badge>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* PRO+ 账号级代理门禁 */}
        <Card className="mb-6">
          <CardContent className="py-4">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <Network className="h-4 w-4 text-muted-foreground" />
                  <span className="text-sm font-medium">PRO+ 账号级代理门禁</span>
                  <Badge variant={proPlusProxyGateEnabled ? 'success' : 'secondary'}>
                    {proPlusProxyGateEnabled ? '默认保护中' : '已关闭'}
                  </Badge>
                </div>
                <p className="text-xs text-muted-foreground">
                  开启后，KIRO PRO+ 必须自动领取并验证账号级代理；代理容量不足时保持禁用。
                </p>
              </div>
              <div className="flex items-center gap-3">
                <label className="flex items-center gap-2 text-sm">
                  <Switch
                    checked={proPlusProxyGateEnabled}
                    onCheckedChange={setProPlusProxyGateEnabled}
                    disabled={isSettingProPlusProxyGate}
                  />
                  启用门禁
                </label>
                <label className="flex items-center gap-2 text-sm">
                  每个代理账号数
                  <Input
                    type="number"
                    min="1"
                    step="1"
                    className="h-8 w-20"
                    value={maxAccountsPerProxy}
                    onChange={(event) => setMaxAccountsPerProxy(event.target.value)}
                    disabled={isSettingProPlusProxyGate}
                  />
                </label>
                <Button
                  size="sm"
                  onClick={handleProPlusProxyGateSave}
                  disabled={isSettingProPlusProxyGate}
                >
                  {isSettingProPlusProxyGate ? '保存中...' : '保存'}
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* 全局默认 RPM 配置 */}
        <Card className="mb-6">
          <CardContent className="py-3">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div className="flex items-center gap-2">
                <Gauge className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm font-medium">全局默认 RPM：</span>
                {editingDefaultRpm ? (
                  <span className="inline-flex items-center gap-1">
                    <Input
                      type="number"
                      value={defaultRpmValue}
                      onChange={(e) => setDefaultRpmValue(e.target.value)}
                      className="w-24 h-8 text-sm"
                      min="0"
                      placeholder="不限制"
                      autoFocus
                    />
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-8 w-8 p-0"
                      onClick={handleDefaultRpmSave}
                      disabled={isSettingDefaultRpm}
                    >
                      ✓
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-8 w-8 p-0"
                      onClick={() => setEditingDefaultRpm(false)}
                    >
                      ✕
                    </Button>
                  </span>
                ) : (
                  <span
                    className="text-sm font-medium cursor-pointer hover:underline"
                    onClick={() => {
                      setDefaultRpmValue(
                        defaultRpmData?.defaultRpm == null ? '' : String(defaultRpmData.defaultRpm)
                      )
                      setEditingDefaultRpm(true)
                    }}
                  >
                    {defaultRpmData?.defaultRpm == null || defaultRpmData?.defaultRpm === 0
                      ? '不限制'
                      : defaultRpmData.defaultRpm}
                    <span className="text-xs text-muted-foreground ml-1">(点击编辑)</span>
                  </span>
                )}
              </div>
              <span className="text-xs text-muted-foreground">未单独设置 RPM 的账号沿用此值</span>
            </div>
          </CardContent>
        </Card>

        {/* CC Test 透传配置 */}
        <Card className="mb-6">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Network className="h-4 w-4 text-muted-foreground" />
              CC Test 透传
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-xs text-muted-foreground">
              开启后，只有识别出的 CC Test 检测请求会原样透传到下方配置的上游渠道；普通用户请求仍走本机 Kiro。
            </p>
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground">base_url</label>
              <Input
                type="text"
                value={maxRelayBaseUrl}
                onChange={(e) => setMaxRelayBaseUrl(e.target.value)}
                placeholder="https://api.example.com"
                className="h-9 text-sm"
              />
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground">api_key</label>
              <Input
                type="password"
                value={maxRelayApiKey}
                onChange={(e) => setMaxRelayApiKey(e.target.value)}
                placeholder="CC Test 透传上游密钥"
                className="h-9 text-sm"
                autoComplete="new-password"
              />
            </div>
            <div className="flex items-center justify-between flex-wrap gap-2 pt-1">
              <div className="flex items-center gap-2">
                <Switch
                  checked={maxRelayEnabled}
                  onCheckedChange={setMaxRelayEnabled}
                  id="max-relay-enabled"
                />
                <label htmlFor="max-relay-enabled" className="text-sm font-medium cursor-pointer">
                  {maxRelayEnabled ? '透传：开' : '透传：关'}
                </label>
              </div>
              <Button
                size="sm"
                onClick={handleMaxRelaySave}
                disabled={isSettingMaxRelay}
              >
                {isSettingMaxRelay ? '保存中...' : '保存'}
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* 凭据列表 */}
        <div className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-4">
              <h2 className="text-xl font-semibold">凭据管理</h2>
              <div className="inline-flex items-center gap-1 rounded-lg border bg-muted/25 p-1">
                <Button
                  size="sm"
                  variant={viewMode === 'cards' ? 'default' : 'ghost'}
                  className="h-8 gap-1.5"
                  onClick={() => setViewMode('cards')}
                >
                  <LayoutGrid className="h-3.5 w-3.5" />
                  卡片
                </Button>
                <Button
                  size="sm"
                  variant={viewMode === 'available-compact' ? 'default' : 'ghost'}
                  className="h-8 gap-1.5"
                  onClick={() => setViewMode('available-compact')}
                >
                  <Table2 className="h-3.5 w-3.5" />
                  可用紧凑 · {enabledCredentials.length}
                </Button>
                <Button
                  size="sm"
                  variant={viewMode === 'all-compact' ? 'default' : 'ghost'}
                  className="h-8 gap-1.5"
                  onClick={() => setViewMode('all-compact')}
                >
                  <Table2 className="h-3.5 w-3.5" />
                  全部紧凑 · {sortedCredentials.length}
                </Button>
              </div>
              {selectedIds.size > 0 && (
                <div className="flex items-center gap-2">
                  <Badge variant="secondary">已选择 {selectedIds.size} 个</Badge>
                  <Button onClick={deselectAll} size="sm" variant="ghost">
                    取消选择
                  </Button>
                </div>
              )}
            </div>
            <div className="flex flex-wrap justify-end gap-2">
              {selectedIds.size > 0 && (
                <>
                  <Button onClick={invertCurrentViewSelection} size="sm" variant="outline">
                    <Shuffle className="h-4 w-4 mr-2" />
                    反选当前视图
                  </Button>
                  <Button onClick={() => setBatchEditDialogOpen(true)} size="sm" variant="outline">
                    <PencilLine className="h-4 w-4 mr-2" />
                    批量编辑
                  </Button>
                  <Button onClick={handleBatchVerify} size="sm" variant="outline">
                    <CheckCircle2 className="h-4 w-4 mr-2" />
                    批量验活
                  </Button>
                  <Button
                    onClick={handleBatchForceRefresh}
                    size="sm"
                    variant="outline"
                    disabled={batchRefreshing}
                  >
                    <RefreshCw className={`h-4 w-4 mr-2 ${batchRefreshing ? 'animate-spin' : ''}`} />
                    {batchRefreshing ? `刷新中... ${batchRefreshProgress.current}/${batchRefreshProgress.total}` : '批量刷新 Token'}
                  </Button>
                  <Button onClick={handleBatchResetFailure} size="sm" variant="outline">
                    <RotateCcw className="h-4 w-4 mr-2" />
                    恢复异常
                  </Button>
                  <Button
                    onClick={handleBatchSetRpm}
                    size="sm"
                    variant="outline"
                    disabled={batchSetRpm.isPending}
                  >
                    <Gauge className="h-4 w-4 mr-2" />
                    批量设置 RPM
                  </Button>
                  <Button
                    onClick={handleBatchDelete}
                    size="sm"
                    variant="destructive"
                    disabled={selectedDisabledCount === 0}
                    title={selectedDisabledCount === 0 ? '只能删除已禁用凭据' : undefined}
                  >
                    <Trash2 className="h-4 w-4 mr-2" />
                    批量删除
                  </Button>
                </>
              )}
              {verifying && !verifyDialogOpen && (
                <Button onClick={() => setVerifyDialogOpen(true)} size="sm" variant="secondary">
                  <CheckCircle2 className="h-4 w-4 mr-2 animate-spin" />
                  验活中... {verifyProgress.current}/{verifyProgress.total}
                </Button>
              )}
              {data?.credentials && data.credentials.length > 0 && (
                <Button
                  onClick={handleQueryCurrentPageInfo}
                  size="sm"
                  variant="outline"
                  disabled={queryingInfo}
                >
                  <RefreshCw className={`h-4 w-4 mr-2 ${queryingInfo ? 'animate-spin' : ''}`} />
                  {queryingInfo ? `查询中... ${queryInfoProgress.current}/${queryInfoProgress.total}` : '查询信息'}
                </Button>
              )}
              {data?.credentials && data.credentials.length > 0 && (
                <Button
                  onClick={handleClearAll}
                  size="sm"
                  variant="outline"
                  className="text-destructive hover:text-destructive"
                  disabled={disabledCredentialCount === 0}
                  title={disabledCredentialCount === 0 ? '没有可清除的已禁用凭据' : undefined}
                >
                  <Trash2 className="h-4 w-4 mr-2" />
                  清除已禁用
                </Button>
              )}
              <Button onClick={() => setKamImportDialogOpen(true)} size="sm" variant="outline">
                <FileUp className="h-4 w-4 mr-2" />
                Kiro Account Manager 导入
              </Button>
              <Button onClick={() => setBatchImportDialogOpen(true)} size="sm" variant="outline">
                <Upload className="h-4 w-4 mr-2" />
                批量导入
              </Button>
              <Button onClick={() => setAddDialogOpen(true)} size="sm">
                <Plus className="h-4 w-4 mr-2" />
                添加凭据
              </Button>
            </div>
          </div>
          {data?.credentials.length === 0 ? (
            <Card>
              <CardContent className="py-8 text-center text-muted-foreground">
                暂无凭据
              </CardContent>
            </Card>
          ) : viewMode === 'cards' ? (
            <>
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                {currentCredentials.map((credential) => (
                  <CredentialCard
                    key={credential.id}
                    credential={credential}
                    onViewBalance={handleViewBalance}
                    selected={selectedIds.has(credential.id)}
                    onToggleSelect={() => toggleSelect(credential.id)}
                    balance={balanceMap.get(credential.id) || null}
                    loadingBalance={loadingBalanceIds.has(credential.id)}
                  />
                ))}
              </div>

              {totalPages > 1 && (
                <div className="flex justify-center items-center gap-4 mt-6">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setCurrentPage(page => Math.max(1, page - 1))}
                    disabled={currentPage === 1}
                  >
                    上一页
                  </Button>
                  <span className="text-sm text-muted-foreground">
                    第 {currentPage} / {totalPages} 页（共 {sortedCredentials.length} 个凭据）
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setCurrentPage(page => Math.min(totalPages, page + 1))}
                    disabled={currentPage === totalPages}
                  >
                    下一页
                  </Button>
                </div>
              )}
            </>
          ) : (
            <CredentialCompactTable
              credentials={currentCredentials}
              balances={balanceMap}
              loadingBalanceIds={loadingBalanceIds}
              selectedIds={selectedIds}
              onToggleSelect={toggleSelect}
            />
          )}
        </div>
      </main>

      {/* 余额对话框 */}
      <BalanceDialog
        credentialId={selectedCredentialId}
        open={balanceDialogOpen}
        onOpenChange={setBalanceDialogOpen}
      />

      {/* 添加凭据对话框 */}
      <AddCredentialDialog
        open={addDialogOpen}
        onOpenChange={setAddDialogOpen}
      />

      {/* 批量导入对话框 */}
      <BatchImportDialog
        open={batchImportDialogOpen}
        onOpenChange={setBatchImportDialogOpen}
      />

      {/* KAM 账号导入对话框 */}
      <KamImportDialog
        open={kamImportDialogOpen}
        onOpenChange={setKamImportDialogOpen}
      />

      <BatchEditDialog
        open={batchEditDialogOpen}
        onOpenChange={setBatchEditDialogOpen}
        credentialIds={Array.from(selectedIds)}
        onCompleted={deselectAll}
      />

      {/* 批量验活对话框 */}
      <BatchVerifyDialog
        open={verifyDialogOpen}
        onOpenChange={setVerifyDialogOpen}
        verifying={verifying}
        progress={verifyProgress}
        results={verifyResults}
        onCancel={handleCancelVerify}
      />
    </div>
  )
}
