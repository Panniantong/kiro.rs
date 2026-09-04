import { useState } from 'react'
import { toast } from 'sonner'
import { RefreshCw, ChevronUp, ChevronDown, Wallet, Trash2, Loader2, Network, ScrollText } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Input } from '@/components/ui/input'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import type { CredentialStatusItem, BalanceResponse } from '@/types/api'
// 禁用原因中文标签（与后端 DisabledReason 对应）
const DISABLED_REASON_LABELS: Record<string, string> = {
  QuotaExceeded: '额度用尽',
  UpstreamSuspended: '上游封停',
  InvalidRefreshToken: 'Token 失效',
  TooManyFailures: '连续失败',
  TooManyRefreshFailures: '刷新失败',
  InvalidConfig: '配置无效',
  Manual: '手动禁用',
}

// 禁用原因对应 Badge 样式：额度/封停/失效 → 红；其他明确原因 → 黄；未知 → 灰
function disabledReasonVariant(reason?: string) {
  if (!reason) return 'secondary'
  if (reason === 'QuotaExceeded' || reason === 'UpstreamSuspended' || reason === 'InvalidRefreshToken') {
    return 'destructive'
  }
  if (reason === 'Manual') return 'secondary'
  return 'warning'
}

function disabledReasonLabel(reason?: string) {
  return reason ? (DISABLED_REASON_LABELS[reason] ?? reason) : '手动/未知'
}
import {
  useSetDisabled,
  useSetPriority,
  useResetFailure,
  useDeleteCredential,
  useForceRefreshToken,
  useSetCredentialProxy,
  useTestCredentialProxy,
  useSetRpm,
} from '@/hooks/use-credentials'

interface CredentialCardProps {
  credential: CredentialStatusItem
  onViewBalance: (id: number) => void
  onViewLogs: (id: number) => void
  selected: boolean
  onToggleSelect: () => void
  balance: BalanceResponse | null
  loadingBalance: boolean
}

function formatLastUsed(lastUsedAt: string | null): string {
  if (!lastUsedAt) return '从未使用'
  const date = new Date(lastUsedAt)
  const now = new Date()
  const diff = now.getTime() - date.getTime()
  if (diff < 0) return '刚刚'
  const seconds = Math.floor(diff / 1000)
  if (seconds < 60) return `${seconds} 秒前`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes} 分钟前`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours} 小时前`
  const days = Math.floor(hours / 24)
  return `${days} 天前`
}

export function CredentialCard({
  credential,
  onViewBalance,
  onViewLogs,
  selected,
  onToggleSelect,
  balance,
  loadingBalance,
}: CredentialCardProps) {
  const [editingPriority, setEditingPriority] = useState(false)
  const [priorityValue, setPriorityValue] = useState(String(credential.priority))
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const [editingRpm, setEditingRpm] = useState(false)
  const [rpmValue, setRpmValue] = useState(credential.rpm == null ? '' : String(credential.rpm))
  const [showProxyDialog, setShowProxyDialog] = useState(false)
  const [proxyUrl, setProxyUrl] = useState(credential.proxyUrl || '')
  const [proxyUsername, setProxyUsername] = useState('')
  const [proxyPassword, setProxyPassword] = useState('')
  const [egressIp, setEgressIp] = useState<string | null>(null)

  const setDisabled = useSetDisabled()
  const setPriority = useSetPriority()
  const resetFailure = useResetFailure()
  const deleteCredential = useDeleteCredential()
  const forceRefresh = useForceRefreshToken()
  const setRpm = useSetRpm()
  const setCredentialProxy = useSetCredentialProxy()
  const testCredentialProxy = useTestCredentialProxy()

  const effectiveRpm = credential.effectiveRpm
  const isAtLimit = effectiveRpm != null && credential.currentRpm >= effectiveRpm

  const handleToggleDisabled = () => {
    setDisabled.mutate(
      { id: credential.id, disabled: !credential.disabled },
      {
        onSuccess: (res) => {
          toast.success(res.message)
        },
        onError: (err) => {
          toast.error('操作失败: ' + (err as Error).message)
        },
      }
    )
  }

  const handlePriorityChange = () => {
    const newPriority = parseInt(priorityValue, 10)
    if (isNaN(newPriority) || newPriority < 0) {
      toast.error('优先级必须是非负整数')
      return
    }
    setPriority.mutate(
      { id: credential.id, priority: newPriority },
      {
        onSuccess: (res) => {
          toast.success(res.message)
          setEditingPriority(false)
        },
        onError: (err) => {
          toast.error('操作失败: ' + (err as Error).message)
        },
      }
    )
  }

  const handleRpmChange = () => {
    const trimmed = rpmValue.trim()
    let rpm: number | null
    if (trimmed === '') {
      rpm = null // 留空 = 跟随全局默认
    } else {
      const parsed = parseInt(trimmed, 10)
      if (isNaN(parsed) || parsed < 0) {
        toast.error('RPM 必须是非负整数；留空表示跟随默认，0 表示不限制')
        return
      }
      rpm = parsed
    }
    setRpm.mutate(
      { id: credential.id, rpm },
      {
        onSuccess: (res) => {
          toast.success(res.message)
          setEditingRpm(false)
        },
        onError: (err) => {
          toast.error('操作失败: ' + (err as Error).message)
        },
      }
    )
  }

  const handleReset = () => {
    resetFailure.mutate(credential.id, {
      onSuccess: (res) => {
        toast.success(res.message)
      },
      onError: (err) => {
        toast.error('操作失败: ' + (err as Error).message)
      },
    })
  }

  const handleForceRefresh = () => {
    forceRefresh.mutate(credential.id, {
      onSuccess: (res) => {
        toast.success(res.message)
      },
      onError: (err) => {
        toast.error('刷新失败: ' + (err as Error).message)
      },
    })
  }

  const handleDelete = () => {
    if (!credential.disabled) {
      toast.error('请先禁用凭据再删除')
      setShowDeleteDialog(false)
      return
    }

    deleteCredential.mutate(credential.id, {
      onSuccess: (res) => {
        toast.success(res.message)
        setShowDeleteDialog(false)
      },
      onError: (err) => {
        toast.error('删除失败: ' + (err as Error).message)
      },
    })
  }

  const handleSaveProxy = () => {
    const trimmedUrl = proxyUrl.trim()
    if (!trimmedUrl) {
      toast.error('请输入完整代理 URL；如需解除绑定请使用“清除 IP 绑定”')
      return
    }
    setCredentialProxy.mutate(
      {
        id: credential.id,
        req: {
          proxyUrl: trimmedUrl,
          proxyUsername: proxyUsername.trim() || undefined,
          proxyPassword: proxyPassword || undefined,
        },
      },
      {
        onSuccess: (res) => {
          toast.success(res.message)
          setShowProxyDialog(false)
          setProxyUsername('')
          setProxyPassword('')
        },
        onError: (err) => toast.error('代理绑定失败: ' + (err as Error).message),
      }
    )
  }

  const handleClearProxy = () => {
    setCredentialProxy.mutate(
      { id: credential.id, req: {} },
      {
        onSuccess: (res) => {
          toast.success(res.message)
          setShowProxyDialog(false)
        },
        onError: (err) => toast.error('清除代理失败: ' + (err as Error).message),
      }
    )
  }

  const handleTestProxy = () => {
    testCredentialProxy.mutate(credential.id, {
      onSuccess: (result) => {
        setEgressIp(result.egressIp)
        toast.success(`出口 IP：${result.egressIp}`)
      },
      onError: (err) => toast.error('代理测试失败: ' + (err as Error).message),
    })
  }

  return (
    <>
      <Card className={credential.isCurrent ? 'ring-2 ring-primary' : ''}>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Checkbox
                checked={selected}
                onCheckedChange={onToggleSelect}
              />
              <CardTitle className="text-lg flex items-center gap-2">
                {credential.email || `凭据 #${credential.id}`}
                {credential.isCurrent && (
                  <Badge variant="success">当前</Badge>
                )}
                {credential.disabled && (
                  <Badge variant="destructive">已禁用</Badge>
                )}
                {credential.disabled && (
                  <Badge variant={disabledReasonVariant(credential.disabledReason) as 'destructive' | 'secondary' | 'warning'}>
                    {disabledReasonLabel(credential.disabledReason)}
                  </Badge>
                )}
                {credential.authMethod && (
                  <Badge variant="secondary">
                    {credential.authMethod === 'api_key' ? 'API Key' :
                     credential.authMethod === 'idc' ? 'IdC' :
                     credential.authMethod === 'social' ? 'Social' :
                     credential.authMethod}
                  </Badge>
                )}
                {credential.endpoint && (
                  <Badge variant="outline">{credential.endpoint}</Badge>
                )}
                {credential.overageStatus === 'ENABLED' && (
                  <Badge variant="success">可超额</Badge>
                )}
                {credential.overageStatus === 'DISABLED' && (
                  <Badge variant="secondary">不可超额</Badge>
                )}
                {credential.overageStatus === 'ENABLED' &&
                  balance != null &&
                  balance.currentUsage > balance.usageLimit && (
                    <Badge variant="outline" className="border-amber-500 text-amber-600">
                      超额中
                    </Badge>
                  )}
              </CardTitle>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">启用</span>
              <Switch
                checked={!credential.disabled}
                onCheckedChange={handleToggleDisabled}
                disabled={setDisabled.isPending}
              />
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* 信息网格 */}
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-muted-foreground">优先级：</span>
              {editingPriority ? (
                <div className="inline-flex items-center gap-1 ml-1">
                  <Input
                    type="number"
                    value={priorityValue}
                    onChange={(e) => setPriorityValue(e.target.value)}
                    className="w-16 h-7 text-sm"
                    min="0"
                  />
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-7 w-7 p-0"
                    onClick={handlePriorityChange}
                    disabled={setPriority.isPending}
                  >
                    ✓
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-7 w-7 p-0"
                    onClick={() => {
                      setEditingPriority(false)
                      setPriorityValue(String(credential.priority))
                    }}
                  >
                    ✕
                  </Button>
                </div>
              ) : (
                <span
                  className="font-medium cursor-pointer hover:underline ml-1"
                  onClick={() => setEditingPriority(true)}
                >
                  {credential.priority}
                  <span className="text-xs text-muted-foreground ml-1">(点击编辑)</span>
                </span>
              )}
            </div>
            <div>
              <span className="text-muted-foreground">失败次数：</span>
              <span className={credential.failureCount > 0 ? 'text-red-500 font-medium' : ''}>
                {credential.failureCount}
              </span>
            </div>
            <div>
              <span className="text-muted-foreground">刷新失败：</span>
              <span className={credential.refreshFailureCount > 0 ? 'text-red-500 font-medium' : ''}>
                {credential.refreshFailureCount}
              </span>
            </div>
            <div>
              <span className="text-muted-foreground">订阅等级：</span>
              <span className="font-medium">
                {loadingBalance ? (
                  <Loader2 className="inline w-3 h-3 animate-spin" />
                ) : balance?.subscriptionTitle || '未知'}
              </span>
            </div>
            <div>
              <span className="text-muted-foreground">成功次数：</span>
              <span className="font-medium">{credential.successCount}</span>
            </div>
            <div className="col-span-2">
              <span className="text-muted-foreground">最后调用：</span>
              <span className="font-medium">{formatLastUsed(credential.lastUsedAt)}</span>
            </div>
            {credential.maskedApiKey && (
              <div className="col-span-2">
                <span className="text-muted-foreground">API Key：</span>
                <span className="font-mono font-medium">{credential.maskedApiKey}</span>
              </div>
            )}
            {credential.importNote && (
              <div className="col-span-2">
                <span className="text-muted-foreground">备注：</span>
                <span className="font-medium break-words">{credential.importNote}</span>
              </div>
            )}
            <div className="col-span-2">
              <span className="text-muted-foreground">基础用量：</span>
              {loadingBalance ? (
                <span className="text-sm ml-1">
                  <Loader2 className="inline w-3 h-3 animate-spin" /> 加载中...
                </span>
              ) : balance ? (
                <span className="font-medium ml-1">
                  {Math.min(balance.currentUsage, balance.usageLimit).toFixed(0)} / {balance.usageLimit.toFixed(0)} 次
                  <span className="text-xs text-muted-foreground ml-1">
                    (剩余 {Math.max(0, balance.usageLimit - balance.currentUsage).toFixed(0)} 次)
                  </span>
                </span>
              ) : (
                <span className="text-sm text-muted-foreground ml-1">未知</span>
              )}
            </div>
            {balance && balance.currentUsage > balance.usageLimit && (
              <div className="col-span-2">
                <span className="text-muted-foreground">超额用量：</span>
                <span className="font-medium text-amber-600 ml-1">
                  超额 {(balance.currentUsage - balance.usageLimit).toFixed(0)} 次
                  {balance.overageCap > 0 && (
                    <span className="text-xs text-muted-foreground ml-1">
                      (上限 {balance.overageCap.toFixed(0)} 次)
                    </span>
                  )}
                </span>
              </div>
            )}
            {credential.hasProxy && (
              <div className="col-span-2">
                <span className="text-muted-foreground">代理：</span>
                <span className="font-medium">{credential.proxyUrl}</span>
                {egressIp && <span className="text-xs text-muted-foreground ml-2">出口 {egressIp}</span>}
              </div>
            )}
            {credential.hasProfileArn && (
              <div className="col-span-2">
                <Badge variant="secondary">有 Profile ARN</Badge>
              </div>
            )}
          </div>

          {/* RPM 限流 */}
          <div className="pt-3 border-t space-y-2">
            <div className="flex items-center justify-between flex-wrap gap-2 text-sm">
              <div className="flex items-center">
                <span className="text-muted-foreground">RPM 限制：</span>
                {editingRpm ? (
                  <span className="inline-flex items-center gap-1 ml-1">
                    <Input
                      type="number"
                      value={rpmValue}
                      onChange={(e) => setRpmValue(e.target.value)}
                      className="w-20 h-7 text-sm"
                      min="0"
                      placeholder="默认"
                    />
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-7 w-7 p-0"
                      onClick={handleRpmChange}
                      disabled={setRpm.isPending}
                    >
                      ✓
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-7 w-7 p-0"
                      onClick={() => {
                        setEditingRpm(false)
                        setRpmValue(credential.rpm == null ? '' : String(credential.rpm))
                      }}
                    >
                      ✕
                    </Button>
                  </span>
                ) : (
                  <span
                    className="font-medium cursor-pointer hover:underline ml-1 inline-flex items-center"
                    onClick={() => setEditingRpm(true)}
                  >
                    {effectiveRpm == null ? '不限' : effectiveRpm}
                    {credential.rpmFollowsDefault ? (
                      <span className="text-xs text-muted-foreground ml-1">跟随默认 (点击编辑)</span>
                    ) : (
                      <Badge variant="secondary" className="ml-1">自定义</Badge>
                    )}
                  </span>
                )}
              </div>
              <div className="flex items-center gap-4 text-xs text-muted-foreground">
                <span>
                  近1h尝试峰值 <span className="text-foreground font-medium">{credential.peakRpm1h}</span>
                </span>
                <span className={credential.throttled1h > 0 ? 'text-amber-600' : ''}>
                  近1h被限 <span className="font-medium">{credential.throttled1h}</span>
                </span>
              </div>
            </div>
            {effectiveRpm != null && (
              <div className="flex items-center gap-2">
                <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full ${isAtLimit ? 'bg-amber-500' : 'bg-emerald-500'}`}
                    style={{ width: `${Math.min(100, (credential.currentRpm / effectiveRpm) * 100)}%` }}
                  />
                </div>
                <span className={`text-xs whitespace-nowrap ${isAtLimit ? 'text-amber-600 font-medium' : 'text-muted-foreground'}`}>
                  {credential.currentRpm} / {effectiveRpm}
                  {isAtLimit ? ' · 本分钟尝试已满' : ''}
                </span>
              </div>
            )}
          </div>

          {/* 操作按钮 */}
          <div className="flex flex-wrap gap-2 pt-2 border-t">
            <Button
              size="sm"
              variant="outline"
              onClick={handleReset}
              disabled={resetFailure.isPending || (credential.failureCount === 0 && credential.refreshFailureCount === 0)}
            >
              <RefreshCw className="h-4 w-4 mr-1" />
              重置失败
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={handleForceRefresh}
              disabled={forceRefresh.isPending || credential.disabled || credential.authMethod === 'api_key'}
              title={credential.authMethod === 'api_key' ? 'API Key 凭据无需刷新 Token' : credential.disabled ? '已禁用的凭据无法刷新 Token' : '强制刷新 Token'}
            >
              <RefreshCw className={`h-4 w-4 mr-1 ${forceRefresh.isPending ? 'animate-spin' : ''}`} />
              刷新 Token
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                const newPriority = Math.max(0, credential.priority - 1)
                setPriority.mutate(
                  { id: credential.id, priority: newPriority },
                  {
                    onSuccess: (res) => toast.success(res.message),
                    onError: (err) => toast.error('操作失败: ' + (err as Error).message),
                  }
                )
              }}
              disabled={setPriority.isPending || credential.priority === 0}
            >
              <ChevronUp className="h-4 w-4 mr-1" />
              提高优先级
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                const newPriority = credential.priority + 1
                setPriority.mutate(
                  { id: credential.id, priority: newPriority },
                  {
                    onSuccess: (res) => toast.success(res.message),
                    onError: (err) => toast.error('操作失败: ' + (err as Error).message),
                  }
                )
              }}
              disabled={setPriority.isPending}
            >
              <ChevronDown className="h-4 w-4 mr-1" />
              降低优先级
            </Button>
            <Button
              size="sm"
              variant="default"
              onClick={() => onViewBalance(credential.id)}
            >
              <Wallet className="h-4 w-4 mr-1" />
              查看余额
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => onViewLogs(credential.id)}
            >
              <ScrollText className="h-4 w-4 mr-1" />
              日志
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                setProxyUrl('')
                setProxyUsername('')
                setProxyPassword('')
                setEgressIp(null)
                setShowProxyDialog(true)
              }}
            >
              <Network className="h-4 w-4 mr-1" />
              {credential.hasProxy ? '更换 IP' : '绑定 IP'}
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={handleTestProxy}
              disabled={testCredentialProxy.isPending}
            >
              <Network className={`h-4 w-4 mr-1 ${testCredentialProxy.isPending ? 'animate-pulse' : ''}`} />
              测试出口
            </Button>
            <Button
              size="sm"
              variant="destructive"
              onClick={() => setShowDeleteDialog(true)}
              disabled={!credential.disabled}
              title={!credential.disabled ? '需要先禁用凭据才能删除' : undefined}
            >
              <Trash2 className="h-4 w-4 mr-1" />
              删除
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* 删除确认对话框 */}
      <Dialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>确认删除凭据</DialogTitle>
            <DialogDescription>
              您确定要删除凭据 #{credential.id} 吗？此操作无法撤销。
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setShowDeleteDialog(false)}
              disabled={deleteCredential.isPending}
            >
              取消
            </Button>
            <Button
              variant="destructive"
              onClick={handleDelete}
              disabled={deleteCredential.isPending || !credential.disabled}
            >
              确认删除
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={showProxyDialog} onOpenChange={setShowProxyDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>绑定账号代理</DialogTitle>
            <DialogDescription>
              当前：{credential.proxyUrl || '未绑定'}。同一个住宅 IP 的账号数由全局 PRO+ 代理门禁配置限制；更换时请输入完整新代理，输入 direct 则强制直连。
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <Input
              placeholder="http://host:port 或 socks5://host:port"
              value={proxyUrl}
              onChange={(event) => setProxyUrl(event.target.value)}
              disabled={setCredentialProxy.isPending}
            />
            <div className="grid grid-cols-2 gap-2">
              <Input
                placeholder="代理用户名"
                value={proxyUsername}
                onChange={(event) => setProxyUsername(event.target.value)}
                disabled={setCredentialProxy.isPending}
              />
              <Input
                type="password"
                placeholder="代理密码"
                value={proxyPassword}
                onChange={(event) => setProxyPassword(event.target.value)}
                disabled={setCredentialProxy.isPending}
              />
            </div>
          </div>
          <DialogFooter>
            {credential.hasProxy && (
              <Button variant="destructive" onClick={handleClearProxy} disabled={setCredentialProxy.isPending}>
                清除 IP 绑定
              </Button>
            )}
            <Button variant="outline" onClick={() => setShowProxyDialog(false)} disabled={setCredentialProxy.isPending}>
              取消
            </Button>
            <Button onClick={handleSaveProxy} disabled={setCredentialProxy.isPending}>
              保存绑定
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
