import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Checkbox } from '@/components/ui/checkbox'
import { Switch } from '@/components/ui/switch'
import { useSetDisabled } from '@/hooks/use-credentials'
import type { BalanceResponse, CredentialStatusItem } from '@/types/api'

interface CredentialCompactTableProps {
  credentials: CredentialStatusItem[]
  balances: Map<number, BalanceResponse>
  balanceErrors: Map<number, string>
  loadingBalanceIds: Set<number>
  selectedIds: Set<number>
  onToggleSelect: (id: number) => void
}

const disabledReasonMeta: Record<string, { label: string; description: string }> = {
  QuotaExceeded: { label: '额度用尽', description: '等待上游额度恢复；不会自动恢复' },
  UpstreamSuspended: { label: '上游封停', description: '账号已被上游封停；不会自动恢复' },
  InvalidRefreshToken: { label: 'Token 失效', description: '需要重新导入或更换 Token' },
  TooManyFailures: { label: '连续失败', description: '需通过代理出口与账号探测后恢复' },
  TooManyRefreshFailures: { label: '刷新失败', description: '需 Token 刷新与账号探测通过后恢复' },
  InvalidConfig: { label: '配置无效', description: '修正配置并通过账号探测后恢复' },
  Manual: { label: '手动禁用', description: '仅在人工确认后恢复' },
}

function formatLastUsed(value: string | null) {
  if (!value) return '未调用'
  const time = new Date(value)
  if (Number.isNaN(time.getTime())) return value
  return time.toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

function authLabel(value: string | null) {
  if (value === 'api_key') return 'API Key'
  if (value === 'idc') return 'IdC'
  if (value === 'social') return 'Social'
  return value || '未知'
}

export function CredentialCompactTable({
  credentials,
  balances,
  balanceErrors,
  loadingBalanceIds,
  selectedIds,
  onToggleSelect,
}: CredentialCompactTableProps) {
  const setDisabled = useSetDisabled()

  const toggleDisabled = (credential: CredentialStatusItem) => {
    setDisabled.mutate(
      { id: credential.id, disabled: !credential.disabled },
      {
        onSuccess: (result) => toast.success(result.message),
        onError: (error) => toast.error(`状态更新失败：${(error as Error).message}`),
      }
    )
  }

  return (
    <div className="overflow-hidden rounded-xl border bg-card shadow-sm">
      <div className="max-h-[72vh] overflow-auto">
        <table className="w-full min-w-[1180px] border-collapse text-sm">
          <thead className="sticky top-0 z-10 bg-muted/95 backdrop-blur">
            <tr className="border-b text-left text-xs font-medium uppercase tracking-wide text-muted-foreground">
              <th className="w-10 px-3 py-3">选</th>
              <th className="min-w-[220px] px-3 py-3">凭据</th>
              <th className="min-w-[150px] px-3 py-3">状态</th>
              <th className="min-w-[150px] px-3 py-3">RPM</th>
              <th className="min-w-[170px] px-3 py-3">额度</th>
              <th className="min-w-[220px] px-3 py-3">分组 / 备注</th>
              <th className="min-w-[120px] px-3 py-3">优先级</th>
              <th className="min-w-[130px] px-3 py-3">最后调用</th>
              <th className="w-24 px-3 py-3 text-right">启用</th>
            </tr>
          </thead>
          <tbody>
            {credentials.map((credential) => {
              const balance = balances.get(credential.id)
              const balanceError = balanceErrors.get(credential.id)
              const loadingBalance = loadingBalanceIds.has(credential.id)
              const remaining = balance ? Math.max(0, balance.remaining) : null
              const limit = balance?.usageLimit ?? null
              const reasonMeta = disabledReasonMeta[credential.disabledReason || '']

              return (
                <tr
                  key={credential.id}
                  className={`border-b last:border-b-0 hover:bg-muted/35 ${credential.disabled ? 'bg-muted/15 text-muted-foreground' : ''}`}
                >
                  <td className="px-3 py-3 align-top">
                    <Checkbox checked={selectedIds.has(credential.id)} onCheckedChange={() => onToggleSelect(credential.id)} />
                  </td>
                  <td className="px-3 py-3 align-top">
                    <div className="font-semibold text-foreground">{credential.email || `凭据 #${credential.id}`}</div>
                    <div className="mt-1 flex flex-wrap gap-1">
                      <Badge variant="secondary">#{credential.id}</Badge>
                      <Badge variant="outline">{authLabel(credential.authMethod)}</Badge>
                      <Badge variant="outline">{balance?.subscriptionTitle || credential.subscriptionTitle || '订阅未知'}</Badge>
                      {credential.isCurrent && <Badge variant="success">当前</Badge>}
                    </div>
                  </td>
                  <td className="px-3 py-3 align-top">
                    {credential.disabled ? (
                      <div className="space-y-1">
                        <Badge variant="destructive">已禁用</Badge>
                        <div className="text-xs">{reasonMeta?.label || credential.disabledReason || '原因未知'}</div>
                        <div className="text-[11px] leading-4 text-muted-foreground">
                          {reasonMeta?.description || '等待人工确认恢复条件'}
                        </div>
                        {credential.disabledAt && (
                          <div className="text-[11px] text-muted-foreground">
                            起始 {formatLastUsed(credential.disabledAt)}
                          </div>
                        )}
                        {credential.recoveryChecks && credential.recoveryChecks.length > 0 && (
                          <div className="text-[11px] text-muted-foreground">
                            检查：{credential.recoveryChecks.join('、')}
                          </div>
                        )}
                        <div className="text-[11px] text-muted-foreground">
                          恢复：{credential.recoveryClass || 'manual'}
                        </div>
                      </div>
                    ) : (
                      <Badge variant="success">可用</Badge>
                    )}
                  </td>
                  <td className="px-3 py-3 align-top font-mono tabular-nums">
                    <div><span className="text-muted-foreground">实时</span> {credential.currentRpm}</div>
                    <div><span className="text-muted-foreground">上限</span> {credential.effectiveRpm ?? '不限'}</div>
                    <div className="text-xs text-muted-foreground">1h 峰值 {credential.peakRpm1h} · 被限 {credential.throttled1h}</div>
                  </td>
                  <td className="px-3 py-3 align-top font-mono tabular-nums">
                    {loadingBalance ? (
                      <span className="inline-flex items-center gap-1 text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" />查询中</span>
                    ) : balance ? (
                      <>
                        <div className="font-semibold text-foreground">{remaining?.toFixed(0)} / {limit?.toFixed(0)}</div>
                        <div className="text-xs text-muted-foreground">已用 {balance.usagePercentage.toFixed(1)}%</div>
                        {credential.balanceState === 'stale' && (
                          <div className="text-[11px] text-amber-600">缓存已过期</div>
                        )}
                      </>
                    ) : balanceError ? (
                      <span className="text-destructive">查询失败 · {balanceError}</span>
                    ) : credential.balanceState === 'stale' ? (
                      <span className="text-amber-600">缓存已过期</span>
                    ) : (
                      <span className="text-muted-foreground">未查询</span>
                    )}
                  </td>
                  <td className="max-w-[260px] px-3 py-3 align-top">
                    <div className="truncate font-medium text-foreground" title={credential.importNote || ''}>
                      {credential.importNote || '未分组'}
                    </div>
                    <div className="mt-1 truncate text-xs text-muted-foreground" title={credential.maskedApiKey || credential.endpoint}>
                      {credential.maskedApiKey || credential.endpoint || '—'}
                    </div>
                  </td>
                  <td className="px-3 py-3 align-top font-mono tabular-nums">
                    <div>{credential.priority}</div>
                    <div className="text-xs text-muted-foreground">成功 {credential.successCount}</div>
                  </td>
                  <td className="px-3 py-3 align-top text-xs">{formatLastUsed(credential.lastUsedAt)}</td>
                  <td className="px-3 py-3 text-right align-top">
                    <Switch
                      checked={!credential.disabled}
                      onCheckedChange={() => toggleDisabled(credential)}
                      disabled={setDisabled.isPending}
                    />
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      <div className="border-t bg-muted/25 px-4 py-2 text-xs text-muted-foreground">
        当前视图共 {credentials.length} 个凭据
      </div>
    </div>
  )
}
