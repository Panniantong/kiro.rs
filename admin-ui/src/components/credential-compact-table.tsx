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
  loadingBalanceIds: Set<number>
  selectedIds: Set<number>
  onToggleSelect: (id: number) => void
}

const disabledReasonLabels: Record<string, string> = {
  QuotaExceeded: '额度用尽',
  UpstreamSuspended: '上游封停',
  InvalidRefreshToken: 'Token 失效',
  TooManyFailures: '连续失败',
  TooManyRefreshFailures: '刷新失败',
  InvalidConfig: '配置无效',
  Manual: '手动禁用',
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
              const loadingBalance = loadingBalanceIds.has(credential.id)
              const remaining = balance ? Math.max(0, balance.remaining) : null
              const limit = balance?.usageLimit ?? null

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
                        <div className="text-xs">{disabledReasonLabels[credential.disabledReason || ''] || credential.disabledReason || '原因未知'}</div>
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
                      <span className="inline-flex items-center gap-1 text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" />加载中</span>
                    ) : balance ? (
                      <>
                        <div className="font-semibold text-foreground">{remaining?.toFixed(0)} / {limit?.toFixed(0)}</div>
                        <div className="text-xs text-muted-foreground">已用 {balance.usagePercentage.toFixed(1)}%</div>
                      </>
                    ) : (
                      <span className="text-muted-foreground">未知</span>
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
