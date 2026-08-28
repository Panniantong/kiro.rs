import { AlertTriangle, CheckCircle2, CircleHelp, Network } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import type { ProxyPoolResponse } from '@/types/api'

interface ProxyPoolStatusCardProps {
  data?: ProxyPoolResponse
  isLoading: boolean
}

export function ProxyPoolStatusCard({ data, isLoading }: ProxyPoolStatusCardProps) {
  const utilization = data && data.totalCapacity > 0
    ? Math.min(100, (data.assignedSlots / data.totalCapacity) * 100)
    : 0

  return (
    <Card className="mb-6 overflow-hidden">
      <CardHeader className="border-b bg-muted/20 pb-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Network className="h-4 w-4 text-sky-600" />
            代理池状态
          </CardTitle>
          <div className="flex flex-wrap gap-2">
            <Badge variant={data?.pendingCredentialCount ? 'warning' : 'success'}>
              等待 {data?.pendingCredentialCount ?? 0}
            </Badge>
            <Badge variant="outline">历史未绑定 {data?.unboundEnabledCount ?? 0}</Badge>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-5 py-5">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-6">
          <Metric label="代理总数" value={isLoading ? '—' : data?.total ?? 0} />
          <Metric label="总容量" value={isLoading ? '—' : data?.totalCapacity ?? 0} />
          <Metric label="已占用" value={isLoading ? '—' : data?.assignedSlots ?? 0} tone="blue" />
          <Metric label="空闲槽位" value={isLoading ? '—' : data?.availableSlots ?? 0} tone="green" />
          <Metric label="正常账号" value={isLoading ? '—' : data?.healthyAssignedCount ?? 0} tone="green" />
          <Metric
            label="异常 / 未知"
            value={isLoading ? '—' : `${data?.abnormalAssignedCount ?? 0} / ${data?.unknownAssignedCount ?? 0}`}
            tone={(data?.abnormalAssignedCount ?? 0) > 0 ? 'red' : 'default'}
          />
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>容量利用率 {utilization.toFixed(1)}%</span>
            <span>
              空代理 {data?.emptyProxyCount ?? 0} · 部分占用 {data?.partialProxyCount ?? 0} · 满载 {data?.fullProxyCount ?? 0}
            </span>
          </div>
          <div className="h-2 overflow-hidden rounded-full bg-muted">
            <div className="h-full rounded-full bg-sky-500 transition-all" style={{ width: `${utilization}%` }} />
          </div>
          {data?.emptyReason && (
            <p className="flex items-start gap-2 rounded-lg bg-muted/35 px-3 py-2 text-xs text-muted-foreground">
              <CircleHelp className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              {data.emptyReason}
            </p>
          )}
        </div>

        {data && data.proxies.length > 0 && (
          <details className="group rounded-lg border">
            <summary className="cursor-pointer select-none px-4 py-3 text-sm font-medium">
              查看 {data.proxies.length} 个代理的占用明细
            </summary>
            <div className="grid gap-3 border-t bg-muted/10 p-3 lg:grid-cols-2 xl:grid-cols-3">
              {data.proxies.map(proxy => (
                <div key={proxy.proxyUrl} className="rounded-lg border bg-background p-3 text-xs">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0 truncate font-mono font-medium" title={proxy.proxyUrl}>
                      {proxy.proxyUrl}
                    </div>
                    <Badge variant={proxy.assignedCount === 0 ? 'secondary' : proxy.abnormalCount > 0 ? 'destructive' : 'success'}>
                      {proxy.assignedCount}/{proxy.assignedCount + proxy.remainingSlots}
                    </Badge>
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1">
                    <Badge variant="success">正常 {proxy.healthyCount}</Badge>
                    <Badge variant={proxy.abnormalCount > 0 ? 'destructive' : 'outline'}>异常 {proxy.abnormalCount}</Badge>
                    <Badge variant="outline">未知 {proxy.unknownCount}</Badge>
                    {proxy.assignedCount === 0 && <Badge variant="secondary">空置</Badge>}
                  </div>
                  <div className="mt-3 space-y-1.5">
                    {proxy.assignedCredentials.length === 0 ? (
                      <div className="text-muted-foreground">暂无绑定账号</div>
                    ) : proxy.assignedCredentials.map(credential => (
                      <div key={credential.credentialId} className="flex items-center justify-between gap-2 rounded bg-muted/35 px-2 py-1.5">
                        <div className="min-w-0">
                          <div className="truncate font-medium" title={credential.email || ''}>
                            #{credential.credentialId} {credential.email || credential.subscriptionTitle || '未知账号'}
                          </div>
                          <div className="text-muted-foreground">
                            {credential.remaining == null || credential.usageLimit == null
                              ? '余额未知'
                              : `剩余 ${credential.remaining.toFixed(0)} / ${credential.usageLimit.toFixed(0)}`}
                          </div>
                        </div>
                        {credential.health === 'healthy' ? (
                          <CheckCircle2 className="h-4 w-4 shrink-0 text-green-600" />
                        ) : credential.health === 'abnormal' ? (
                          <AlertTriangle className="h-4 w-4 shrink-0 text-red-500" />
                        ) : (
                          <CircleHelp className="h-4 w-4 shrink-0 text-muted-foreground" />
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </details>
        )}
      </CardContent>
    </Card>
  )
}

function Metric({ label, value, tone = 'default' }: { label: string; value: string | number; tone?: 'default' | 'blue' | 'green' | 'red' }) {
  const toneClass = tone === 'blue'
    ? 'text-sky-700 dark:text-sky-300'
    : tone === 'green'
      ? 'text-green-700 dark:text-green-300'
      : tone === 'red'
        ? 'text-red-600 dark:text-red-400'
        : 'text-foreground'
  return (
    <div className="rounded-lg border bg-muted/15 px-3 py-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className={`mt-1 font-mono text-xl font-bold tabular-nums ${toneClass}`}>{value}</div>
    </div>
  )
}
