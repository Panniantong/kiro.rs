import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Activity, FileText, RefreshCw } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { getRecentModelStatus } from '@/api/credentials'
import type { RecentModelError } from '@/types/api'

// 只读展示：近 10 分钟每个账号按模型的请求情况，不参与任何调度。

type AccountFilter = 'enabled' | 'active' | 'failing' | 'all'

const filterLabels: Record<AccountFilter, string> = {
  enabled: '启用中的号',
  active: '有请求的号',
  failing: '有报错的号',
  all: '全部',
}

const errorClassLabels: Record<string, string> = {
  upstream_400: '上游 400',
  upstream_408: '上游超时 408',
  upstream_429: '限流 429',
  upstream_5xx: '上游 5xx',
  upstream_4xx: '上游 4xx',
  upstream_401_403: '鉴权失败 401/403',
  quota_exhausted: '额度用完',
  send_error: '网络错误',
  empty_stream: '空回复',
  stream_incomplete: '流未完成/客户端断开',
}

function errorLabel(error: RecentModelError): string {
  const label = error.errorClass ? errorClassLabels[error.errorClass] || error.errorClass : '未知错误'
  return error.upstreamStatus && !label.includes(String(error.upstreamStatus)) ? `${label}（${error.upstreamStatus}）` : label
}

interface RecentModelStatusCardProps {
  onViewLogs: (id: number) => void
}

export function RecentModelStatusCard({ onViewLogs }: RecentModelStatusCardProps) {
  const [filter, setFilter] = useState<AccountFilter>('enabled')
  const { data, isLoading, isFetching, refetch, error } = useQuery({
    queryKey: ['recentModelStatus', 10],
    queryFn: () => getRecentModelStatus(10),
    refetchInterval: 30000,
  })

  const accounts = data?.accounts || []
  const activeCount = accounts.filter(account => account.models.length > 0).length
  const failingCount = accounts.filter(account => account.models.some(model => model.failure > 0)).length
  const visible = accounts.filter(account => {
    if (filter === 'enabled') return !account.disabled || account.models.length > 0
    if (filter === 'active') return account.models.length > 0
    if (filter === 'failing') return account.models.some(model => model.failure > 0)
    return true
  })

  return (
    <Card className="mb-6 overflow-hidden">
      <CardHeader className="border-b bg-muted/20 pb-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Activity className="h-4 w-4 text-sky-600" />
            近 10 分钟模型状态
          </CardTitle>
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="outline">有请求 {activeCount}</Badge>
            <Badge variant={failingCount > 0 ? 'destructive' : 'success'}>有报错 {failingCount}</Badge>
            <Badge variant="secondary">无请求 {accounts.length - activeCount}</Badge>
            <Button size="sm" variant="outline" className="gap-1.5" onClick={() => refetch()} disabled={isFetching}>
              <RefreshCw className={`h-3.5 w-3.5 ${isFetching ? 'animate-spin' : ''}`} />
              刷新
            </Button>
          </div>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2" role="group" aria-label="筛选账号">
          {(Object.keys(filterLabels) as AccountFilter[]).map(key => (
            <Button
              key={key}
              size="sm"
              variant={filter === key ? 'default' : 'outline'}
              aria-pressed={filter === key}
              onClick={() => setFilter(key)}
            >
              {filterLabels[key]}
            </Button>
          ))}
          <span className="text-xs text-muted-foreground">
            只读展示，每 30 秒自动刷新{data ? ` · 更新于 ${new Date(data.generatedAt).toLocaleTimeString('zh-CN')}` : ''}
          </span>
        </div>
      </CardHeader>
      <CardContent className="space-y-2 py-4">
        {isLoading && <div className="text-sm text-muted-foreground">加载中…</div>}
        {error && <div className="text-sm text-destructive">加载失败：{(error as Error).message}</div>}
        {!isLoading && !error && visible.length === 0 && (
          <div className="text-sm text-muted-foreground">没有符合条件的账号</div>
        )}
        <div className="max-h-[560px] space-y-2 overflow-y-auto pr-1">
          {visible.map(account => {
            const totals = account.models.reduce(
              (sum, model) => ({
                success: sum.success + model.success,
                failure: sum.failure + model.failure,
                inProgress: sum.inProgress + model.inProgress,
              }),
              { success: 0, failure: 0, inProgress: 0 }
            )
            return (
              <div key={account.id} className="rounded-lg border bg-background p-3 text-xs">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="truncate font-medium">
                      #{account.id} {account.email || account.importNote || '未知账号'}
                      {account.disabled && <span className="ml-2 text-muted-foreground">（已禁用）</span>}
                    </div>
                    {account.email && account.importNote && (
                      <div className="truncate text-[11px] text-muted-foreground" title={account.importNote}>{account.importNote}</div>
                    )}
                  </div>
                  <div className="flex shrink-0 items-center gap-1.5">
                    {account.models.length === 0 ? (
                      <Badge variant="secondary">无请求</Badge>
                    ) : (
                      <>
                        <Badge variant="success">成功 {totals.success}</Badge>
                        <Badge variant={totals.failure > 0 ? 'destructive' : 'outline'}>失败 {totals.failure}</Badge>
                        {totals.inProgress > 0 && <Badge variant="outline">进行中 {totals.inProgress}</Badge>}
                      </>
                    )}
                    <Button size="sm" variant="ghost" className="h-7 gap-1 px-2" onClick={() => onViewLogs(account.id)}>
                      <FileText className="h-3.5 w-3.5" />日志
                    </Button>
                  </div>
                </div>
                {account.models.length > 0 && (
                  <div className="mt-2 space-y-1.5">
                    {account.models.map(model => (
                      <div key={model.model} className="rounded bg-muted/35 px-2 py-1.5">
                        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                          <span className="font-mono font-medium">{model.model}</span>
                          <span className="text-green-700 dark:text-green-300">成功 {model.success}</span>
                          <span className={model.failure > 0 ? 'text-red-600 dark:text-red-400' : 'text-muted-foreground'}>失败 {model.failure}</span>
                          {model.inProgress > 0 && <span className="text-muted-foreground">进行中 {model.inProgress}</span>}
                          <span className="text-muted-foreground">
                            最近请求 {new Date(model.lastRequestAt).toLocaleTimeString('zh-CN')}
                            {model.failure > 0 && ` · 最近成功 ${model.lastSuccessAt ? new Date(model.lastSuccessAt).toLocaleTimeString('zh-CN') : '无'}`}
                          </span>
                        </div>
                        {model.errors.map(err => (
                          <div key={`${err.errorClass}-${err.upstreamStatus}`} className="mt-1 text-red-600 dark:text-red-400">
                            <span className="font-medium">{errorLabel(err)} × {err.count}</span>
                            <span className="ml-1 break-all text-[11px] text-muted-foreground" title={err.lastMessage}>
                              {new Date(err.lastAt).toLocaleTimeString('zh-CN')} · {err.lastMessage}
                            </span>
                          </div>
                        ))}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </CardContent>
    </Card>
  )
}
