import { useEffect, useMemo, useState } from 'react'
import { Search, ScrollText } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import {
  useCredentialLogs,
  useLogAccounts,
} from '@/hooks/use-credentials'
import type {
  AccountLogEventType,
  AccountLogItem,
  AccountLogOutcome,
  AccountLogSeverity,
  CredentialLogQuery,
  CredentialStatusItem,
} from '@/types/api'

interface AccountLogsDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  credentials: CredentialStatusItem[]
  initialCredentialId: number | null
}

const eventTypeLabels: Record<AccountLogEventType, string> = {
  request: '请求',
  token_refresh: 'Token 刷新',
  balance: '余额',
  credential_status: '账号状态',
  proxy: '代理',
  recovery_probe: '恢复探针',
}

const outcomeLabels: Record<AccountLogOutcome, string> = {
  success: '成功',
  failure: '失败',
  retry: '重试',
  pending: '进行中',
}

const severityLabels: Record<AccountLogSeverity, string> = {
  info: '信息',
  warn: '警告',
  error: '错误',
}

function formatTime(value: string): string {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN')
}

function badgeVariant(severity: AccountLogSeverity): 'default' | 'secondary' | 'destructive' | 'outline' {
  if (severity === 'error') return 'destructive'
  if (severity === 'warn') return 'outline'
  return 'secondary'
}

function accountLabel(account: { id: number; email?: string | null; importNote?: string | null }): string {
  return account.email || account.importNote || `凭据 #${account.id}`
}

export function AccountLogsDialog({
  open,
  onOpenChange,
  credentials,
  initialCredentialId,
}: AccountLogsDialogProps) {
  const [selectedId, setSelectedId] = useState<number | null>(initialCredentialId)
  const [searchInput, setSearchInput] = useState('')
  const [submittedSearch, setSubmittedSearch] = useState('')
  const [filters, setFilters] = useState<CredentialLogQuery>({})
  const [fromInput, setFromInput] = useState('')
  const [toInput, setToInput] = useState('')
  const [expandedLogId, setExpandedLogId] = useState<number | null>(null)

  useEffect(() => {
    if (!open) return
    setSelectedId(initialCredentialId)
    setSearchInput('')
    setSubmittedSearch('')
    setFilters({})
    setFromInput('')
    setToInput('')
    setExpandedLogId(null)
  }, [open, initialCredentialId])

  const accountSearch = useLogAccounts(
    submittedSearch,
    open && initialCredentialId === null && selectedId === null
  )
  const logs = useCredentialLogs(selectedId, filters, open)

  const selectedAccount = useMemo(() => {
    if (selectedId === null) return null
    return credentials.find((credential) => credential.id === selectedId) ||
      accountSearch.data?.accounts.find((account) => account.id === selectedId) ||
      null
  }, [accountSearch.data?.accounts, credentials, selectedId])

  const items = useMemo<AccountLogItem[]>(
    () => logs.data?.pages.flatMap((page) => page.items) ?? [],
    [logs.data?.pages]
  )

  const chooseAccount = (id: number) => {
    setSelectedId(id)
    setFilters({})
    setFromInput('')
    setToInput('')
    setExpandedLogId(null)
  }

  const updateFilter = <K extends keyof CredentialLogQuery>(key: K, value: CredentialLogQuery[K]) => {
    setFilters((current) => ({ ...current, [key]: value || undefined }))
    setExpandedLogId(null)
  }

  const updateTimeFilter = (key: 'from' | 'to', value: string) => {
    if (key === 'from') setFromInput(value)
    else setToInput(value)
    updateFilter(key, value ? new Date(value).toISOString() : undefined)
  }

  const clearFilters = () => {
    setFilters({})
    setFromInput('')
    setToInput('')
    setExpandedLogId(null)
  }

  const clearSelection = () => {
    setSelectedId(null)
    setFilters({})
    setFromInput('')
    setToInput('')
    setExpandedLogId(null)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-6xl max-h-[88vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ScrollText className="h-5 w-5" />
            账号日志中心
          </DialogTitle>
        </DialogHeader>

        {initialCredentialId === null && selectedId === null && (
          <div className="space-y-3 border-b pb-4">
            <div className="flex gap-2">
              <Input
                value={searchInput}
                onChange={(event) => setSearchInput(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter') setSubmittedSearch(searchInput.trim())
                }}
                placeholder="输入账号 ID、邮箱或导入备注"
                autoFocus
              />
              <Button
                onClick={() => setSubmittedSearch(searchInput.trim())}
                disabled={!searchInput.trim() || accountSearch.isFetching}
              >
                <Search className="h-4 w-4 mr-1" />
                确定搜索
              </Button>
            </div>
            {accountSearch.isFetching && (
              <p className="text-sm text-muted-foreground">正在搜索账号…</p>
            )}
            {accountSearch.error && (
              <p className="text-sm text-destructive">搜索失败，请检查关键词后重试。</p>
            )}
            {submittedSearch && !accountSearch.isFetching && accountSearch.data?.accounts.length === 0 && (
              <p className="text-sm text-muted-foreground">没有找到匹配账号。</p>
            )}
            {accountSearch.data?.accounts.map((account) => (
              <button
                key={account.id}
                type="button"
                className="w-full rounded-md border p-3 text-left hover:bg-muted/50 transition-colors"
                onClick={() => chooseAccount(account.id)}
              >
                <div className="flex items-center justify-between gap-3">
                  <div className="min-w-0">
                    <div className="font-medium truncate">{accountLabel(account)}</div>
                    <div className="text-xs text-muted-foreground">
                      #{account.id}{account.importNote && account.email ? ` · ${account.importNote}` : ''}
                    </div>
                  </div>
                  {account.disabled && <Badge variant="destructive">已禁用</Badge>}
                </div>
              </button>
            ))}
          </div>
        )}

        {selectedId !== null && (
          <div className="min-h-0 flex flex-col gap-4">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b pb-3">
              <div>
                <div className="font-medium">
                  {selectedAccount ? accountLabel(selectedAccount) : `凭据 #${selectedId}`}
                </div>
                <div className="text-xs text-muted-foreground">账号 #{selectedId} · 仅保留最近 7 天</div>
              </div>
              {initialCredentialId === null && (
                <Button variant="outline" size="sm" onClick={clearSelection}>重新搜索</Button>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <select
                className="h-9 rounded-md border bg-background px-3 text-sm"
                value={filters.severity || ''}
                onChange={(event) => updateFilter('severity', event.target.value as AccountLogSeverity || undefined)}
                aria-label="日志级别"
              >
                <option value="">全部级别</option>
                {Object.entries(severityLabels).map(([value, label]) => (
                  <option key={value} value={value}>{label}</option>
                ))}
              </select>
              <select
                className="h-9 rounded-md border bg-background px-3 text-sm"
                value={filters.eventType || ''}
                onChange={(event) => updateFilter('eventType', event.target.value as AccountLogEventType || undefined)}
                aria-label="事件类型"
              >
                <option value="">全部事件</option>
                {Object.entries(eventTypeLabels).map(([value, label]) => (
                  <option key={value} value={value}>{label}</option>
                ))}
              </select>
              <select
                className="h-9 rounded-md border bg-background px-3 text-sm"
                value={filters.outcome || ''}
                onChange={(event) => updateFilter('outcome', event.target.value as AccountLogOutcome || undefined)}
                aria-label="结果"
              >
                <option value="">全部结果</option>
                {Object.entries(outcomeLabels).map(([value, label]) => (
                  <option key={value} value={value}>{label}</option>
                ))}
              </select>
              <Button
                variant={filters.severity === 'error' ? 'default' : 'outline'}
                size="sm"
                onClick={() => updateFilter('severity', filters.severity === 'error' ? undefined : 'error')}
              >
                只看错误
              </Button>
              <label className="flex items-center gap-1 text-xs text-muted-foreground">
                起始
                <Input
                  type="datetime-local"
                  value={fromInput}
                  onChange={(event) => updateTimeFilter('from', event.target.value)}
                  className="h-9 w-[180px] text-xs"
                />
              </label>
              <label className="flex items-center gap-1 text-xs text-muted-foreground">
                结束
                <Input
                  type="datetime-local"
                  value={toInput}
                  onChange={(event) => updateTimeFilter('to', event.target.value)}
                  className="h-9 w-[180px] text-xs"
                />
              </label>
              <Button variant="ghost" size="sm" onClick={clearFilters}>
                清除筛选
              </Button>
              <span className="text-xs text-muted-foreground ml-auto">点击日志行查看安全详情</span>
            </div>

            <div className="min-h-0 overflow-auto rounded-md border">
              {logs.isLoading && (
                <div className="py-12 text-center text-sm text-muted-foreground">正在加载日志…</div>
              )}
              {logs.error && (
                <div className="py-12 text-center text-sm text-destructive">日志加载失败，请稍后重试。</div>
              )}
              {!logs.isLoading && !logs.error && items.length === 0 && (
                <div className="py-12 text-center text-sm text-muted-foreground">当前筛选条件下暂无日志。</div>
              )}
              {items.length > 0 && (
                <table className="w-full text-sm">
                  <thead className="sticky top-0 bg-muted/95 text-left">
                    <tr>
                      <th className="px-3 py-2 whitespace-nowrap">时间</th>
                      <th className="px-3 py-2 whitespace-nowrap">事件</th>
                      <th className="px-3 py-2 whitespace-nowrap">级别</th>
                      <th className="px-3 py-2 whitespace-nowrap">结果</th>
                      <th className="px-3 py-2">模型 / 错误</th>
                      <th className="px-3 py-2 whitespace-nowrap">状态 / 延迟</th>
                      <th className="px-3 py-2">摘要</th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((item) => (
                      <tr
                        key={item.id}
                        className="border-t cursor-pointer hover:bg-muted/40 align-top"
                        onClick={() => setExpandedLogId(expandedLogId === item.id ? null : item.id)}
                      >
                        <td className="px-3 py-2 whitespace-nowrap text-xs text-muted-foreground">{formatTime(item.createdAt)}</td>
                        <td className="px-3 py-2 whitespace-nowrap">{eventTypeLabels[item.eventType] || item.eventType}</td>
                        <td className="px-3 py-2 whitespace-nowrap"><Badge variant={badgeVariant(item.severity)}>{severityLabels[item.severity] || item.severity}</Badge></td>
                        <td className="px-3 py-2 whitespace-nowrap">{outcomeLabels[item.outcome] || item.outcome}</td>
                        <td className="px-3 py-2 max-w-[220px]">
                          <div className="truncate">{item.model || item.apiType || '—'}</div>
                          {item.errorClass && <div className="truncate text-xs text-destructive">{item.errorClass}</div>}
                        </td>
                        <td className="px-3 py-2 whitespace-nowrap text-xs text-muted-foreground">
                          {item.upstreamStatus ?? '—'}{item.latencyMs != null ? ` · ${item.latencyMs}ms` : ''}
                        </td>
                        <td className="px-3 py-2 min-w-[240px]">
                          <div className="line-clamp-2">{item.message}</div>
                          {expandedLogId === item.id && (
                            <div className="mt-2 space-y-1 text-xs">
                              {item.requestId && <div className="text-muted-foreground">请求 ID：{item.requestId}</div>}
                              {item.details && (
                                <pre className="max-h-40 overflow-auto rounded bg-muted p-2 whitespace-pre-wrap break-all">
                                  {JSON.stringify(item.details, null, 2)}
                                </pre>
                              )}
                            </div>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
            {logs.hasNextPage && (
              <Button variant="outline" onClick={() => logs.fetchNextPage()} disabled={logs.isFetchingNextPage}>
                {logs.isFetchingNextPage ? '正在加载…' : '加载更早 100 条'}
              </Button>
            )}
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
