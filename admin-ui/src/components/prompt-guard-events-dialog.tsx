import { useMemo, useState } from 'react'
import { RefreshCw, ShieldAlert } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { usePromptGuardEvents } from '@/hooks/use-credentials'
import { cn, extractErrorMessage } from '@/lib/utils'
import type {
  PromptGuardEventCategory,
  PromptGuardEventItem,
  PromptGuardEventKind,
} from '@/types/api'

interface PromptGuardEventsDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

const PAGE_SIZE = 20
const SELECT_CLASS = 'h-9 rounded-md border bg-background px-3 text-sm'

const CATEGORY_ORDER: PromptGuardEventCategory[] = [
  'bio',
  'crack',
  'intrusion',
  'bulk_data',
  'distill',
  'jailbreak',
  'sysprompt',
  'privacy',
  'cot',
  'reverse',
  'porn',
  'violence',
  'gore',
  'hate',
  'politics',
  'roleplay',
  'zhipu_filter',
  'unknown',
]

const CATEGORY_LABELS: Record<PromptGuardEventCategory, string> = {
  bio: '生化武器',
  crack: '软件破解',
  intrusion: '入侵攻击',
  bulk_data: '批量造假数据',
  distill: '模型蒸馏',
  jailbreak: '越狱',
  sysprompt: '套系统提示词',
  privacy: '隐私与凭证窃取',
  cot: '思考过程索取',
  reverse: '逆向破解',
  porn: '色情',
  violence: '暴力',
  gore: '血腥',
  hate: '仇恨',
  politics: '政治',
  roleplay: '角色扮演陪聊',
  zhipu_filter: '智谱风控拦截',
  unknown: '未分类',
}

const KIND_LABELS: Record<PromptGuardEventKind, string> = {
  block: 'AI 拦截',
  log_only: '仅记录',
  judge_error: '审核出错放行',
}

const KIND_OPTIONS: PromptGuardEventKind[] = ['block', 'log_only', 'judge_error']

const DAYS_OPTIONS: { value: number; label: string }[] = [
  { value: 1, label: '近 24 小时' },
  { value: 7, label: '近7天' },
  { value: 30, label: '近30天' },
  { value: 0, label: '全部时间' },
]

const DETAIL_DESCRIPTIONS: Record<PromptGuardEventKind, string> = {
  block: '本地拦截，没有转发给 Kiro。',
  log_only: '只记录，请求已照常转发。',
  judge_error: '审核服务出错，请求已照常放行。',
}

function categoryLabel(category: string): string {
  return CATEGORY_LABELS[category as PromptGuardEventCategory] ?? (category || '—')
}

function kindBadgeVariant(kind: PromptGuardEventKind): 'destructive' | 'warning' | 'secondary' {
  if (kind === 'block') return 'destructive'
  if (kind === 'log_only') return 'warning'
  return 'secondary'
}

function formatLocalTime(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${date.getFullYear()}/${pad(date.getMonth() + 1)}/${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}

function statusTextOf(active: boolean | undefined, mode: string | undefined): string {
  if (active === undefined) return '—'
  if (active && mode === 'block') return '正常审核'
  if (active && mode === 'log') return '只记录不拦截'
  return '未生效'
}

function StatBlock({ label, value, hint }: { label: string; value: number; hint?: string }) {
  return (
    <div className="rounded-md border p-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-xl font-semibold tabular-nums">{value}</div>
      {hint && <div className="text-xs text-muted-foreground">{hint}</div>}
    </div>
  )
}

function MetaRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex gap-2">
      <dt className="shrink-0 text-muted-foreground">{label}</dt>
      <dd className="break-all">{value}</dd>
    </div>
  )
}

export function PromptGuardEventsDialog({ open, onOpenChange }: PromptGuardEventsDialogProps) {
  const [days, setDays] = useState(7)
  const [kind, setKind] = useState<PromptGuardEventKind | ''>('')
  const [category, setCategory] = useState<PromptGuardEventCategory | ''>('')
  const [page, setPage] = useState(1)
  const [expandedId, setExpandedId] = useState<number | null>(null)
  const [detailItem, setDetailItem] = useState<PromptGuardEventItem | null>(null)

  const filters = useMemo(
    () => ({
      days,
      ...(kind ? { kind } : {}),
      ...(category ? { category } : {}),
      page,
      pageSize: PAGE_SIZE,
    }),
    [days, kind, category, page]
  )

  const events = usePromptGuardEvents(filters, open)
  const data = events.data
  const items = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = data ? Math.max(1, Math.ceil(data.total / (data.pageSize || PAGE_SIZE))) : 1
  const logOnly = data?.totals.logOnly ?? 0

  const categoryCounts = useMemo(() => {
    const map = new Map<string, number>()
    for (const entry of data?.categories ?? []) {
      map.set(entry.category, entry.count)
    }
    return map
  }, [data?.categories])

  const changeDays = (value: number) => {
    setDays(value)
    setPage(1)
    setExpandedId(null)
  }

  const changeKind = (value: PromptGuardEventKind | '') => {
    setKind(value)
    setPage(1)
    setExpandedId(null)
  }

  const toggleCategory = (value: PromptGuardEventCategory) => {
    setCategory((current) => (current === value ? '' : value))
    setPage(1)
    setExpandedId(null)
  }

  const changeCategory = (value: PromptGuardEventCategory | '') => {
    setCategory(value)
    setPage(1)
    setExpandedId(null)
  }

  const handleOpenChange = (next: boolean) => {
    if (!next) setDetailItem(null)
    onOpenChange(next)
  }

  const currentStatusText = statusTextOf(data?.status.active, data?.status.mode)
  const statusClass =
    currentStatusText === '正常审核'
      ? 'text-green-600 dark:text-green-500'
      : currentStatusText === '只记录不拦截'
        ? 'text-amber-600 dark:text-amber-500'
        : 'text-muted-foreground'

  return (
    <>
      <Dialog open={open} onOpenChange={handleOpenChange}>
        <DialogContent className="max-w-3xl max-h-[90vh] overflow-hidden flex flex-col gap-3">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5" />
              拦截明细
            </DialogTitle>
          </DialogHeader>

          <div className="min-h-0 flex-1 space-y-4 overflow-auto pr-1">
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
              <StatBlock label="AI 拦截" value={data?.totals.block ?? 0} />
              <StatBlock
                label="审核出错放行"
                value={data?.totals.judgeError ?? 0}
                hint={`近 1 小时 ${data?.recentJudgeErrors1h ?? 0} 次`}
              />
              {logOnly !== 0 && <StatBlock label="仅记录" value={logOnly} />}
              <div className="rounded-md border p-3">
                <div className="text-xs text-muted-foreground">当前状态</div>
                <div className={cn('text-sm font-medium', statusClass)}>{currentStatusText}</div>
              </div>
            </div>

            <div className="space-y-2">
              <div className="text-xs font-medium text-muted-foreground">拦截分类（点标签筛选，再点取消）</div>
              <div className="flex flex-wrap gap-2">
                {CATEGORY_ORDER.map((value) => {
                  const active = category === value
                  return (
                    <button
                      key={value}
                      type="button"
                      onClick={() => toggleCategory(value)}
                      className={cn(
                        'inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-xs transition-colors',
                        active ? 'border-primary bg-primary text-primary-foreground' : 'hover:bg-muted'
                      )}
                    >
                      <span>{CATEGORY_LABELS[value]}</span>
                      <span className={cn('tabular-nums', active ? 'opacity-90' : 'text-muted-foreground')}>
                        {categoryCounts.get(value) ?? 0}
                      </span>
                    </button>
                  )
                })}
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <select
                className={SELECT_CLASS}
                value={days}
                onChange={(event) => changeDays(Number(event.target.value))}
                aria-label="时间范围"
              >
                {DAYS_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
              <select
                className={SELECT_CLASS}
                value={kind}
                onChange={(event) => changeKind(event.target.value as PromptGuardEventKind | '')}
                aria-label="事件类型"
              >
                <option value="">全部事件类型</option>
                {KIND_OPTIONS.map((value) => (
                  <option key={value} value={value}>
                    {KIND_LABELS[value]}
                  </option>
                ))}
              </select>
              <select
                className={SELECT_CLASS}
                value={category}
                onChange={(event) => changeCategory(event.target.value as PromptGuardEventCategory | '')}
                aria-label="拦截分类"
              >
                <option value="">全部拦截分类</option>
                {CATEGORY_ORDER.map((value) => (
                  <option key={value} value={value}>
                    {CATEGORY_LABELS[value]}
                  </option>
                ))}
              </select>
              <Button
                variant="outline"
                size="sm"
                className="ml-auto"
                onClick={() => void events.refetch()}
                disabled={events.isFetching}
              >
                <RefreshCw className={cn('mr-1 h-4 w-4', events.isFetching && 'animate-spin')} />
                刷新
              </Button>
            </div>

            {events.error && (
              <div className="rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive">
                {extractErrorMessage(events.error)}
              </div>
            )}

            {events.isLoading && (
              <div className="py-10 text-center text-sm text-muted-foreground">正在加载拦截明细…</div>
            )}

            {!events.isLoading && !events.error && items.length === 0 && (
              <div className="py-10 text-center text-sm text-muted-foreground">这段时间没有拦截记录</div>
            )}

            <div className="space-y-2">
              {items.map((item) => {
                const expanded = expandedId === item.id
                return (
                  <div key={item.id} className="space-y-2 rounded-md border p-3">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0 space-y-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <Badge variant={kindBadgeVariant(item.kind)}>
                            {KIND_LABELS[item.kind] ?? item.kind}
                          </Badge>
                          <span className="text-xs text-muted-foreground">{categoryLabel(item.category)}</span>
                          <span className="text-xs text-muted-foreground">{formatLocalTime(item.createdAt)}</span>
                        </div>
                        <div className="break-words text-sm">{item.reason || '—'}</div>
                      </div>
                      <Button
                        variant="outline"
                        size="sm"
                        className="shrink-0"
                        onClick={() => setDetailItem(item)}
                      >
                        查看详情
                      </Button>
                    </div>
                    <button
                      type="button"
                      className="text-xs text-muted-foreground hover:underline"
                      onClick={() => setExpandedId(expanded ? null : item.id)}
                    >
                      {expanded ? '收起请求标识' : '展开请求标识'}
                    </button>
                    {expanded && (
                      <dl className="grid grid-cols-1 gap-x-4 gap-y-1 text-xs sm:grid-cols-2">
                        <MetaRow label="模型" value={item.model || '—'} />
                        <MetaRow label="请求路径" value={item.path || '—'} />
                        <MetaRow label="返回状态" value={item.status === null ? '已放行' : String(item.status)} />
                        <MetaRow label="审核耗时" value={`${item.elapsedMs} ms`} />
                        <MetaRow label="文本字数" value={String(item.chars)} />
                        <MetaRow label="是否超长截断" value={item.truncated ? '是' : '否'} />
                      </dl>
                    )}
                  </div>
                )
              })}
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2 border-t pt-3">
            <span className="text-xs text-muted-foreground">
              共 {total} 条 · 第 {page} / {totalPages} 页
            </span>
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={page <= 1 || events.isFetching}
                onClick={() => {
                  setPage((current) => Math.max(1, current - 1))
                  setExpandedId(null)
                }}
              >
                上一页
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={page >= totalPages || events.isFetching}
                onClick={() => {
                  setPage((current) => current + 1)
                  setExpandedId(null)
                }}
              >
                下一页
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      <Dialog
        open={detailItem !== null}
        onOpenChange={(next) => {
          if (!next) setDetailItem(null)
        }}
      >
        <DialogContent className="max-w-2xl max-h-[88vh] overflow-hidden flex flex-col">
          <DialogHeader>
            <DialogTitle>拦截详情</DialogTitle>
          </DialogHeader>
          {detailItem && (
            <div className="min-h-0 flex-1 space-y-3 overflow-auto pr-1">
              <p className="text-sm text-muted-foreground">
                {DETAIL_DESCRIPTIONS[detailItem.kind] ?? ''}
              </p>
              <dl className="space-y-1 text-sm">
                <MetaRow label="时间" value={formatLocalTime(detailItem.createdAt)} />
                <MetaRow label="请求" value={`POST ${detailItem.path || '—'}`} />
                <MetaRow
                  label="状态"
                  value={detailItem.status === null ? '已放行' : String(detailItem.status)}
                />
                <MetaRow label="分类" value={categoryLabel(detailItem.category)} />
                <MetaRow label="理由" value={detailItem.reason || '—'} />
                <MetaRow label="模型" value={detailItem.model || '—'} />
              </dl>
              <div className="space-y-1">
                <div className="text-xs font-medium text-muted-foreground">被拦的那段话</div>
                <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-md border bg-muted p-3 font-mono text-xs">{detailItem.preview || '未留存内容'}</pre>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </>
  )
}
