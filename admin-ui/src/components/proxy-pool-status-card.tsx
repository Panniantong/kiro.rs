import { useState } from 'react'
import type { ChangeEvent } from 'react'
import { AlertTriangle, CheckCircle2, CircleHelp, Network, Plus, RefreshCw, Trash2, Unplug, UserPlus } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  addProxyPoolEntries,
  batchGetCredentialBalance,
  manualBindProxy,
  manualUnbindProxy,
  removeProxyPoolEntries,
  testProxyPoolEntry,
} from '@/api/credentials'
import type { CredentialStatusItem, ProxyPoolEntryStatus, ProxyPoolResponse } from '@/types/api'

interface ProxyPoolStatusCardProps {
  data?: ProxyPoolResponse
  isLoading: boolean
  credentials: CredentialStatusItem[]
  onChanged: () => void
}

export function ProxyPoolStatusCard({ data, isLoading, credentials, onChanged }: ProxyPoolStatusCardProps) {
  const [working, setWorking] = useState(false)
  const [testingProxies, setTestingProxies] = useState<Set<string>>(new Set())
  const [bindingProxy, setBindingProxy] = useState<ProxyPoolEntryStatus | null>(null)
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set())
  const [selectedProxies, setSelectedProxies] = useState<Set<string>>(new Set())
  const [candidateStatusFilter, setCandidateStatusFilter] = useState<'all' | 'enabled' | 'disabled' | 'recent'>('all')
  const [candidateReasonFilter, setCandidateReasonFilter] = useState('all')
  const [candidateBalanceFilter, setCandidateBalanceFilter] = useState<'all' | 'fresh' | 'stale' | 'failed' | 'notChecked'>('all')
  const utilization = data && data.totalCapacity > 0
    ? Math.min(100, (data.assignedSlots / data.totalCapacity) * 100)
    : 0

  const openBind = (proxy: ProxyPoolEntryStatus) => {
    setCandidateStatusFilter('all')
    setCandidateReasonFilter('all')
    setCandidateBalanceFilter('all')
    setBindingProxy(proxy)
    setSelectedIds(new Set())
  }

  const toggleCandidate = (id: number) => {
    setSelectedIds(previous => {
      const next = new Set(previous)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const bindSelected = async () => {
    if (!bindingProxy || selectedIds.size === 0) return
    setWorking(true)
    try {
      const result = await manualBindProxy({
        proxyUrl: bindingProxy.proxyUrl,
        credentialIds: Array.from(selectedIds),
      })
      if (result.failed.length > 0) {
        toast.warning(`绑定完成 ${result.updatedCredentialIds.length} 个，失败 ${result.failed.length} 个`)
      } else {
        toast.success(`已绑定 ${result.updatedCredentialIds.length} 个账号`)
      }
      setBindingProxy(null)
      onChanged()
    } catch (error) {
      toast.error(`手动绑定失败：${(error as Error).message}`)
    } finally {
      setWorking(false)
    }
  }

  const unbind = async (credentialId: number) => {
    if (!confirm(`确定解除账号 #${credentialId} 的代理占用吗？启用账号会先被禁用，避免解绑后直连。`)) return
    setWorking(true)
    try {
      const result = await manualUnbindProxy({ credentialIds: [credentialId] })
      if (result.failed.length > 0) toast.error(result.failed[0].reason)
      else toast.success(`账号 #${credentialId} 已解除代理占用`)
      onChanged()
    } catch (error) {
      toast.error(`解除占用失败：${(error as Error).message}`)
    } finally {
      setWorking(false)
    }
  }

  const testProxy = async (proxyUrl: string) => {
    setTestingProxies(previous => new Set([...previous, proxyUrl]))
    try {
      const result = await testProxyPoolEntry(proxyUrl)
      if (result.state === 'passed') {
        const egress = result.egressIp ? `，出口 ${result.egressIp}` : ''
        toast.success(`代理测试通过${egress}`)
      } else {
        toast.error(`代理测试失败：${result.failureClass || '未知错误'}`)
      }
      onChanged()
    } catch (error) {
      toast.error(`代理测试失败：${(error as Error).message}`)
    } finally {
      setTestingProxies(previous => {
        const next = new Set(previous)
        next.delete(proxyUrl)
        return next
      })
    }
  }

  const toggleProxy = (url: string) => setSelectedProxies(previous => {
    const next = new Set(previous)
    if (next.has(url)) next.delete(url)
    else next.add(url)
    return next
  })

  const importProxyFile = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    const text = await file.text()
    const proxies = Array.from(new Set(text.split(/\r?\n/).flatMap(line => {
      const clean = line.trim()
      if (!clean) return []
      const url = clean.match(/(?:socks5|https?):\/\/[^\s,"']+/i)
      if (url) return [url[0].replace(/[\]\)]+$/, '')]
      // 兼容代理服务商 CSV：ip:port,username,password,...
      const columns = clean.split(',').map(column => column.trim().replace(/^"|"$/g, ''))
      const hostPort = columns[0]
      const username = columns[1]
      const password = columns[2]
      if (/^[^:]+:\d+$/.test(hostPort) && username && password) {
        return [`socks5://${username}:${password}@${hostPort}`]
      }
      return []
    })))
    if (proxies.length === 0) {
      toast.error('文件中没有识别到代理地址')
      return
    }
    setWorking(true)
    try {
      const result = await addProxyPoolEntries({ proxies: proxies.map(proxyUrl => ({ proxyUrl })) })
      toast.success(`${result.message}，识别 ${proxies.length} 条`)
      onChanged()
    } catch (error) {
      toast.error(`导入代理失败：${(error as Error).message}`)
    } finally {
      setWorking(false)
    }
  }

  const removeSelected = async () => {
    if (selectedProxies.size === 0) return
    if (!confirm(`确定从代理池移除 ${selectedProxies.size} 个代理吗？已绑定账号不会被删除。`)) return
    setWorking(true)
    try {
      const result = await removeProxyPoolEntries({ proxyUrls: Array.from(selectedProxies) })
      toast.success(result.message)
      setSelectedProxies(new Set())
      onChanged()
    } catch (error) {
      toast.error(`删除代理失败：${(error as Error).message}`)
    } finally {
      setWorking(false)
    }
  }

  const candidates = bindingProxy
    ? credentials
      .filter(credential => {
        if (credential.hasProxy || bindingProxy.remainingSlots <= 0) return false
        if (candidateStatusFilter === 'enabled' && credential.disabled) return false
        if (candidateStatusFilter === 'disabled' && !credential.disabled) return false
        if (candidateStatusFilter === 'recent') {
          if (!credential.disabledAt) return false
          const disabledAt = Date.parse(credential.disabledAt)
          if (!Number.isFinite(disabledAt) || Date.now() - disabledAt > 72 * 60 * 60 * 1000) return false
        }
        if (candidateReasonFilter !== 'all' && credential.disabledReason !== candidateReasonFilter) return false
        if (candidateBalanceFilter !== 'all' && (credential.balanceState || 'notChecked') !== candidateBalanceFilter) return false
        return true
      })
      .sort((a, b) => Number(a.disabled) - Number(b.disabled) || a.id - b.id)
    : []

  const queryCandidateBalances = async () => {
    const ids = candidates.map(credential => credential.id)
    if (ids.length === 0) {
      toast.info('当前筛选没有可查询的账号')
      return
    }
    setWorking(true)
    try {
      const response = await batchGetCredentialBalance(ids, true)
      const successCount = response.results.filter(result => Boolean(result.balance)).length
      toast.success(`候选余额查询完成：成功 ${successCount}/${ids.length}`)
      onChanged()
    } catch (error) {
      toast.error(`候选余额查询失败：${(error as Error).message}`)
    } finally {
      setWorking(false)
    }
  }

  return (
    <>
      <Card className="mb-6 overflow-hidden">
        <CardHeader className="border-b bg-muted/20 pb-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <Network className="h-4 w-4 text-sky-600" />
              代理池状态
            </CardTitle>
            <div className="flex flex-wrap gap-2">
              <input id="proxy-import-file" type="file" accept=".txt,.csv,text/plain,text/csv" className="hidden" onChange={importProxyFile} disabled={working} />
              <Button size="sm" variant="outline" className="gap-1.5" onClick={() => document.getElementById('proxy-import-file')?.click()} disabled={working}><Plus className="h-3.5 w-3.5" />导入代理</Button>
              {selectedProxies.size > 0 && <Button size="sm" variant="destructive" className="gap-1.5" onClick={removeSelected} disabled={working}><Trash2 className="h-3.5 w-3.5" />删除选中 ({selectedProxies.size})</Button>}
              <Badge variant={data?.pendingCredentialCount ? 'warning' : 'success'}>等待 {data?.pendingCredentialCount ?? 0}</Badge>
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
            <Metric label="异常 / 未知" value={isLoading ? '—' : `${data?.abnormalAssignedCount ?? 0} / ${data?.unknownAssignedCount ?? 0}`} tone={(data?.abnormalAssignedCount ?? 0) > 0 ? 'red' : 'default'} />
          </div>
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <span>容量利用率 {utilization.toFixed(1)}%</span>
              <span>空代理 {data?.emptyProxyCount ?? 0} · 部分占用 {data?.partialProxyCount ?? 0} · 满载 {data?.fullProxyCount ?? 0}</span>
            </div>
            <div className="h-2 overflow-hidden rounded-full bg-muted"><div className="h-full rounded-full bg-sky-500 transition-all" style={{ width: `${utilization}%` }} /></div>
            {data?.emptyReason && <p className="flex items-start gap-2 rounded-lg bg-muted/35 px-3 py-2 text-xs text-muted-foreground"><CircleHelp className="mt-0.5 h-3.5 w-3.5 shrink-0" />{data.emptyReason}</p>}
          </div>
          {data && data.proxies.length > 0 && (
            <details className="group rounded-lg border" open>
              <summary className="cursor-pointer select-none px-4 py-3 text-sm font-medium">查看 {data.proxies.length} 个代理的占用明细</summary>
              <div className="grid gap-3 border-t bg-muted/10 p-3 lg:grid-cols-2 xl:grid-cols-3">
                {data.proxies.map(proxy => (
                  <ProxyEntry
                    key={proxy.proxyUrl}
                    proxy={proxy}
                    selected={selectedProxies.has(proxy.proxyUrl)}
                    onSelect={() => toggleProxy(proxy.proxyUrl)}
                    onBind={() => openBind(proxy)}
                    onTest={() => testProxy(proxy.proxyUrl)}
                    onUnbind={unbind}
                    testing={testingProxies.has(proxy.proxyUrl)}
                    working={working}
                  />
                ))}
              </div>
            </details>
          )}
        </CardContent>
      </Card>
      <Dialog open={bindingProxy !== null} onOpenChange={open => !open && setBindingProxy(null)}>
        <DialogContent className="sm:max-w-[620px]">
          <DialogHeader>
            <DialogTitle>手动绑定代理账号</DialogTitle>
            <DialogDescription>{bindingProxy?.proxyUrl}，剩余 {bindingProxy?.remainingSlots ?? 0} 个槽位。显示所有未绑定账号，禁用账号只有在代理与账号探测都通过后才会恢复。</DialogDescription>
          </DialogHeader>
          <div className="grid gap-2 rounded-lg border bg-muted/20 p-3 sm:grid-cols-3">
            <label className="space-y-1 text-xs">
              <span className="text-muted-foreground">账号状态</span>
              <select
                className="h-8 w-full rounded-md border bg-background px-2"
                value={candidateStatusFilter}
                onChange={event => setCandidateStatusFilter(event.target.value as typeof candidateStatusFilter)}
              >
                <option value="all">全部</option>
                <option value="enabled">仅可用</option>
                <option value="disabled">仅禁用</option>
                <option value="recent">禁用近 72 小时</option>
              </select>
            </label>
            <label className="space-y-1 text-xs">
              <span className="text-muted-foreground">禁用原因</span>
              <select
                className="h-8 w-full rounded-md border bg-background px-2"
                value={candidateReasonFilter}
                onChange={event => setCandidateReasonFilter(event.target.value)}
              >
                <option value="all">全部原因</option>
                <option value="QuotaExceeded">额度用尽</option>
                <option value="UpstreamSuspended">上游封停</option>
                <option value="InvalidRefreshToken">Token 失效</option>
                <option value="TooManyFailures">连续失败</option>
                <option value="TooManyRefreshFailures">刷新失败</option>
                <option value="InvalidConfig">配置无效</option>
                <option value="Manual">手动禁用</option>
              </select>
            </label>
            <label className="space-y-1 text-xs">
              <span className="text-muted-foreground">余额状态</span>
              <select
                className="h-8 w-full rounded-md border bg-background px-2"
                value={candidateBalanceFilter}
                onChange={event => setCandidateBalanceFilter(event.target.value as typeof candidateBalanceFilter)}
              >
                <option value="all">全部状态</option>
                <option value="fresh">最新缓存</option>
                <option value="stale">缓存过期</option>
                <option value="failed">查询失败</option>
                <option value="notChecked">未查询</option>
              </select>
            </label>
          </div>
          <div className="flex items-center justify-between gap-2 text-xs text-muted-foreground">
            <span>当前筛选 {candidates.length} 个账号</span>
            <Button size="sm" variant="outline" onClick={queryCandidateBalances} disabled={working || candidates.length === 0}>
              查询候选余额
            </Button>
          </div>
          <div className="max-h-[50vh] space-y-1 overflow-auto rounded-lg border p-2">
            {candidates.length === 0 ? <p className="p-4 text-sm text-muted-foreground">没有可绑定账号</p> : candidates.map(credential => (
              <label key={credential.id} className="flex cursor-pointer items-center gap-3 rounded-md px-3 py-2 hover:bg-muted/50">
                <Checkbox checked={selectedIds.has(credential.id)} onCheckedChange={() => toggleCandidate(credential.id)} />
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-medium">#{credential.id} {credential.email || credential.subscriptionTitle || '未知账号'}</span>
                  <span className="text-xs text-muted-foreground">
                    {credential.disabled ? `已禁用 · ${credential.disabledReason || '原因未知'}` : '可用'} · {credential.importNote || '无备注'} · RPM {credential.currentRpm}
                  </span>
                  <span className="block text-[11px] text-muted-foreground">
                    余额 {credential.balanceState || 'notChecked'} · {credential.balanceRemaining == null || credential.balanceUsageLimit == null ? '—' : `${credential.balanceRemaining.toFixed(0)} / ${credential.balanceUsageLimit.toFixed(0)}`}
                  </span>
                </span>
              </label>
            ))}
          </div>
          <DialogFooter><Button variant="outline" onClick={() => setBindingProxy(null)} disabled={working}>取消</Button><Button onClick={bindSelected} disabled={working || selectedIds.size === 0}>绑定并验证 {selectedIds.size} 个</Button></DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}

function ProxyEntry({
  proxy,
  selected,
  onSelect,
  onBind,
  onTest,
  onUnbind,
  testing,
  working,
}: {
  proxy: ProxyPoolEntryStatus
  selected: boolean
  onSelect: () => void
  onBind: () => void
  onTest: () => void
  onUnbind: (id: number) => void
  testing: boolean
  working: boolean
}) {
  const lastTest = proxy.lastTest
  return (
    <div className="rounded-lg border bg-background p-3 text-xs">
      <div className="flex items-start justify-between gap-2">
        <label className="flex min-w-0 items-center gap-2">
          <Checkbox checked={selected} onCheckedChange={onSelect} />
          <span className="truncate font-mono font-medium" title={proxy.proxyUrl}>{proxy.proxyUrl}</span>
        </label>
        <Badge variant={proxy.assignedCount === 0 ? 'secondary' : proxy.abnormalCount > 0 ? 'destructive' : 'success'}>
          {proxy.assignedCount}/{proxy.assignedCount + proxy.remainingSlots}
        </Badge>
      </div>
      <div className="mt-2 flex flex-wrap gap-1">
        <Badge variant="success">正常 {proxy.healthyCount}</Badge>
        <Badge variant={proxy.abnormalCount > 0 ? 'destructive' : 'outline'}>异常 {proxy.abnormalCount}</Badge>
        <Badge variant="outline">未知 {proxy.unknownCount}</Badge>
        {proxy.assignedCount === 0 && <Badge variant="secondary">空置</Badge>}
        <Badge variant={!lastTest ? 'outline' : lastTest.state === 'passed' ? 'success' : 'destructive'}>
          {!lastTest ? '未测试出口' : lastTest.state === 'passed' ? `出口通过${lastTest.egressIp ? ` · ${lastTest.egressIp}` : ''}` : `出口失败 · ${lastTest.failureClass || '未知'}`}
        </Badge>
        {lastTest && (
          <span className="basis-full text-[11px] text-muted-foreground">
            测试于 {new Date(lastTest.testedAt).toLocaleString('zh-CN')} · 延迟 {lastTest.latencyMs == null ? '—' : `${lastTest.latencyMs}ms`}
          </span>
        )}
      </div>
      <div className="mt-3 space-y-1.5">
        {proxy.assignedCredentials.length === 0 ? <div className="text-muted-foreground">暂无绑定账号</div> : proxy.assignedCredentials.map(credential => (
          <div key={credential.credentialId} className="flex items-center justify-between gap-2 rounded bg-muted/35 px-2 py-1.5">
            <div className="min-w-0">
              <div className="truncate font-medium">#{credential.credentialId} {credential.email || credential.subscriptionTitle || '未知账号'}</div>
              <div className="text-muted-foreground">{credential.remaining == null || credential.usageLimit == null ? '余额未知' : `剩余 ${credential.remaining.toFixed(0)} / ${credential.usageLimit.toFixed(0)}`}</div>
              <div className="text-[11px] text-muted-foreground">
                代理 {credential.proxyProbeState} · 账号 {credential.accountProbeState} · 恢复 {credential.recoveryState}
              </div>
            </div>
            <div className="flex items-center gap-1">
              {credential.health === 'healthy' ? <CheckCircle2 className="h-4 w-4 text-green-600" /> : credential.health === 'abnormal' ? <AlertTriangle className="h-4 w-4 text-red-500" /> : <CircleHelp className="h-4 w-4 text-muted-foreground" />}
              <Button size="sm" variant="ghost" className="h-7 px-2" onClick={() => onUnbind(credential.credentialId)} disabled={working}><Unplug className="h-3.5 w-3.5" /></Button>
            </div>
          </div>
        ))}
      </div>
      <div className="mt-3 grid grid-cols-2 gap-2">
        <Button size="sm" variant="outline" className="gap-1.5" onClick={onTest} disabled={working || testing}>
          <RefreshCw className={`h-3.5 w-3.5 ${testing ? 'animate-spin' : ''}`} />
          {testing ? '测试中...' : '测试出口'}
        </Button>
        {proxy.remainingSlots > 0 && (
          <Button size="sm" variant="outline" className="gap-1.5" onClick={onBind} disabled={working || testing}>
            <UserPlus className="h-3.5 w-3.5" />手动绑定
          </Button>
        )}
      </div>
    </div>
  )
}

function Metric({ label, value, tone = 'default' }: { label: string; value: string | number; tone?: 'default' | 'blue' | 'green' | 'red' }) { const toneClass = tone === 'blue' ? 'text-sky-700 dark:text-sky-300' : tone === 'green' ? 'text-green-700 dark:text-green-300' : tone === 'red' ? 'text-red-600 dark:text-red-400' : 'text-foreground'; return <div className="rounded-lg border bg-muted/15 px-3 py-3"><div className="text-xs text-muted-foreground">{label}</div><div className={`mt-1 font-mono text-xl font-bold tabular-nums ${toneClass}`}>{value}</div></div> }
