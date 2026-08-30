import { useState } from 'react'
import { AlertTriangle, CheckCircle2, CircleHelp, Network, Unplug, UserPlus } from 'lucide-react'
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
import { manualBindProxy, manualUnbindProxy } from '@/api/credentials'
import type { CredentialStatusItem, ProxyPoolEntryStatus, ProxyPoolResponse } from '@/types/api'

interface ProxyPoolStatusCardProps {
  data?: ProxyPoolResponse
  isLoading: boolean
  credentials: CredentialStatusItem[]
  onChanged: () => void
}

export function ProxyPoolStatusCard({ data, isLoading, credentials, onChanged }: ProxyPoolStatusCardProps) {
  const [bindingProxy, setBindingProxy] = useState<ProxyPoolEntryStatus | null>(null)
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set())
  const [working, setWorking] = useState(false)
  const utilization = data && data.totalCapacity > 0
    ? Math.min(100, (data.assignedSlots / data.totalCapacity) * 100)
    : 0

  const openBind = (proxy: ProxyPoolEntryStatus) => {
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

  const candidates = bindingProxy
    ? credentials.filter(credential => !credential.hasProxy && bindingProxy.remainingSlots > 0)
    : []


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
                {data.proxies.map(proxy => <ProxyEntry key={proxy.proxyUrl} proxy={proxy} onBind={() => openBind(proxy)} onUnbind={unbind} working={working} />)}
              </div>
            </details>
          )}
        </CardContent>
      </Card>
      <Dialog open={bindingProxy !== null} onOpenChange={open => !open && setBindingProxy(null)}>
        <DialogContent className="sm:max-w-[620px]">
          <DialogHeader>
            <DialogTitle>手动绑定代理账号</DialogTitle>
            <DialogDescription>{bindingProxy?.proxyUrl}，剩余 {bindingProxy?.remainingSlots ?? 0} 个槽位。仅显示启用且未绑定代理的账号。</DialogDescription>
          </DialogHeader>
          <div className="max-h-[50vh] space-y-1 overflow-auto rounded-lg border p-2">
            {candidates.length === 0 ? <p className="p-4 text-sm text-muted-foreground">没有可绑定账号</p> : candidates.map(credential => (
              <label key={credential.id} className="flex cursor-pointer items-center gap-3 rounded-md px-3 py-2 hover:bg-muted/50">
                <Checkbox checked={selectedIds.has(credential.id)} onCheckedChange={() => toggleCandidate(credential.id)} />
                <span className="min-w-0 flex-1"><span className="block truncate font-medium">#{credential.id} {credential.email || credential.subscriptionTitle || '未知账号'}</span><span className="text-xs text-muted-foreground">{credential.importNote || '无备注'} · RPM {credential.currentRpm}</span></span>
              </label>
            ))}
          </div>
          <DialogFooter><Button variant="outline" onClick={() => setBindingProxy(null)} disabled={working}>取消</Button><Button onClick={bindSelected} disabled={working || selectedIds.size === 0}>绑定并验证 {selectedIds.size} 个</Button></DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}

function ProxyEntry({ proxy, onBind, onUnbind, working }: { proxy: ProxyPoolEntryStatus; onBind: () => void; onUnbind: (id: number) => void; working: boolean }) {
  return <div className="rounded-lg border bg-background p-3 text-xs"><div className="flex items-start justify-between gap-2"><div className="min-w-0 truncate font-mono font-medium" title={proxy.proxyUrl}>{proxy.proxyUrl}</div><Badge variant={proxy.assignedCount === 0 ? 'secondary' : proxy.abnormalCount > 0 ? 'destructive' : 'success'}>{proxy.assignedCount}/{proxy.assignedCount + proxy.remainingSlots}</Badge></div><div className="mt-2 flex flex-wrap gap-1"><Badge variant="success">正常 {proxy.healthyCount}</Badge><Badge variant={proxy.abnormalCount > 0 ? 'destructive' : 'outline'}>异常 {proxy.abnormalCount}</Badge><Badge variant="outline">未知 {proxy.unknownCount}</Badge>{proxy.assignedCount === 0 && <Badge variant="secondary">空置</Badge>}</div><div className="mt-3 space-y-1.5">{proxy.assignedCredentials.length === 0 ? <div className="text-muted-foreground">暂无绑定账号</div> : proxy.assignedCredentials.map(credential => <div key={credential.credentialId} className="flex items-center justify-between gap-2 rounded bg-muted/35 px-2 py-1.5"><div className="min-w-0"><div className="truncate font-medium">#{credential.credentialId} {credential.email || credential.subscriptionTitle || '未知账号'}</div><div className="text-muted-foreground">{credential.remaining == null || credential.usageLimit == null ? '余额未知' : `剩余 ${credential.remaining.toFixed(0)} / ${credential.usageLimit.toFixed(0)}`}</div></div><div className="flex items-center gap-1">{credential.health === 'healthy' ? <CheckCircle2 className="h-4 w-4 text-green-600" /> : credential.health === 'abnormal' ? <AlertTriangle className="h-4 w-4 text-red-500" /> : <CircleHelp className="h-4 w-4 text-muted-foreground" />}<Button size="sm" variant="ghost" className="h-7 px-2" onClick={() => onUnbind(credential.credentialId)} disabled={working}><Unplug className="h-3.5 w-3.5" /></Button></div></div>)}</div>{proxy.remainingSlots > 0 && <Button size="sm" variant="outline" className="mt-3 w-full gap-1.5" onClick={onBind} disabled={working}><UserPlus className="h-3.5 w-3.5" />手动绑定账号</Button>}</div>
}

function Metric({ label, value, tone = 'default' }: { label: string; value: string | number; tone?: 'default' | 'blue' | 'green' | 'red' }) { const toneClass = tone === 'blue' ? 'text-sky-700 dark:text-sky-300' : tone === 'green' ? 'text-green-700 dark:text-green-300' : tone === 'red' ? 'text-red-600 dark:text-red-400' : 'text-foreground'; return <div className="rounded-lg border bg-muted/15 px-3 py-3"><div className="text-xs text-muted-foreground">{label}</div><div className={`mt-1 font-mono text-xl font-bold tabular-nums ${toneClass}`}>{value}</div></div> }
