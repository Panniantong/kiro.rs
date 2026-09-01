import { useEffect, useState } from 'react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { useBatchUpdateCredentials } from '@/hooks/use-credentials'

interface BatchEditDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  credentialIds: number[]
  onCompleted: () => void
}

export function BatchEditDialog({
  open,
  onOpenChange,
  credentialIds,
  onCompleted,
}: BatchEditDialogProps) {
  const [importNote, setImportNote] = useState('')
  const [priority, setPriority] = useState('')
  const batchUpdate = useBatchUpdateCredentials()

  useEffect(() => {
    if (open) {
      setImportNote('')
      setPriority('')
    }
  }, [open])

  const submit = () => {
    const note = importNote.trim()
    const parsedPriority = priority.trim() === '' ? undefined : Number(priority)

    if (!note && parsedPriority === undefined) {
      toast.error('请至少填写备注或优先级')
      return
    }
    if (parsedPriority !== undefined && (!Number.isInteger(parsedPriority) || parsedPriority < 0)) {
      toast.error('优先级必须是非负整数')
      return
    }

    batchUpdate.mutate(
      {
        ids: credentialIds,
        importNote: note || undefined,
        priority: parsedPriority,
      },
      {
        onSuccess: (result) => {
          toast.success(result.message)
          onOpenChange(false)
          onCompleted()
        },
        onError: (error) => toast.error(`批量更新失败：${(error as Error).message}`),
      }
    )
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[520px]">
        <DialogHeader>
          <DialogTitle>批量编辑凭据</DialogTitle>
          <DialogDescription>
            已选择 {credentialIds.length} 个凭据。填写的字段会覆盖选中账号的现有值，空字段保持不变。
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <label className="block space-y-2">
            <span className="text-sm font-medium">统一备注 / 分组</span>
            <Input
              value={importNote}
              onChange={event => setImportNote(event.target.value)}
              placeholder="例如：8月27日企业号测试组"
              maxLength={200}
            />
            <span className="text-xs text-muted-foreground">非空时覆盖 importNote。</span>
          </label>
          <label className="block space-y-2">
            <span className="text-sm font-medium">统一优先级</span>
            <Input
              type="number"
              min="0"
              step="1"
              value={priority}
              onChange={event => setPriority(event.target.value)}
              placeholder="留空则不修改"
            />
            <span className="text-xs text-muted-foreground">数字越小优先级越高。</span>
          </label>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={batchUpdate.isPending}>
            取消
          </Button>
          <Button onClick={submit} disabled={batchUpdate.isPending || credentialIds.length === 0}>
            {batchUpdate.isPending ? '保存中...' : `更新 ${credentialIds.length} 个`}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
