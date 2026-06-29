import { useEffect, useState, KeyboardEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import { UserPlus, X } from 'lucide-react'
import { Button, Card, PageHeader, Spinner, AlertBanner } from '@/components/ui'
import { toArr } from '@/lib/api'

interface Role {
  id: string
  name: string
}

interface AutoEnrollConfig {
  domains: string[]
  role_id: string | null
}

function DomainTagInput({
  values,
  onChange,
}: {
  values: string[]
  onChange: (v: string[]) => void
}) {
  const [draft, setDraft] = useState('')

  function commit() {
    const t = draft.trim().toLowerCase()
    if (!t || values.includes(t)) { setDraft(''); return }
    if (t.includes('@')) { toast.error("Enter the domain only, e.g. acme.com"); return }
    onChange([...values, t])
    setDraft('')
  }

  function onKey(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); commit() }
    if (e.key === 'Backspace' && draft === '' && values.length > 0) onChange(values.slice(0, -1))
  }

  return (
    <div
      className="flex flex-wrap gap-1.5 min-h-10 rounded-lg px-3 py-2 cursor-text"
      style={{ border: '0.5px solid var(--clavex-border)', background: 'var(--clavex-surface-card, #fff)' }}
      onClick={(e) => (e.currentTarget.querySelector('input') as HTMLInputElement | null)?.focus()}
    >
      {values.map((v) => (
        <span
          key={v}
          className="flex items-center gap-1 text-xs rounded-full px-2.5 py-0.5 font-medium"
          style={{ background: 'var(--clavex-50, #E1F5EE)', color: 'var(--clavex-700, #0F6E56)' }}
        >
          {v}
          <button type="button" onClick={() => onChange(values.filter((x) => x !== v))} className="opacity-60 hover:opacity-100">
            <X size={10} />
          </button>
        </span>
      ))}
      <input
        className="flex-1 min-w-24 outline-none text-sm bg-transparent"
        placeholder={values.length === 0 ? 'acme.com, partner.com … (Enter to add)' : ''}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={onKey}
        onBlur={commit}
      />
    </div>
  )
}

export default function AutoEnrollPage() {
  const orgId = useAuthStore((s) => s.orgId)
  const qc = useQueryClient()
  const [form, setForm] = useState<AutoEnrollConfig | null>(null)

  const { data, isLoading } = useQuery<AutoEnrollConfig>({
    queryKey: ['auto-enroll', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/auto-enroll`).then((r) => r.data),
    enabled: !!orgId,
  })

  const { data: roles = [] } = useQuery<Role[]>({
    queryKey: ['roles', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/roles`).then((r) => toArr<Role>(r.data)),
    enabled: !!orgId,
  })

  useEffect(() => {
    if (data && !form) setForm({ domains: data.domains ?? [], role_id: data.role_id ?? null })
  }, [data])

  const save = useMutation({
    mutationFn: (body: AutoEnrollConfig) =>
      api.put(`/organizations/${orgId}/auto-enroll`, body).then((r) => r.data),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['auto-enroll', orgId] })
      setForm({ domains: res.domains ?? [], role_id: res.role_id ?? null })
      toast.success('Auto-enroll settings saved')
    },
    onError: () => toast.error('Failed to save auto-enroll settings'),
  })

  if (isLoading || !form) return <Spinner />

  return (
    <div className="space-y-6">
      <PageHeader
        title="Auto-Enroll by Domain"
        subtitle="Automatically create an account for users whose email domain matches, and optionally assign a role."
      />

      <AlertBanner variant="info">
        Users signing in via an identity provider (e.g. Google, SAML) with a matching email domain
        will be auto-registered without requiring an explicit invitation.
      </AlertBanner>

      <Card className="p-6 space-y-5">
        <div className="flex items-center gap-3 pb-3" style={{ borderBottom: '0.5px solid var(--clavex-border)' }}>
          <div
            className="flex items-center justify-center w-9 h-9 rounded-lg flex-shrink-0"
            style={{ background: 'rgba(93,202,165,0.12)' }}
          >
            <UserPlus size={18} style={{ color: 'var(--clavex-accent, #5DCAA5)' }} />
          </div>
          <div>
            <p className="text-sm font-semibold">Email domains</p>
            <p className="text-xs" style={{ color: 'var(--clavex-ink-subtle)' }}>
              {form.domains.length === 0 ? 'Auto-enroll disabled — no domains configured.' : `${form.domains.length} domain(s) configured`}
            </p>
          </div>
        </div>

        <DomainTagInput
          values={form.domains}
          onChange={(v) => setForm((f) => f ? { ...f, domains: v } : f)}
        />

        <div className="space-y-1.5">
          <label className="text-sm font-medium block">Default role (optional)</label>
          <p className="text-xs" style={{ color: 'var(--clavex-ink-subtle)' }}>
            Auto-enrolled users will be assigned this role automatically.
          </p>
          <select
            className="w-full rounded-lg px-3 py-2 text-sm outline-none"
            style={{ border: '0.5px solid var(--clavex-border)', background: 'var(--clavex-surface-card, #fff)' }}
            value={form.role_id ?? ''}
            onChange={(e) => setForm((f) => f ? { ...f, role_id: e.target.value || null } : f)}
          >
            <option value="">— No role —</option>
            {roles.map((r) => (
              <option key={r.id} value={r.id}>{r.name}</option>
            ))}
          </select>
        </div>

        <div className="flex justify-end pt-2">
          <Button onClick={() => save.mutate(form)} loading={save.isPending}>
            Save auto-enroll
          </Button>
        </div>
      </Card>
    </div>
  )
}
