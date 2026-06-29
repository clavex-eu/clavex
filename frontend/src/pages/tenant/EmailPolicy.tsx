import { useEffect, useState, KeyboardEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import { Mail, X } from 'lucide-react'
import { Button, Card, PageHeader, Spinner } from '@/components/ui'

interface EmailPolicy {
  email_blocklist: string[]
  email_allowlist: string[]
}

function TagInput({
  label,
  hint,
  values,
  onChange,
  placeholder,
}: {
  label: string
  hint?: string
  values: string[]
  onChange: (v: string[]) => void
  placeholder?: string
}) {
  const [draft, setDraft] = useState('')

  function commit() {
    const trimmed = draft.trim().toLowerCase()
    if (!trimmed || values.includes(trimmed)) { setDraft(''); return }
    onChange([...values, trimmed])
    setDraft('')
  }

  function onKey(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); commit() }
    if (e.key === 'Backspace' && draft === '' && values.length > 0) {
      onChange(values.slice(0, -1))
    }
  }

  return (
    <div className="space-y-2">
      <p className="text-sm font-medium">{label}</p>
      {hint && <p className="text-xs" style={{ color: 'var(--clavex-ink-subtle)' }}>{hint}</p>}
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
            <button
              type="button"
              onClick={() => onChange(values.filter((x) => x !== v))}
              className="opacity-60 hover:opacity-100"
            >
              <X size={10} />
            </button>
          </span>
        ))}
        <input
          className="flex-1 min-w-24 outline-none text-sm bg-transparent"
          placeholder={values.length === 0 ? (placeholder ?? 'Type and press Enter') : ''}
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={onKey}
          onBlur={commit}
        />
      </div>
    </div>
  )
}

export default function EmailPolicyPage() {
  const orgId = useAuthStore((s) => s.orgId)
  const qc = useQueryClient()
  const [form, setForm] = useState<EmailPolicy | null>(null)

  const { data, isLoading } = useQuery<EmailPolicy>({
    queryKey: ['email-policy', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/email-policy`).then((r) => r.data),
    enabled: !!orgId,
  })

  useEffect(() => {
    if (data && !form) setForm(data)
  }, [data])

  const save = useMutation({
    mutationFn: (body: EmailPolicy) =>
      api.put(`/organizations/${orgId}/email-policy`, body).then((r) => r.data),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['email-policy', orgId] })
      setForm(res)
      toast.success('Email policy saved')
    },
    onError: () => toast.error('Failed to save email policy'),
  })

  if (isLoading || !form) return <Spinner />

  return (
    <div className="space-y-6">
      <PageHeader
        title="Email Domain Policy"
        subtitle="Control which email domains are allowed or blocked during self-registration."
      />

      <Card className="p-6 space-y-6">
        <div className="flex items-center gap-3 pb-3" style={{ borderBottom: '0.5px solid var(--clavex-border)' }}>
          <div
            className="flex items-center justify-center w-9 h-9 rounded-lg flex-shrink-0"
            style={{ background: 'rgba(93,202,165,0.12)' }}
          >
            <Mail size={18} style={{ color: 'var(--clavex-accent, #5DCAA5)' }} />
          </div>
          <div>
            <p className="text-sm font-semibold">Domain rules</p>
            <p className="text-xs" style={{ color: 'var(--clavex-ink-subtle)' }}>
              Allowlist takes precedence over blocklist. Wildcards supported (e.g. <code>*.corp.com</code>).
            </p>
          </div>
        </div>

        <TagInput
          label="Allowlist — only these domains may register"
          hint="Leave empty to allow all domains (subject to blocklist)."
          values={form.email_allowlist}
          onChange={(v) => setForm((f) => f ? { ...f, email_allowlist: v } : f)}
          placeholder="acme.com, partner.com …"
        />

        <TagInput
          label="Blocklist — these domains are always rejected"
          hint="Public mailbox domains (gmail.com, outlook.com) or competitors."
          values={form.email_blocklist}
          onChange={(v) => setForm((f) => f ? { ...f, email_blocklist: v } : f)}
          placeholder="gmail.com, yahoo.com …"
        />

        <div className="flex justify-end pt-2">
          <Button onClick={() => save.mutate(form)} loading={save.isPending}>
            Save policy
          </Button>
        </div>
      </Card>
    </div>
  )
}
