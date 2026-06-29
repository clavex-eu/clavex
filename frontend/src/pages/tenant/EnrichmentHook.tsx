import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import { Zap, Trash2, Eye, EyeOff } from 'lucide-react'
import { Button, Card, Input, PageHeader, Spinner, AlertBanner } from '@/components/ui'

interface EnrichmentConfig {
  url: string | null
  has_secret: boolean
}

interface FormState {
  url: string
  secret: string
}

export default function EnrichmentHookPage() {
  const orgId = useAuthStore((s) => s.orgId)
  const qc = useQueryClient()
  const [form, setForm] = useState<FormState>({ url: '', secret: '' })
  const [showSecret, setShowSecret] = useState(false)

  const { data, isLoading } = useQuery<EnrichmentConfig>({
    queryKey: ['enrichment-hook', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/enrichment-hook`).then((r) => r.data),
    enabled: !!orgId,
  })

  useEffect(() => {
    if (data) setForm({ url: data.url ?? '', secret: '' })
  }, [data])

  const save = useMutation({
    mutationFn: (body: { url: string | null; secret?: string }) =>
      api.put(`/organizations/${orgId}/enrichment-hook`, body).then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['enrichment-hook', orgId] })
      toast.success('Enrichment hook saved')
      setForm((f) => ({ ...f, secret: '' }))
    },
    onError: () => toast.error('Failed to save enrichment hook'),
  })

  const remove = useMutation({
    mutationFn: () => api.delete(`/organizations/${orgId}/enrichment-hook`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['enrichment-hook', orgId] })
      toast.success('Enrichment hook disabled')
      setForm({ url: '', secret: '' })
    },
    onError: () => toast.error('Failed to disable enrichment hook'),
  })

  if (isLoading) return <Spinner />

  function handleSave() {
    const body: { url: string | null; secret?: string } = {
      url: form.url.trim() || null,
    }
    if (form.secret !== '') body.secret = form.secret
    save.mutate(body)
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Claims Enrichment Hook"
        subtitle="Synchronously enrich ID tokens and access tokens with custom claims via a webhook."
      />

      <AlertBanner variant="info">
        During token issuance, Clavex POSTs the user context to this URL and merges the returned
        JSON claims into the token. The call is synchronous — keep your endpoint fast (&lt;500 ms).
      </AlertBanner>

      <Card className="p-6 space-y-5">
        <div className="flex items-center gap-3 pb-3" style={{ borderBottom: '0.5px solid var(--clavex-border)' }}>
          <div
            className="flex items-center justify-center w-9 h-9 rounded-lg flex-shrink-0"
            style={{ background: 'rgba(93,202,165,0.12)' }}
          >
            <Zap size={18} style={{ color: 'var(--clavex-accent, #5DCAA5)' }} />
          </div>
          <div>
            <p className="text-sm font-semibold">Webhook endpoint</p>
            <p className="text-xs" style={{ color: 'var(--clavex-ink-subtle)' }}>
              {data?.url ? 'Active' : 'Not configured'}
              {data?.has_secret && ' · bearer secret set'}
            </p>
          </div>
        </div>

        <Input
          label="Endpoint URL (HTTPS)"
          type="url"
          placeholder="https://api.yourapp.com/clavex/enrich"
          value={form.url}
          onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))}
          hint="Leave empty to disable the hook."
        />

        <div className="relative">
          <Input
            label="Bearer secret"
            type={showSecret ? 'text' : 'password'}
            placeholder={data?.has_secret ? '••••••••  (unchanged)' : 'Optional — sent as Authorization: Bearer …'}
            value={form.secret}
            onChange={(e) => setForm((f) => ({ ...f, secret: e.target.value }))}
            hint="Leave blank to keep the existing secret. Set to empty to clear it."
          />
          <button
            type="button"
            onClick={() => setShowSecret((v) => !v)}
            className="absolute right-3 top-8 text-[var(--clavex-neutral)]"
          >
            {showSecret ? <EyeOff size={15} /> : <Eye size={15} />}
          </button>
        </div>

        <div className="flex items-center justify-between pt-2">
          {data?.url ? (
            <Button
              variant="danger"
              size="sm"
              onClick={() => { if (confirm('Disable the enrichment hook?')) remove.mutate() }}
              loading={remove.isPending}
            >
              <Trash2 size={14} /> Disable hook
            </Button>
          ) : (
            <span />
          )}
          <Button onClick={handleSave} loading={save.isPending}>
            Save
          </Button>
        </div>
      </Card>

      <Card className="p-5 space-y-2">
        <p className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--clavex-ink-subtle)' }}>
          Expected response format
        </p>
        <pre
          className="text-xs rounded-lg p-4 overflow-x-auto"
          style={{ background: 'var(--clavex-surface)', color: 'var(--clavex-ink)' }}
        >{`{
  "claims": {
    "department": "engineering",
    "cost_center": "CC-42",
    "custom_role": "senior"
  }
}`}</pre>
        <p className="text-xs" style={{ color: 'var(--clavex-ink-subtle)' }}>
          Claims are merged into the token. Existing claims cannot be overwritten.
          Return HTTP 200; any other status aborts token issuance.
        </p>
      </Card>
    </div>
  )
}
