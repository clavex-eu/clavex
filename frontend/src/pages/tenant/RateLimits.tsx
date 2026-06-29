import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import { Gauge, Plus, Trash2 } from 'lucide-react'
import { Button, Card, Input, PageHeader, Spinner } from '@/components/ui'

interface RateLimits {
  login_per_ip_per_min: number
  token_per_client_per_min: number
  global_per_ip_per_min: number
  endpoint_limits: Record<string, number> | null
}

export default function RateLimitsPage() {
  const orgId = useAuthStore((s) => s.orgId)
  const qc = useQueryClient()
  const [form, setForm] = useState<RateLimits | null>(null)
  const [newPath, setNewPath] = useState('')
  const [newLimit, setNewLimit] = useState('')

  const { data, isLoading } = useQuery<RateLimits>({
    queryKey: ['rate-limits', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/rate-limits`).then((r) => r.data),
    enabled: !!orgId,
  })

  useEffect(() => {
    if (data && !form) setForm({ ...data, endpoint_limits: data.endpoint_limits ?? {} })
  }, [data])

  const save = useMutation({
    mutationFn: (body: RateLimits) =>
      api.put(`/organizations/${orgId}/rate-limits`, body).then((r) => r.data),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['rate-limits', orgId] })
      setForm({ ...res, endpoint_limits: res.endpoint_limits ?? {} })
      toast.success('Rate limits saved')
    },
    onError: () => toast.error('Failed to save rate limits'),
  })

  if (isLoading || !form) return <Spinner />

  const set = <K extends keyof RateLimits>(key: K, val: RateLimits[K]) =>
    setForm((prev) => (prev ? { ...prev, [key]: val } : prev))

  function addEndpointLimit() {
    const path = newPath.trim()
    const limit = parseInt(newLimit)
    if (!path || isNaN(limit) || limit < 1) {
      toast.error('Provide a valid path and limit')
      return
    }
    setForm((prev) =>
      prev
        ? { ...prev, endpoint_limits: { ...(prev.endpoint_limits ?? {}), [path]: limit } }
        : prev,
    )
    setNewPath('')
    setNewLimit('')
  }

  function removeEndpointLimit(path: string) {
    setForm((prev) => {
      if (!prev) return prev
      const { [path]: _, ...rest } = prev.endpoint_limits ?? {}
      return { ...prev, endpoint_limits: rest }
    })
  }

  const endpointEntries = Object.entries(form.endpoint_limits ?? {})

  return (
    <div className="space-y-6">
      <PageHeader
        title="Rate Limits"
        subtitle="Control request throttling for login, token, and custom endpoints."
      />

      <Card className="p-6 space-y-5">
        <div className="flex items-center gap-3 pb-3" style={{ borderBottom: '0.5px solid var(--clavex-border)' }}>
          <div
            className="flex items-center justify-center w-9 h-9 rounded-lg flex-shrink-0"
            style={{ background: 'rgba(93,202,165,0.12)' }}
          >
            <Gauge size={18} style={{ color: 'var(--clavex-accent, #5DCAA5)' }} />
          </div>
          <p className="text-sm font-semibold">Global limits</p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <Input
            label="Login / IP / minute"
            type="number"
            min={1}
            max={600}
            value={form.login_per_ip_per_min}
            onChange={(e) => set('login_per_ip_per_min', Math.max(1, parseInt(e.target.value) || 1))}
            hint="Password-submit attempts per source IP"
          />
          <Input
            label="Token / client / minute"
            type="number"
            min={1}
            max={3600}
            value={form.token_per_client_per_min}
            onChange={(e) => set('token_per_client_per_min', Math.max(1, parseInt(e.target.value) || 1))}
            hint="Token endpoint per OIDC client"
          />
          <Input
            label="Global / IP / minute"
            type="number"
            min={1}
            max={3600}
            value={form.global_per_ip_per_min}
            onChange={(e) => set('global_per_ip_per_min', Math.max(1, parseInt(e.target.value) || 1))}
            hint="All requests from one IP"
          />
        </div>
      </Card>

      <Card className="p-6 space-y-4">
        <p className="text-sm font-semibold">Per-endpoint overrides</p>
        <p className="text-xs" style={{ color: 'var(--clavex-ink-subtle)' }}>
          Override the rate for a specific path (e.g. <code>/elevate</code>, <code>/oid4vci/offers</code>).
          Path keys are matched as suffixes of the request URL.
        </p>

        {endpointEntries.length > 0 && (
          <div className="rounded-lg overflow-hidden" style={{ border: '0.5px solid var(--clavex-border)' }}>
            <table className="w-full text-sm">
              <thead>
                <tr style={{ background: 'var(--clavex-surface)' }}>
                  <th className="text-left px-4 py-2 text-xs font-semibold">Path</th>
                  <th className="text-left px-4 py-2 text-xs font-semibold">req / min</th>
                  <th className="px-4 py-2" />
                </tr>
              </thead>
              <tbody>
                {endpointEntries.map(([path, limit]) => (
                  <tr key={path} style={{ borderTop: '0.5px solid var(--clavex-border)' }}>
                    <td className="px-4 py-2 font-mono text-xs">{path}</td>
                    <td className="px-4 py-2 text-xs">{limit}</td>
                    <td className="px-4 py-2 text-right">
                      <button
                        onClick={() => removeEndpointLimit(path)}
                        className="text-red-400 hover:text-red-600"
                      >
                        <Trash2 size={14} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="flex gap-2 items-end">
          <Input
            label="Path suffix"
            placeholder="/elevate"
            value={newPath}
            onChange={(e) => setNewPath(e.target.value)}
          />
          <Input
            label="req / min"
            type="number"
            min={1}
            placeholder="10"
            value={newLimit}
            onChange={(e) => setNewLimit(e.target.value)}
          />
          <Button variant="secondary" size="sm" onClick={addEndpointLimit} className="mb-0.5">
            <Plus size={14} /> Add
          </Button>
        </div>
      </Card>

      <div className="flex justify-end">
        <Button onClick={() => save.mutate(form)} loading={save.isPending}>
          Save rate limits
        </Button>
      </div>
    </div>
  )
}
