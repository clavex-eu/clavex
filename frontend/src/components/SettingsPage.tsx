import { useState, useEffect } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import api from '@/lib/api'
import { Button, Input, Card, PageHeader, Spinner, ManagedBadge } from '@/components/ui'

// ── Types ──────────────────────────────────────────────────────────────────────

interface PasswordPolicy {
  org_id: string
  min_length: number
  require_uppercase: boolean
  require_number: boolean
  require_symbol: boolean
  max_age_days: number | null
  prevent_reuse_count: number
  breached_password_action: string
  managed_by?: string | null
  managed_ref?: string | null
}

interface SMTPSettings {
  org_id: string
  host: string
  port: number
  username: string
  from_address: string
  from_name: string
  use_tls: boolean
  is_active: boolean
}

interface Props {
  orgId: string
}

// ── Sub-tabs ───────────────────────────────────────────────────────────────────

function PasswordPolicyTab({ orgId }: { orgId: string }) {
  const [form, setForm] = useState<PasswordPolicy | null>(null)

  const { data, isLoading } = useQuery<PasswordPolicy>({
    queryKey: ['password-policy', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/password-policy`).then((r) => r.data),
  })

  useEffect(() => {
    if (data && !form) setForm(data)
  }, [data])

  const save = useMutation({
    mutationFn: (body: PasswordPolicy) =>
      api.put(`/organizations/${orgId}/password-policy`, body),
    onSuccess: (res) => {
      setForm(res.data)
      toast.success('Password policy saved')
    },
    onError: () => toast.error('Failed to save password policy'),
  })

  if (isLoading || !form) return <Spinner />

  const set = <K extends keyof PasswordPolicy>(key: K, val: PasswordPolicy[K]) =>
    setForm((prev) => prev ? { ...prev, [key]: val } : prev)

  return (
    <Card className="p-6 space-y-6">
      {data?.managed_by && (
        <div className="flex items-center">
          <ManagedBadge managedBy={data.managed_by} managedRef={data.managed_ref} />
        </div>
      )}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Minimum length
          </label>
          <input
            type="number"
            min={4}
            max={128}
            value={form.min_length}
            onChange={(e) => set('min_length', parseInt(e.target.value) || 8)}
            className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--clavex-primary)]"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Max password age (days, 0 = no expiry)
          </label>
          <input
            type="number"
            min={0}
            value={form.max_age_days ?? 0}
            onChange={(e) => {
              const v = parseInt(e.target.value) || 0
              set('max_age_days', v > 0 ? v : null)
            }}
            className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--clavex-primary)]"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Prevent reuse (last N passwords, 0 = disabled)
          </label>
          <input
            type="number"
            min={0}
            max={24}
            value={form.prevent_reuse_count}
            onChange={(e) => set('prevent_reuse_count', parseInt(e.target.value) || 0)}
            className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[var(--clavex-primary)]"
          />
        </div>
      </div>

      <div className="space-y-3">
        <p className="text-sm font-medium text-gray-700">Character requirements</p>
        {(
          [
            ['require_uppercase', 'Require uppercase letter (A–Z)'],
            ['require_number',    'Require digit (0–9)'],
            ['require_symbol',    'Require symbol (!@#$…)'],
          ] as [keyof PasswordPolicy, string][]
        ).map(([field, label]) => (
          <label key={field} className="flex items-center gap-3 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={!!form[field]}
              onChange={(e) => set(field, e.target.checked as PasswordPolicy[typeof field])}
              className="h-4 w-4 rounded border-gray-300 text-[var(--clavex-primary)] focus:ring-[var(--clavex-primary)]"
            />
            <span className="text-sm text-gray-700">{label}</span>
          </label>
        ))}
      </div>

      <div className="space-y-3">
        <p className="text-sm font-medium text-gray-700">Breached password check (HIBP)</p>
        <p className="text-xs text-gray-500">
          Checks passwords against the Have I Been Pwned database using k-anonymity.
          The full password is never sent.
        </p>
        {([
          ['off',         'Disabled'],
          ['warn',        'Warn user but allow sign in'],
          ['block',       'Block sign in with breached password'],
          ['force_reset', 'Force password reset before sign in'],
        ] as [string, string][]).map(([val, label]) => (
          <label key={val} className="flex items-center gap-3 cursor-pointer select-none">
            <input
              type="radio"
              name="breached_password_action"
              value={val}
              checked={form.breached_password_action === val}
              onChange={() => set('breached_password_action', val)}
              className="h-4 w-4 border-gray-300 text-[var(--clavex-primary)] focus:ring-[var(--clavex-primary)]"
            />
            <span className="text-sm text-gray-700">{label}</span>
          </label>
        ))}
      </div>

      <div className="flex justify-end">
        <Button onClick={() => save.mutate(form!)} disabled={save.isPending}>
          {save.isPending ? 'Saving…' : 'Save policy'}
        </Button>
      </div>
    </Card>
  )
}

function SMTPTab({ orgId }: { orgId: string }) {
  const [form, setForm] = useState<SMTPSettings & { password?: string } | null>(null)
  const [testEmail, setTestEmail] = useState('')
  const [testPending, setTestPending] = useState(false)

  const { data, isLoading } = useQuery<SMTPSettings>({
    queryKey: ['smtp', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/smtp`).then((r) => r.data),
  })

  useEffect(() => {
    if (data && !form) setForm(data)
  }, [data])

  const save = useMutation({
    mutationFn: (body: SMTPSettings & { password?: string }) =>
      api.put(`/organizations/${orgId}/smtp`, body),
    onSuccess: (res) => {
      setForm({ ...res.data, password: '' })
      toast.success('SMTP settings saved')
    },
    onError: () => toast.error('Failed to save SMTP settings'),
  })

  const sendTest = async () => {
    if (!testEmail) { toast.error('Enter an email address for the test'); return }
    setTestPending(true)
    try {
      await api.post(`/organizations/${orgId}/smtp/test`, { to: testEmail })
      toast.success(`Test email sent to ${testEmail}`)
    } catch {
      toast.error('Failed to send test email — check your SMTP settings')
    } finally {
      setTestPending(false)
    }
  }

  if (isLoading || !form) return <Spinner />

  const set = <K extends keyof typeof form>(key: K, val: (typeof form)[K]) =>
    setForm((prev) => prev ? { ...prev, [key]: val } : prev)

  return (
    <Card className="p-6 space-y-6">
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <Input
          label="SMTP host"
          value={form.host}
          onChange={(e) => set('host', e.target.value)}
          placeholder="smtp.example.com"
        />
        <Input
          label="Port"
          type="number"
          value={String(form.port)}
          onChange={(e) => set('port', parseInt(e.target.value) || 587)}
        />
        <Input
          label="Username"
          value={form.username}
          onChange={(e) => set('username', e.target.value)}
          autoComplete="off"
        />
        <Input
          label="Password (leave blank to keep existing)"
          type="password"
          value={form.password ?? ''}
          onChange={(e) => set('password', e.target.value)}
          autoComplete="new-password"
        />
        <Input
          label="From address"
          type="email"
          value={form.from_address}
          onChange={(e) => set('from_address', e.target.value)}
          placeholder="noreply@example.com"
        />
        <Input
          label="From name"
          value={form.from_name}
          onChange={(e) => set('from_name', e.target.value)}
          placeholder="Clavex IAM"
        />
      </div>

      <label className="flex items-center gap-3 cursor-pointer select-none">
        <input
          type="checkbox"
          checked={form.use_tls}
          onChange={(e) => set('use_tls', e.target.checked)}
          className="h-4 w-4 rounded border-gray-300 text-[var(--clavex-primary)] focus:ring-[var(--clavex-primary)]"
        />
        <span className="text-sm text-gray-700">Use TLS (STARTTLS / SMTPS)</span>
      </label>

      <label className="flex items-center gap-3 cursor-pointer select-none">
        <input
          type="checkbox"
          checked={form.is_active}
          onChange={(e) => set('is_active', e.target.checked)}
          className="h-4 w-4 rounded border-gray-300 text-[var(--clavex-primary)] focus:ring-[var(--clavex-primary)]"
        />
        <span className="text-sm text-gray-700">Enable outbound email for this organization</span>
      </label>

      <div className="flex items-center gap-3 pt-2 border-t border-gray-100">
        <div className="flex-1">
          <Input
            label="Send a test email to"
            type="email"
            value={testEmail}
            onChange={(e) => setTestEmail(e.target.value)}
            placeholder="you@example.com"
          />
        </div>
        <div className="pt-5">
          <Button variant="secondary" onClick={sendTest} disabled={testPending}>
            {testPending ? 'Sending…' : 'Send test'}
          </Button>
        </div>
      </div>

      <div className="flex justify-end">
        <Button onClick={() => save.mutate(form!)} disabled={save.isPending}>
          {save.isPending ? 'Saving…' : 'Save settings'}
        </Button>
      </div>
    </Card>
  )
}

// ── Main export ────────────────────────────────────────────────────────────────

type Tab = 'password-policy' | 'smtp'

export default function SettingsPage({ orgId }: Props) {
  const [tab, setTab] = useState<Tab>('password-policy')

  const tabs: { id: Tab; label: string }[] = [
    { id: 'password-policy', label: 'Password Policy' },
    { id: 'smtp',            label: 'Email / SMTP'    },
  ]

  return (
    <div>
      <PageHeader title="Organization Settings" />

      {/* Tab bar */}
      <div className="flex gap-1 mb-6 border-b border-gray-200">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${
              tab === t.id
                ? 'border-[var(--clavex-primary)] text-[var(--clavex-primary)]'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'password-policy' && <PasswordPolicyTab orgId={orgId} />}
      {tab === 'smtp'            && <SMTPTab orgId={orgId} />}
    </div>
  )
}
