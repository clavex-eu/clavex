import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Zap, Check, Copy, ArrowLeft } from 'lucide-react'
import toast from 'react-hot-toast'
import api from '@/lib/api'

interface ProvisionResult {
  organization: { id: string; name: string; slug: string }
  admin_user: { id: string; email: string }
  temp_password: string
  rate_limits: { login_per_ip_per_min: number; token_per_client_per_min: number }
  smtp?: { host: string; from_address: string }
  oidc_client?: { client_id: string; name: string }
  client_secret?: string
}

function CopyField({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(value)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <div>
      <p className="text-xs text-gray-500 mb-0.5">{label}</p>
      <div className="flex items-center gap-2 font-mono text-sm bg-gray-50 border rounded-lg px-3 py-2">
        <span className="flex-1 truncate">{value}</span>
        <button onClick={copy} className="text-gray-400 hover:text-gray-700">
          {copied ? <Check className="h-3.5 w-3.5 text-green-500" /> : <Copy className="h-3.5 w-3.5" />}
        </button>
      </div>
    </div>
  )
}

export default function ProvisionOrgPage() {
  const [result, setResult] = useState<ProvisionResult | null>(null)
  const [form, setForm] = useState({
    name: '',
    slug: '',
    admin_email: '',
    plan: 'community',
    temp_password: '',
    // SMTP
    smtpEnabled: false,
    smtp_host: '',
    smtp_port: '587',
    smtp_from_address: '',
    smtp_from_name: '',
    smtp_password: '',
    smtp_use_tls: true,
    // OIDC Client
    clientEnabled: false,
    client_name: '',
    client_redirect_uris: '',
    client_is_public: false,
  })

  const provision = useMutation({
    mutationFn: () => {
      const body: Record<string, unknown> = {
        name: form.name,
        slug: form.slug,
        admin_email: form.admin_email,
        plan: form.plan,
        ...(form.temp_password ? { temp_password: form.temp_password } : {}),
      }
      if (form.smtpEnabled) {
        body.smtp = {
          host: form.smtp_host,
          port: parseInt(form.smtp_port),
          from_address: form.smtp_from_address,
          from_name: form.smtp_from_name,
          password: form.smtp_password,
          use_tls: form.smtp_use_tls,
        }
      }
      if (form.clientEnabled) {
        body.oidc_client = {
          name: form.client_name,
          redirect_uris: form.client_redirect_uris.split('\n').map(s => s.trim()).filter(Boolean),
          is_public: form.client_is_public,
        }
      }
      return api.post<ProvisionResult>('/organizations/provision', body).then(r => r.data)
    },
    onSuccess: (data) => { setResult(data); toast.success('Organization provisioned') },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { message?: string } } })?.response?.data?.message ?? 'Provisioning failed'
      toast.error(msg)
    },
  })

  const set = (k: string, v: unknown) => setForm(f => ({ ...f, [k]: v }))

  if (result) {
    return (
      <div className="max-w-xl">
        <div className="flex items-center gap-3 mb-6">
          <div className="h-10 w-10 rounded-xl flex items-center justify-center" style={{ background: '#dcfce7' }}>
            <Check className="h-5 w-5 text-green-700" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-gray-900">Organization provisioned</h1>
            <p className="text-sm text-gray-500">Save the credentials below — they are shown only once.</p>
          </div>
        </div>

        <div className="space-y-4 bg-amber-50 border border-amber-200 rounded-xl p-5 mb-6">
          <p className="text-xs font-bold text-amber-700 uppercase tracking-wider">⚠️ One-time secrets</p>
          <CopyField label="Admin email" value={result.admin_user.email} />
          {result.temp_password && <CopyField label="Temporary password" value={result.temp_password} />}
          {result.client_secret && <CopyField label="OIDC client secret" value={result.client_secret} />}
        </div>

        <div className="space-y-3 mb-8">
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div className="bg-white border rounded-xl p-4">
              <p className="text-xs text-gray-500 mb-0.5">Organization ID</p>
              <p className="font-mono text-xs text-gray-800 truncate">{result.organization.id}</p>
            </div>
            <div className="bg-white border rounded-xl p-4">
              <p className="text-xs text-gray-500 mb-0.5">Slug</p>
              <p className="font-semibold">{result.organization.slug}</p>
            </div>
          </div>
          {result.oidc_client && (
            <div className="bg-white border rounded-xl p-4 text-sm">
              <p className="text-xs text-gray-500 mb-0.5">OIDC Client ID</p>
              <p className="font-mono text-xs text-gray-800 truncate">{result.oidc_client.client_id}</p>
            </div>
          )}
        </div>

        <div className="flex gap-3">
          <Link
            to={`/admin/orgs/${result.organization.id}`}
            className="px-4 py-2 rounded-lg text-sm font-medium text-white"
            style={{ background: 'var(--clavex-primary)' }}
          >
            Open organization →
          </Link>
          <button
            onClick={() => { setResult(null); setForm(f => ({ ...f, name: '', slug: '', admin_email: '', temp_password: '' })) }}
            className="px-4 py-2 rounded-lg text-sm font-medium border text-gray-600"
          >
            Provision another
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="max-w-2xl">
      <div className="flex items-center gap-2 mb-1">
        <Link to="/admin/orgs" className="text-gray-400 hover:text-gray-600">
          <ArrowLeft className="h-4 w-4" />
        </Link>
        <h1 className="text-xl font-semibold text-gray-900">Provision organization</h1>
      </div>
      <p className="text-sm text-gray-500 mb-8 ml-6">
        Atomic bootstrap: creates org + admin user + rate limits in one call.
      </p>

      <div className="space-y-6">
        {/* Core */}
        <section className="bg-white border rounded-xl p-5">
          <p className="text-xs font-semibold uppercase tracking-wider text-gray-500 mb-4">Organization</p>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Name *</label>
              <input className="w-full border rounded-lg px-3 py-2 text-sm" value={form.name}
                onChange={e => set('name', e.target.value)} placeholder="Acme Corp" />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Slug *</label>
              <input className="w-full border rounded-lg px-3 py-2 text-sm font-mono" value={form.slug}
                onChange={e => set('slug', e.target.value.toLowerCase().replace(/[^a-z0-9]/g, ''))}
                placeholder="acme" />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Admin email *</label>
              <input className="w-full border rounded-lg px-3 py-2 text-sm" type="email" value={form.admin_email}
                onChange={e => set('admin_email', e.target.value)} placeholder="admin@acme.com" />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Plan *</label>
              <select className="w-full border rounded-lg px-3 py-2 text-sm bg-white" value={form.plan}
                onChange={e => set('plan', e.target.value)}>
                <option value="community">Community (BSL)</option>
                <option value="enterprise">Enterprise</option>
                <option value="cloud">Cloud SaaS</option>
              </select>
            </div>
            <div className="col-span-2">
              <label className="block text-xs font-medium text-gray-600 mb-1">Temporary password <span className="text-gray-400">(generated if blank)</span></label>
              <input className="w-full border rounded-lg px-3 py-2 text-sm font-mono" type="text"
                value={form.temp_password} onChange={e => set('temp_password', e.target.value)}
                placeholder="auto-generated" />
            </div>
          </div>
        </section>

        {/* SMTP */}
        <section className="bg-white border rounded-xl p-5">
          <label className="flex items-center gap-2 cursor-pointer mb-4">
            <input type="checkbox" checked={form.smtpEnabled} onChange={e => set('smtpEnabled', e.target.checked)} />
            <p className="text-xs font-semibold uppercase tracking-wider text-gray-500">SMTP settings <span className="normal-case text-gray-400">(optional)</span></p>
          </label>
          {form.smtpEnabled && (
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Host</label>
                <input className="w-full border rounded-lg px-3 py-2 text-sm" value={form.smtp_host}
                  onChange={e => set('smtp_host', e.target.value)} placeholder="smtp.example.com" />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Port</label>
                <input className="w-full border rounded-lg px-3 py-2 text-sm" type="number" value={form.smtp_port}
                  onChange={e => set('smtp_port', e.target.value)} />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">From address</label>
                <input className="w-full border rounded-lg px-3 py-2 text-sm" type="email" value={form.smtp_from_address}
                  onChange={e => set('smtp_from_address', e.target.value)} placeholder="noreply@acme.com" />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">From name</label>
                <input className="w-full border rounded-lg px-3 py-2 text-sm" value={form.smtp_from_name}
                  onChange={e => set('smtp_from_name', e.target.value)} placeholder="Acme" />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Password</label>
                <input className="w-full border rounded-lg px-3 py-2 text-sm" type="password" value={form.smtp_password}
                  onChange={e => set('smtp_password', e.target.value)} />
              </div>
              <div className="flex items-end pb-2">
                <label className="flex items-center gap-2 text-sm cursor-pointer">
                  <input type="checkbox" checked={form.smtp_use_tls} onChange={e => set('smtp_use_tls', e.target.checked)} />
                  Use TLS
                </label>
              </div>
            </div>
          )}
        </section>

        {/* OIDC Client */}
        <section className="bg-white border rounded-xl p-5">
          <label className="flex items-center gap-2 cursor-pointer mb-4">
            <input type="checkbox" checked={form.clientEnabled} onChange={e => set('clientEnabled', e.target.checked)} />
            <p className="text-xs font-semibold uppercase tracking-wider text-gray-500">First OIDC client <span className="normal-case text-gray-400">(optional)</span></p>
          </label>
          {form.clientEnabled && (
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Client name</label>
                <input className="w-full border rounded-lg px-3 py-2 text-sm" value={form.client_name}
                  onChange={e => set('client_name', e.target.value)} placeholder="My App" />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Redirect URIs (one per line)</label>
                <textarea className="w-full border rounded-lg px-3 py-2 text-sm font-mono" rows={3}
                  value={form.client_redirect_uris}
                  onChange={e => set('client_redirect_uris', e.target.value)}
                  placeholder="https://app.acme.com/callback" />
              </div>
              <label className="flex items-center gap-2 text-sm cursor-pointer">
                <input type="checkbox" checked={form.client_is_public} onChange={e => set('client_is_public', e.target.checked)} />
                Public client (no client secret)
              </label>
            </div>
          )}
        </section>

        <button
          disabled={!form.name || !form.slug || !form.admin_email || provision.isPending}
          onClick={() => provision.mutate()}
          className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold text-white disabled:opacity-50"
          style={{ background: 'var(--clavex-primary)' }}
        >
          <Zap className="h-4 w-4" />
          {provision.isPending ? 'Provisioning…' : 'Provision organization'}
        </button>
      </div>
    </div>
  )
}
