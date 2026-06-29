import { useState, useEffect } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { ShieldCheck } from 'lucide-react'
import toast from 'react-hot-toast'
import api from '@/lib/api'
import { Button, Input, Select, PageHeader, Spinner } from '@/components/ui'

interface CaptchaConfig {
  configured: boolean
  provider?: string
  site_key?: string
  is_active?: boolean
}

interface Props {
  orgId: string
  breadcrumb?: React.ReactNode
}

const PROVIDERS = [
  { value: 'turnstile', label: 'Cloudflare Turnstile (recommended)' },
  { value: 'hcaptcha',  label: 'hCaptcha' },
  { value: 'recaptcha', label: 'Google reCAPTCHA v2' },
]

export default function CaptchaPage({ orgId, breadcrumb }: Props) {
  const [provider, setProvider] = useState('turnstile')
  const [siteKey, setSiteKey]   = useState('')
  const [secretKey, setSecretKey] = useState('')
  const [isActive, setIsActive]  = useState(true)
  const [dirty, setDirty]        = useState(false)

  const { data, isLoading } = useQuery<CaptchaConfig>({
    queryKey: ['captcha', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/captcha`).then((r) => r.data),
  })

  useEffect(() => {
    if (data?.configured) {
      setProvider(data.provider ?? 'turnstile')
      setSiteKey(data.site_key ?? '')
      setIsActive(data.is_active ?? true)
      setDirty(false)
    }
  }, [data])

  const save = useMutation({
    mutationFn: () =>
      api.put(`/organizations/${orgId}/captcha`, {
        provider,
        site_key: siteKey,
        secret_key: secretKey,
        is_active: isActive,
      }),
    onSuccess: () => {
      toast.success('CAPTCHA settings saved')
      setSecretKey('')
      setDirty(false)
    },
    onError: () => toast.error('Failed to save CAPTCHA settings'),
  })

  const remove = useMutation({
    mutationFn: () => api.delete(`/organizations/${orgId}/captcha`),
    onSuccess: () => {
      toast.success('CAPTCHA disabled')
      setSiteKey('')
      setSecretKey('')
      setDirty(false)
    },
    onError: () => toast.error('Failed to remove CAPTCHA'),
  })

  if (isLoading) return <Spinner />

  const canSave = siteKey.trim() !== '' && secretKey.trim() !== ''

  return (
    <div>
      {breadcrumb}
      <PageHeader
        title="CAPTCHA Settings"
        subtitle="Require users to complete a challenge before logging in"
        action={
          <div className="flex gap-2">
            {data?.configured && (
              <Button
                variant="danger"
                loading={remove.isPending}
                onClick={() => { if (confirm('Remove CAPTCHA protection?')) remove.mutate() }}
              >
                Remove
              </Button>
            )}
            <Button loading={save.isPending} disabled={!canSave && !dirty} onClick={() => save.mutate()}>
              Save
            </Button>
          </div>
        }
      />

      <div style={{
        background: 'white',
        border: '0.5px solid var(--clavex-border)',
        borderRadius: 'var(--clavex-radius-lg)',
        padding: 28,
        maxWidth: 520,
      }}>
        {/* Status badge */}
        {data?.configured && (
          <div style={{
            display: 'inline-flex', alignItems: 'center', gap: 6,
            background: isActive ? 'rgba(29,158,117,0.08)' : 'var(--clavex-surface)',
            border: `0.5px solid ${isActive ? 'rgba(29,158,117,0.3)' : 'var(--clavex-border)'}`,
            borderRadius: 20, padding: '4px 12px', marginBottom: 20,
          }}>
            <ShieldCheck className="h-3.5 w-3.5" style={{ color: isActive ? 'var(--clavex-primary)' : 'var(--clavex-neutral)' }} />
            <span style={{ fontSize: 12, fontWeight: 600, color: isActive ? 'var(--clavex-primary)' : 'var(--clavex-neutral)' }}>
              {isActive ? 'Active' : 'Disabled'}
            </span>
          </div>
        )}

        <div className="space-y-5">
          <Select
            label="Provider"
            value={provider}
            onChange={(e) => { setProvider(e.target.value); setDirty(true) }}
          >
            {PROVIDERS.map((p) => (
              <option key={p.value} value={p.value}>{p.label}</option>
            ))}
          </Select>

          <Input
            label="Site key (public)"
            value={siteKey}
            onChange={(e) => { setSiteKey(e.target.value); setDirty(true) }}
            placeholder="Paste your site key here"
          />

          <Input
            label="Secret key"
            type="password"
            value={secretKey}
            onChange={(e) => { setSecretKey(e.target.value); setDirty(true) }}
            placeholder={data?.configured ? '••••••••  (leave blank to keep existing)' : 'Paste your secret key here'}
            hint="Stored securely; never exposed via the API"
          />

          <label style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={isActive}
              onChange={(e) => { setIsActive(e.target.checked); setDirty(true) }}
              style={{ accentColor: 'var(--clavex-primary)', width: 16, height: 16 }}
            />
            <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--clavex-ink)' }}>
              Enable on login page
            </span>
          </label>
        </div>

        {provider === 'turnstile' && !data?.configured && (
          <p style={{ marginTop: 20, fontSize: 12, color: 'var(--clavex-neutral)', lineHeight: 1.6 }}>
            Get your free Turnstile keys at{' '}
            <a
              href="https://dash.cloudflare.com/?to=/:account/turnstile"
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: 'var(--clavex-primary)' }}
            >
              dash.cloudflare.com
            </a>. No account tracking; privacy-friendly.
          </p>
        )}
      </div>
    </div>
  )
}
