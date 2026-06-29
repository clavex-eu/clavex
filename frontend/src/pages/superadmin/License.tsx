import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ShieldCheck, Copy, Check, AlertTriangle, Clock, Building2, Key } from 'lucide-react'
import toast from 'react-hot-toast'
import api from '@/lib/api'
import {
  Badge, Button, Card, PageHeader, Spinner, Textarea,
} from '@/components/ui'

// ── Types ─────────────────────────────────────────────────────────────────────

interface LicenseState {
  valid: boolean
  tier: string
  org_limit: number
  current_org_count: number
  exceeds_limit: boolean
  grace_period_expired: boolean
  warning_message: string
  auth_blocked: boolean
  license_expires_at: string | null
  license_expiring_soon: boolean
  installation_mismatch: boolean
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function CopyText({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(value)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 8,
      background: 'white', border: '0.5px solid var(--clavex-border)',
      borderRadius: 'var(--clavex-radius-md)', padding: '8px 12px',
    }}>
      <span style={{ flex: 1, fontFamily: 'monospace', fontSize: 13, color: 'var(--clavex-ink)', wordBreak: 'break-all' }}>
        {value}
      </span>
      <button onClick={copy} title="Copy" style={{
        background: 'none', border: 'none', cursor: 'pointer',
        color: copied ? '#0F6E56' : 'var(--clavex-neutral)', padding: 4, flexShrink: 0,
      }}>
        {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
      </button>
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function LicensePage() {
  const qc = useQueryClient()
  const [token, setToken] = useState('')

  const licenseQ = useQuery<LicenseState>({
    queryKey: ['superadmin-license'],
    queryFn: () => api.get('/superadmin/license').then(r => r.data),
  })

  const installationQ = useQuery<{ installation_id: string }>({
    queryKey: ['superadmin-installation-id'],
    queryFn: () => api.get('/superadmin/license/installation-id').then(r => r.data),
  })

  const uploadM = useMutation({
    mutationFn: (tok: string) => api.put('/superadmin/license', { token: tok }),
    onSuccess: () => {
      toast.success('License activated successfully')
      qc.invalidateQueries({ queryKey: ['superadmin-license'] })
      setToken('')
    },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { error?: string } } })
        ?.response?.data?.error ?? 'Failed to activate license'
      toast.error(msg)
    },
  })

  const lic = licenseQ.data
  const installId = installationQ.data?.installation_id

  const tierBadge = () => {
    if (!lic) return null
    const variants: Record<string, 'gray' | 'blue' | 'green' | 'purple'> = {
      community: 'gray',
      starter: 'blue',
      growth: 'blue',
      enterprise: 'purple',
    }
    const tier = lic.tier ?? ''
    return (
      <Badge variant={variants[tier] ?? 'gray'}>
        {tier ? tier.charAt(0).toUpperCase() + tier.slice(1) : '—'}
      </Badge>
    )
  }

  const expiresLabel = () => {
    if (!lic?.license_expires_at) return '—'
    return new Date(lic.license_expires_at).toLocaleDateString('en-GB', {
      day: 'numeric', month: 'short', year: 'numeric',
    })
  }

  if (licenseQ.isLoading) return <Spinner />

  return (
    <div>
      <PageHeader title="License" subtitle="Manage your Clavex license and activation" />

      {/* Warning banners */}
      {lic?.auth_blocked && (
        <div style={{
          display: 'flex', alignItems: 'flex-start', gap: 12,
          background: '#FCEBEB', border: '0.5px solid #E9B5B5',
          borderRadius: 'var(--clavex-radius-md)', padding: '12px 16px', marginBottom: 12,
        }}>
          <AlertTriangle style={{ width: 15, height: 15, color: '#A32D2D', marginTop: 1, flexShrink: 0 }} />
          <div>
            <p style={{ fontWeight: 700, fontSize: 13, color: '#A32D2D' }}>
              Authentication blocked — license grace period expired
            </p>
            <p style={{ fontSize: 12, color: '#5F5E5A', marginTop: 2 }}>{lic.warning_message}</p>
          </div>
        </div>
      )}
      {lic?.installation_mismatch && (
        <div style={{
          display: 'flex', alignItems: 'flex-start', gap: 12,
          background: '#FCEBEB', border: '0.5px solid #E9B5B5',
          borderRadius: 'var(--clavex-radius-md)', padding: '12px 16px', marginBottom: 12,
        }}>
          <AlertTriangle style={{ width: 15, height: 15, color: '#A32D2D', marginTop: 1, flexShrink: 0 }} />
          <div>
            <p style={{ fontWeight: 700, fontSize: 13, color: '#A32D2D' }}>
              License bound to a different installation — reverted to community tier
            </p>
            <p style={{ fontSize: 12, color: '#5F5E5A', marginTop: 2 }}>
              {lic.warning_message || 'The license is bound to a different installation. Re-issue it for the Installation ID shown below.'}
            </p>
          </div>
        </div>
      )}
      {lic?.exceeds_limit && !lic.auth_blocked && (
        <div style={{
          display: 'flex', alignItems: 'flex-start', gap: 12,
          background: '#FAEEDA', border: '0.5px solid #E8C97C',
          borderRadius: 'var(--clavex-radius-md)', padding: '12px 16px', marginBottom: 12,
        }}>
          <AlertTriangle style={{ width: 15, height: 15, color: '#854F0B', marginTop: 1, flexShrink: 0 }} />
          <div>
            <p style={{ fontWeight: 700, fontSize: 13, color: '#854F0B' }}>
              License org limit exceeded — grace period active
            </p>
            <p style={{ fontSize: 12, color: '#5F5E5A', marginTop: 2 }}>{lic.warning_message}</p>
          </div>
        </div>
      )}
      {lic?.license_expiring_soon && !lic.exceeds_limit && (
        <div style={{
          display: 'flex', alignItems: 'flex-start', gap: 12,
          background: '#FAEEDA', border: '0.5px solid #E8C97C',
          borderRadius: 'var(--clavex-radius-md)', padding: '12px 16px', marginBottom: 12,
        }}>
          <Clock style={{ width: 15, height: 15, color: '#854F0B', marginTop: 1, flexShrink: 0 }} />
          <div>
            <p style={{ fontWeight: 700, fontSize: 13, color: '#854F0B' }}>License expiring soon</p>
            <p style={{ fontSize: 12, color: '#5F5E5A', marginTop: 2 }}>
              Expires {expiresLabel()}.{' '}
              <a href="mailto:support@clavex.eu" style={{ color: '#854F0B' }}>Contact support</a> to renew.
            </p>
          </div>
        </div>
      )}

      {/* License info card */}
      {lic && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap',
          background: 'white', border: '0.5px solid var(--clavex-border)',
          borderRadius: 'var(--clavex-radius-lg)', padding: '16px 20px', marginBottom: 16,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              width: 32, height: 32, borderRadius: 8, flexShrink: 0,
              background: 'var(--clavex-50)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <ShieldCheck style={{ width: 16, height: 16, color: 'var(--clavex-700)' }} />
            </div>
            <div>
              <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--clavex-neutral)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Plan</p>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                {tierBadge()}
                {lic.valid
                  ? <Badge variant="green">Active</Badge>
                  : <Badge variant="gray">Community</Badge>}
              </div>
            </div>
          </div>

          <div style={{ width: 1, height: 32, background: 'var(--clavex-surface)', flexShrink: 0 }} />

          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Building2 style={{ width: 15, height: 15, color: 'var(--clavex-neutral)' }} />
            <div>
              <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--clavex-neutral)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Organizations</p>
              <p style={{ fontSize: 14, fontWeight: 700, color: lic.exceeds_limit ? '#A32D2D' : 'var(--clavex-ink)' }}>
                {lic.current_org_count} / {lic.org_limit === 9999 ? '∞' : lic.org_limit}
              </p>
            </div>
          </div>

          <div style={{ width: 1, height: 32, background: 'var(--clavex-surface)', flexShrink: 0 }} />

          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Clock style={{ width: 15, height: 15, color: 'var(--clavex-neutral)' }} />
            <div>
              <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--clavex-neutral)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Expires</p>
              <p style={{ fontSize: 14, fontWeight: 700, color: lic.license_expiring_soon ? '#854F0B' : 'var(--clavex-ink)' }}>
                {expiresLabel()}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Installation ID */}
      <div style={{
        background: 'white', border: '0.5px solid var(--clavex-border)',
        borderRadius: 'var(--clavex-radius-lg)', padding: '20px', marginBottom: 16,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
          <Key style={{ width: 15, height: 15, color: 'var(--clavex-neutral)' }} />
          <p style={{ fontWeight: 600, fontSize: 14, color: 'var(--clavex-ink)' }}>Installation ID</p>
        </div>
        <p style={{ fontSize: 13, color: 'var(--clavex-neutral)', marginBottom: 12 }}>
          Copy this ID and paste it into the{' '}
          <a href="https://clavex.eu/license" target="_blank" rel="noreferrer"
            style={{ color: 'var(--clavex-primary)', textDecoration: 'none' }}>
            Clavex license portal
          </a>{' '}
          to bind your license to this installation.
        </p>
        {installId
          ? <CopyText value={installId} />
          : <div style={{ height: 38, background: 'var(--clavex-50)', borderRadius: 6 }} />}
      </div>

      {/* Upload section */}
      <Card className="p-5">
        <p style={{ fontWeight: 600, fontSize: 14, color: 'var(--clavex-ink)', marginBottom: 4 }}>
          Activate license
        </p>
        <p style={{ fontSize: 13, color: 'var(--clavex-neutral)', marginBottom: 16 }}>
          Paste the license JWT you received by email. The license is validated and hot-loaded
          instantly — no restart required.
        </p>
        <Textarea
          label="License token (JWT)"
          placeholder="eyJhbGciOiJFUzI1NiJ9..."
          value={token}
          onChange={e => setToken(e.target.value)}
          rows={4}
          spellCheck={false}
          className="font-mono text-[13px]"
        />
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 14 }}>
          <Button
            onClick={() => uploadM.mutate(token.trim())}
            disabled={!token.trim()}
            loading={uploadM.isPending}
          >
            <ShieldCheck className="h-4 w-4" />
            Activate license
          </Button>
        </div>
      </Card>
    </div>
  )
}
