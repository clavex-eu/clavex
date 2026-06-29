import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import {
  Activity,
  AlertTriangle,
  Building2,
  CheckCircle2,
  Clock,
  Database,
  Key,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  Users,
  XCircle,
} from 'lucide-react'
import toast from 'react-hot-toast'
import api from '@/lib/api'
import { Badge, Button, Card, Modal, PageHeader, Spinner } from '@/components/ui'

// ── Types ─────────────────────────────────────────────────────────────────────

interface LicenseState {
  valid: boolean
  tier: string
  org_limit: number
  current_org_count: number
  exceeds_limit: boolean
  first_violation_at: string | null
  grace_period_expired: boolean
  warning_message: string
  auth_blocked: boolean
  license_expires_at: string | null
  license_expiring_soon: boolean
}

interface OrgHealthRow {
  id: string
  name: string
  slug: string
  is_active: boolean
  user_count: number
  mau: number
  dau: number
  logins_today: number
  failed_logins_today: number
  anomaly_score: number
}

interface WorkerStatus {
  name: string
  last_run_at: string | null
  status: 'ok' | 'error' | 'never'
  detail?: string
  extra?: Record<string, number>
}

interface HealthAlert {
  org_id: string
  org_name: string
  org_slug: string
  type: string
  detail: string
}

interface InstallationTotals {
  org_count: number
  active_org_count: number
  dau_total: number
  logins_today: number
  failed_logins_today: number
}

interface HealthDashboard {
  db_version: string
  orgs: OrgHealthRow[]
  workers: WorkerStatus[]
  totals: InstallationTotals
  alerts: HealthAlert[]
  computed_at: string
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const d = new Date(iso)
  const diff = Date.now() - d.getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

function fmtNum(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M'
  if (n >= 1_000) return (n / 1_000).toFixed(1) + 'K'
  return String(n)
}

function anomalyBadge(score: number) {
  if (score >= 80) return <Badge variant="green">Score {score}</Badge>
  if (score >= 50) return <Badge variant="yellow">Score {score}</Badge>
  return <Badge variant="red">Score {score}</Badge>
}

function WorkerCard({ w }: { w: WorkerStatus }) {
  const ok = w.status === 'ok'
  const never = w.status === 'never'
  const Icon = ok ? CheckCircle2 : never ? Clock : XCircle
  const iconColor = ok ? '#0F6E56' : never ? '#854F0B' : '#A32D2D'
  const entryCount = w.extra?.entry_count
  const pendingCount = w.extra?.pending_count

  return (
    <div style={{
      background: 'white',
      border: '0.5px solid var(--clavex-border)',
      borderRadius: 'var(--clavex-radius-lg)',
      padding: '16px 20px',
    }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
        <div style={{
          width: 36, height: 36, borderRadius: 8, flexShrink: 0,
          background: ok ? '#E1F5EE' : never ? '#FAEEDA' : '#FCEBEB',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <Icon style={{ width: 16, height: 16, color: iconColor }} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <p style={{ fontWeight: 600, fontSize: 13, color: 'var(--clavex-ink)' }}>{w.name}</p>
          <p style={{ fontSize: 12, color: 'var(--clavex-neutral)', marginTop: 2 }}>
            {w.last_run_at ? `Last run ${fmtTime(w.last_run_at)}` : 'Never run'}
          </p>
          {w.detail && (
            <p style={{ fontSize: 11, color: '#A32D2D', marginTop: 4, wordBreak: 'break-word' }}>{w.detail}</p>
          )}
          <div style={{ display: 'flex', gap: 8, marginTop: 8, flexWrap: 'wrap' }}>
            {entryCount !== undefined && (
              <span style={{
                fontSize: 11, fontWeight: 600,
                background: 'var(--clavex-50)', border: '0.5px solid var(--clavex-border)',
                borderRadius: 6, padding: '2px 8px', color: 'var(--clavex-700)',
              }}>
                {fmtNum(entryCount)} entries
              </span>
            )}
            {pendingCount !== undefined && pendingCount > 0 && (
              <span style={{
                fontSize: 11, fontWeight: 600,
                background: '#FAEEDA', borderRadius: 6,
                padding: '2px 8px', color: '#854F0B',
              }}>
                {pendingCount} pending
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function SummaryCard({
  icon: Icon, label, value, sub, color,
}: {
  icon: React.ElementType
  label: string
  value: string | number
  sub?: string
  color?: string
}) {
  return (
    <div style={{
      background: 'white',
      border: '0.5px solid var(--clavex-border)',
      borderRadius: 'var(--clavex-radius-lg)',
      padding: '16px 20px',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
        <div style={{
          width: 32, height: 32, borderRadius: 8,
          background: color ? `${color}18` : 'var(--clavex-50)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <Icon style={{ width: 15, height: 15, color: color ?? 'var(--clavex-700)' }} />
        </div>
        <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--clavex-neutral)', letterSpacing: '0.3px' }}>
          {label}
        </span>
      </div>
      <p style={{ fontSize: 22, fontWeight: 700, color: 'var(--clavex-ink)', letterSpacing: '-0.5px' }}>
        {fmtNum(Number(value))}
      </p>
      {sub && <p style={{ fontSize: 11, color: 'var(--clavex-neutral)', marginTop: 3 }}>{sub}</p>}
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function HealthDashboardPage() {
  const [confirmRotate, setConfirmRotate] = useState(false)
  const [newKid, setNewKid] = useState<string | null>(null)
  const [confirmRotateEnc, setConfirmRotateEnc] = useState(false)
  const [newEncKid, setNewEncKid] = useState<string | null>(null)

  const rotateKeyM = useMutation({
    mutationFn: () => api.post<{ kid: string }>('/superadmin/rotate-signing-key').then(r => r.data),
    onSuccess: (data) => {
      setConfirmRotate(false)
      setNewKid(data.kid)
      toast.success('Signing key rotated — new kid: ' + data.kid)
    },
    onError: () => {
      setConfirmRotate(false)
      toast.error('Failed to rotate signing key')
    },
  })

  const rotateEncKeyM = useMutation({
    mutationFn: () => api.post<{ kid: string }>('/superadmin/rotate-enc-key').then(r => r.data),
    onSuccess: (data) => {
      setConfirmRotateEnc(false)
      setNewEncKid(data.kid)
      toast.success('Encryption key rotated — new kid: ' + data.kid)
    },
    onError: () => {
      setConfirmRotateEnc(false)
      toast.error('Failed to rotate encryption key (is request-object encryption enabled?)')
    },
  })

  const { data, isLoading, isFetching, refetch } = useQuery<HealthDashboard>({
    queryKey: ['superadmin-health'],
    queryFn: () => api.get('/superadmin/health').then((r) => r.data),
    refetchInterval: 60_000,
    staleTime: 30_000,
  })

  const { data: lic } = useQuery<LicenseState>({
    queryKey: ['superadmin-license'],
    queryFn: () => api.get('/superadmin/license').then((r) => r.data),
    refetchInterval: 5 * 60_000,
    staleTime: 60_000,
  })

  if (isLoading) return <Spinner />

  const d = data!
  const failurePct = d.totals.logins_today > 0
    ? ((d.totals.failed_logins_today / d.totals.logins_today) * 100).toFixed(1)
    : '0.0'

  return (
    <div>
      <PageHeader
        title="Installation Health"
        subtitle={`Computed ${fmtTime(d.computed_at)} · DB: ${d.db_version.split(' ').slice(0, 2).join(' ')}`}
        action={
          <div style={{ display: 'flex', gap: 8 }}>
            <Button variant="secondary" onClick={() => setConfirmRotate(true)}>
              <RotateCcw className="h-4 w-4" />
              Rotate Signing Key
            </Button>
            <Button variant="secondary" onClick={() => setConfirmRotateEnc(true)}>
              <RotateCcw className="h-4 w-4" />
              Rotate Encryption Key
            </Button>
            <Button variant="secondary" onClick={() => refetch()} disabled={isFetching}>
              <RefreshCw className={`h-4 w-4 ${isFetching ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>
        }
      />

      {/* ── Signing key rotation result ─────────────────────────────────── */}
      {newKid && (
        <div style={{
          display: 'flex', alignItems: 'flex-start', gap: 12,
          background: '#E1F5EE', border: '0.5px solid #0F6E56',
          borderRadius: 'var(--clavex-radius-md)', padding: '12px 16px', marginBottom: 12,
        }}>
          <CheckCircle2 style={{ width: 15, height: 15, color: '#0F6E56', marginTop: 1, flexShrink: 0 }} />
          <div style={{ flex: 1 }}>
            <p style={{ fontWeight: 700, fontSize: 13, color: '#0F6E56' }}>Signing key rotated successfully</p>
            <p style={{ fontSize: 12, color: '#5F5E5A', marginTop: 2 }}>
              New key ID: <code style={{ fontFamily: 'monospace', background: 'rgba(0,0,0,.06)', padding: '1px 6px', borderRadius: 4 }}>{newKid}</code>
              {' '}· The previous key remains in JWKS for 24 h so existing tokens continue to verify.
            </p>
          </div>
          <button
            onClick={() => setNewKid(null)}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#0F6E56', fontSize: 18, lineHeight: 1, padding: 2 }}
            aria-label="Dismiss"
          >×</button>
        </div>
      )}

      {/* ── Encryption key rotation result ──────────────────────────────── */}
      {newEncKid && (
        <div style={{
          display: 'flex', alignItems: 'flex-start', gap: 12,
          background: '#E1F5EE', border: '0.5px solid #0F6E56',
          borderRadius: 'var(--clavex-radius-md)', padding: '12px 16px', marginBottom: 12,
        }}>
          <CheckCircle2 style={{ width: 15, height: 15, color: '#0F6E56', marginTop: 1, flexShrink: 0 }} />
          <div style={{ flex: 1 }}>
            <p style={{ fontWeight: 700, fontSize: 13, color: '#0F6E56' }}>Encryption key rotated successfully</p>
            <p style={{ fontSize: 12, color: '#5F5E5A', marginTop: 2 }}>
              New key ID: <code style={{ fontFamily: 'monospace', background: 'rgba(0,0,0,.06)', padding: '1px 6px', borderRadius: 4 }}>{newEncKid}</code>
              {' '}· The previous key is retained for 24 h so request objects already encrypted to it still decrypt.
            </p>
          </div>
          <button
            onClick={() => setNewEncKid(null)}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#0F6E56', fontSize: 18, lineHeight: 1, padding: 2 }}
            aria-label="Dismiss"
          >×</button>
        </div>
      )}

      {/* ── License status ─────────────────────────────────────────────────── */}
      {lic && (
        <div style={{ marginBottom: 20 }}>
          {/* Hard-block banner */}
          {lic.auth_blocked && (
            <div style={{
              display: 'flex', alignItems: 'flex-start', gap: 12,
              background: '#FCEBEB', border: '0.5px solid #E9B5B5',
              borderRadius: 'var(--clavex-radius-md)', padding: '12px 16px',
              marginBottom: 8,
            }}>
              <XCircle style={{ width: 15, height: 15, color: '#A32D2D', marginTop: 1, flexShrink: 0 }} />
              <div>
                <p style={{ fontWeight: 700, fontSize: 13, color: '#A32D2D' }}>
                  Authentication blocked — license grace period expired
                </p>
                <p style={{ fontSize: 12, color: '#5F5E5A', marginTop: 2 }}>{lic.warning_message}</p>
              </div>
            </div>
          )}
          {/* Grace period warning */}
          {lic.exceeds_limit && !lic.auth_blocked && (
            <div style={{
              display: 'flex', alignItems: 'flex-start', gap: 12,
              background: '#FAEEDA', border: '0.5px solid #E8C97C',
              borderRadius: 'var(--clavex-radius-md)', padding: '12px 16px',
              marginBottom: 8,
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
          {/* Expiring soon */}
          {lic.license_expiring_soon && !lic.exceeds_limit && (
            <div style={{
              display: 'flex', alignItems: 'flex-start', gap: 12,
              background: '#FAEEDA', border: '0.5px solid #E8C97C',
              borderRadius: 'var(--clavex-radius-md)', padding: '12px 16px',
              marginBottom: 8,
            }}>
              <Clock style={{ width: 15, height: 15, color: '#854F0B', marginTop: 1, flexShrink: 0 }} />
              <div>
                <p style={{ fontWeight: 700, fontSize: 13, color: '#854F0B' }}>
                  License expiring soon
                </p>
                <p style={{ fontSize: 12, color: '#5F5E5A', marginTop: 2 }}>
                  Expires {lic.license_expires_at ? new Date(lic.license_expires_at).toLocaleDateString() : '—'}.
                  {' '}Contact <a href="mailto:support@clavex.eu" style={{ color: '#854F0B' }}>support@clavex.eu</a> to renew.
                </p>
              </div>
            </div>
          )}
          {/* License info card */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: 12,
            background: 'white', border: '0.5px solid var(--clavex-border)',
            borderRadius: 'var(--clavex-radius-md)', padding: '10px 16px',
          }}>
            <div style={{
              width: 30, height: 30, borderRadius: 8, flexShrink: 0,
              background: lic.auth_blocked ? '#FCEBEB' : lic.exceeds_limit ? '#FAEEDA' : 'var(--clavex-50)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <Key style={{
                width: 14, height: 14,
                color: lic.auth_blocked ? '#A32D2D' : lic.exceeds_limit ? '#854F0B' : 'var(--clavex-700)',
              }} />
            </div>
            <div style={{ flex: 1 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--clavex-ink)', textTransform: 'capitalize' }}>
                {lic.tier === 'community' ? 'Community edition' : `${lic.tier} license`}
              </span>
              <span style={{ fontSize: 12, color: 'var(--clavex-neutral)', marginLeft: 12 }}>
                {lic.current_org_count} / {lic.org_limit} org{lic.org_limit !== 1 ? 's' : ''}
              </span>
              {lic.license_expires_at && (
                <span style={{ fontSize: 12, color: 'var(--clavex-neutral)', marginLeft: 12 }}>
                  · expires {new Date(lic.license_expires_at).toLocaleDateString()}
                </span>
              )}
            </div>
            <Badge variant={lic.auth_blocked ? 'red' : lic.exceeds_limit ? 'yellow' : 'green'}>
              {lic.auth_blocked ? 'Blocked' : lic.exceeds_limit ? 'Over limit' : 'OK'}
            </Badge>
          </div>
        </div>
      )}

      {/* ── Alerts ──────────────────────────────────────────────────────────── */}
      {d.alerts.length > 0 && (
        <div style={{ marginBottom: 24 }}>
          {d.alerts.map((a, i) => (
            <div key={i} style={{
              display: 'flex', alignItems: 'flex-start', gap: 12,
              background: a.type === 'high_failure_rate' ? '#FAEEDA' : '#FCEBEB',
              border: `0.5px solid ${a.type === 'high_failure_rate' ? '#E8C97C' : '#E9B5B5'}`,
              borderRadius: 'var(--clavex-radius-md)',
              padding: '10px 14px',
              marginBottom: 8,
            }}>
              <AlertTriangle style={{
                width: 15, height: 15, flexShrink: 0, marginTop: 1,
                color: a.type === 'high_failure_rate' ? '#854F0B' : '#A32D2D',
              }} />
              <div>
                <span style={{
                  fontSize: 12, fontWeight: 700,
                  color: a.type === 'high_failure_rate' ? '#854F0B' : '#A32D2D',
                }}>
                  {a.org_name}
                </span>
                <span style={{ fontSize: 12, color: '#5F5E5A', marginLeft: 8 }}>{a.detail}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ── Summary cards ────────────────────────────────────────────────────── */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))',
        gap: 12, marginBottom: 24,
      }}>
        <SummaryCard icon={Building2} label="TOTAL ORGS"    value={d.totals.org_count}
          sub={`${d.totals.active_org_count} active`} />
        <SummaryCard icon={Users}     label="DAU TODAY"     value={d.totals.dau_total}
          sub="distinct authenticated users" color="#185FA5" />
        <SummaryCard icon={Activity}  label="LOGINS TODAY"  value={d.totals.logins_today}
          sub="all organizations" color="#0F6E56" />
        <SummaryCard icon={ShieldAlert} label="FAILURES TODAY" value={d.totals.failed_logins_today}
          sub={`${failurePct}% failure rate`}
          color={Number(failurePct) > 10 ? '#A32D2D' : '#5F5E5A'} />
      </div>

      {/* ── Workers ──────────────────────────────────────────────────────────── */}
      <p style={{
        fontSize: 11, fontWeight: 700, letterSpacing: '1.2px',
        color: 'var(--clavex-neutral)', textTransform: 'uppercase', marginBottom: 10,
      }}>Background Workers</p>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 12, marginBottom: 28 }}>
        {d.workers.map((w) => <WorkerCard key={w.name} w={w} />)}
      </div>

      {/* ── Org table ────────────────────────────────────────────────────────── */}
      <p style={{
        fontSize: 11, fontWeight: 700, letterSpacing: '1.2px',
        color: 'var(--clavex-neutral)', textTransform: 'uppercase', marginBottom: 10,
      }}>Organizations</p>
      <Card>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '0.5px solid var(--clavex-border)' }}>
                {['Organization', 'Status', 'Users', 'MAU', 'DAU', 'Logins today', 'Failures', 'Anomaly'].map((h) => (
                  <th key={h} style={{
                    padding: '10px 16px', textAlign: 'left',
                    fontSize: 11, fontWeight: 700, letterSpacing: '0.5px',
                    color: 'var(--clavex-neutral)', whiteSpace: 'nowrap',
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {d.orgs.map((org, i) => {
                const failPct = org.logins_today > 0
                  ? ((org.failed_logins_today / org.logins_today) * 100).toFixed(0)
                  : '0'
                return (
                  <tr key={org.id} style={{
                    borderBottom: i < d.orgs.length - 1 ? '0.5px solid var(--clavex-border)' : 'none',
                  }}>
                    <td style={{ padding: '11px 16px' }}>
                      <p style={{ fontWeight: 600, fontSize: 13, color: 'var(--clavex-ink)' }}>{org.name}</p>
                      <p style={{ fontSize: 11, color: 'var(--clavex-neutral)', marginTop: 1, fontFamily: 'monospace' }}>
                        {org.slug}
                      </p>
                    </td>
                    <td style={{ padding: '11px 16px' }}>
                      <Badge variant={org.is_active ? 'green' : 'gray'}>
                        {org.is_active ? 'Active' : 'Inactive'}
                      </Badge>
                    </td>
                    <td style={{ padding: '11px 16px', fontSize: 13, color: 'var(--clavex-ink)', textAlign: 'right' }}>
                      {fmtNum(org.user_count)}
                    </td>
                    <td style={{ padding: '11px 16px', fontSize: 13, color: 'var(--clavex-ink)', textAlign: 'right', fontWeight: 600 }}>
                      {fmtNum(org.mau)}
                    </td>
                    <td style={{ padding: '11px 16px', fontSize: 13, color: 'var(--clavex-ink)', textAlign: 'right' }}>
                      {fmtNum(org.dau)}
                    </td>
                    <td style={{ padding: '11px 16px', fontSize: 13, color: 'var(--clavex-ink)', textAlign: 'right' }}>
                      {fmtNum(org.logins_today)}
                    </td>
                    <td style={{ padding: '11px 16px', textAlign: 'right' }}>
                      {org.failed_logins_today > 0 ? (
                        <span style={{
                          fontSize: 12, fontWeight: 700,
                          color: org.anomaly_score < 70 ? '#A32D2D' : 'var(--clavex-ink)',
                        }}>
                          {fmtNum(org.failed_logins_today)}
                          <span style={{ fontWeight: 400, color: 'var(--clavex-neutral)', marginLeft: 4 }}>
                            ({failPct}%)
                          </span>
                        </span>
                      ) : (
                        <span style={{ fontSize: 13, color: 'var(--clavex-neutral)' }}>—</span>
                      )}
                    </td>
                    <td style={{ padding: '11px 16px' }}>
                      {anomalyBadge(org.anomaly_score)}
                    </td>
                  </tr>
                )
              })}
              {d.orgs.length === 0 && (
                <tr>
                  <td colSpan={8} style={{ padding: '32px 16px', textAlign: 'center', fontSize: 13, color: 'var(--clavex-neutral)' }}>
                    No organizations found
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {/* ── DB info footer ────────────────────────────────────────────────────── */}
      <div style={{
        marginTop: 20, padding: '10px 14px',
        background: 'white', border: '0.5px solid var(--clavex-border)',
        borderRadius: 'var(--clavex-radius-md)',
        display: 'flex', alignItems: 'center', gap: 8,
      }}>
        <Database style={{ width: 13, height: 13, color: 'var(--clavex-neutral)' }} />
        <span style={{ fontSize: 12, color: 'var(--clavex-neutral)', fontFamily: 'monospace' }}>
          {d.db_version}
        </span>
      </div>

      {/* ── Rotate signing key confirmation modal ────────────────────────── */}
      <Modal
        open={confirmRotate}
        title="Rotate Signing Key"
        description="A new RSA-2048 key will be generated and immediately used for token signing. The current key stays in JWKS for 24 hours so existing tokens remain verifiable."
        onClose={() => setConfirmRotate(false)}
      >
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, paddingTop: 4 }}>
          <Button variant="secondary" onClick={() => setConfirmRotate(false)} disabled={rotateKeyM.isPending}>
            Cancel
          </Button>
          <Button
            onClick={() => rotateKeyM.mutate()}
            loading={rotateKeyM.isPending}
            style={{ background: '#A32D2D', borderColor: '#A32D2D' }}
          >
            <RotateCcw className="h-4 w-4" />
            Rotate Now
          </Button>
        </div>
      </Modal>

      {/* ── Rotate encryption key confirmation modal ─────────────────────── */}
      <Modal
        open={confirmRotateEnc}
        title="Rotate Encryption Key"
        description="A new RSA-2048 request-object encryption key will be generated and published in the JWKS (use=enc). The previous key is retained for 24 hours so request objects already encrypted to it still decrypt."
        onClose={() => setConfirmRotateEnc(false)}
      >
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, paddingTop: 4 }}>
          <Button variant="secondary" onClick={() => setConfirmRotateEnc(false)} disabled={rotateEncKeyM.isPending}>
            Cancel
          </Button>
          <Button
            onClick={() => rotateEncKeyM.mutate()}
            loading={rotateEncKeyM.isPending}
            style={{ background: '#A32D2D', borderColor: '#A32D2D' }}
          >
            <RotateCcw className="h-4 w-4" />
            Rotate Now
          </Button>
        </div>
      </Modal>
    </div>
  )
}
