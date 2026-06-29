import { useQuery } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import { Award, CheckCircle2, XCircle, HelpCircle, ChevronDown, ChevronUp } from 'lucide-react'
import { useState } from 'react'

interface QTSPItem {
  id: string
  title: string
  description: string
  hint: string
  status: 'pass' | 'fail' | 'manual'
  eidas_ref?: string
}

interface QTSPCategory {
  id: string
  title: string
  description: string
  score: number
  max_score: number
  items: QTSPItem[]
}

interface QTSPAssessment {
  overall_score: number
  ready_for_submission: boolean
  summary: string
  categories: QTSPCategory[]
  assessed_at: string
}

const card: React.CSSProperties = {
  background: 'var(--clavex-surface)', border: '0.5px solid var(--clavex-border)',
  borderRadius: 12, padding: '20px 24px',
}

function StatusBadge({ status }: { status: QTSPItem['status'] }) {
  if (status === 'pass') return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#16a34a' }}>
      <CheckCircle2 size={15} />
      <span style={{ fontSize: 12, fontWeight: 600 }}>Pass</span>
    </div>
  )
  if (status === 'fail') return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#dc2626' }}>
      <XCircle size={15} />
      <span style={{ fontSize: 12, fontWeight: 600 }}>Fail</span>
    </div>
  )
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#9ca3af' }}>
      <HelpCircle size={15} />
      <span style={{ fontSize: 12, fontWeight: 600 }}>Manual</span>
    </div>
  )
}

function ScoreGauge({ score, size = 80 }: { score: number; size?: number }) {
  const color = score >= 80 ? '#16a34a' : score >= 55 ? '#d97706' : '#dc2626'
  const r = (size / 2) - 8
  const circ = 2 * Math.PI * r
  const offset = circ - (score / 100) * circ

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--clavex-border)" strokeWidth={8} />
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={8}
        strokeDasharray={circ} strokeDashoffset={offset}
        strokeLinecap="round" transform={`rotate(-90 ${size / 2} ${size / 2})`} />
      <text x={size / 2} y={size / 2 + 6} textAnchor="middle" fontSize={18} fontWeight={800} fill={color}>{score}</text>
    </svg>
  )
}

function CategoryCard({ cat }: { cat: QTSPCategory }) {
  const [open, setOpen] = useState(false)
  const pct = cat.max_score > 0 ? Math.round((cat.score / cat.max_score) * 100) : 0
  const color = pct >= 80 ? '#16a34a' : pct >= 50 ? '#d97706' : '#dc2626'

  return (
    <div style={card}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, cursor: 'pointer' }}
        onClick={() => setOpen(o => !o)}>
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            <span style={{ fontWeight: 600, fontSize: 15 }}>{cat.title}</span>
            <span style={{ fontSize: 12, color: 'var(--clavex-neutral)' }}>{cat.description}</span>
          </div>
          <div style={{ height: 6, background: 'var(--clavex-border)', borderRadius: 3, overflow: 'hidden' }}>
            <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: 3, transition: 'width 0.4s' }} />
          </div>
        </div>
        <div style={{ textAlign: 'right', flexShrink: 0 }}>
          <span style={{ fontSize: 18, fontWeight: 700, color }}>
            {cat.score}<span style={{ fontSize: 12, fontWeight: 400, color: 'var(--clavex-neutral)' }}>/{cat.max_score}</span>
          </span>
        </div>
        {open ? <ChevronUp size={16} style={{ flexShrink: 0, color: 'var(--clavex-neutral)' }} /> : <ChevronDown size={16} style={{ flexShrink: 0, color: 'var(--clavex-neutral)' }} />}
      </div>

      {open && (
        <div style={{ marginTop: 16, display: 'flex', flexDirection: 'column', gap: 8 }}>
          {cat.items.map(item => (
            <div key={item.id} style={{
              padding: '12px 16px', borderRadius: 8,
              background: item.status === 'pass' ? '#f0fdf4' : item.status === 'fail' ? '#fef2f2' : '#f8fafc',
              border: `0.5px solid ${item.status === 'pass' ? '#bbf7d0' : item.status === 'fail' ? '#fecaca' : 'var(--clavex-border)'}`,
            }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                <div style={{ paddingTop: 2 }}>
                  <StatusBadge status={item.status} />
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontWeight: 600, fontSize: 13 }}>{item.title}</span>
                    {item.eidas_ref && (
                      <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 6, background: '#e0f2fe', color: '#0369a1', fontWeight: 500 }}>
                        {item.eidas_ref}
                      </span>
                    )}
                  </div>
                  <p style={{ fontSize: 12, color: 'var(--clavex-neutral)', margin: '4px 0 0' }}>{item.description}</p>
                  {item.status !== 'pass' && item.hint && (
                    <p style={{ fontSize: 12, color: item.status === 'fail' ? '#b91c1c' : '#6b7280', margin: '6px 0 0', fontStyle: 'italic' }}>
                      → {item.hint}
                    </p>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default function QTSPAssessmentPage() {
  const { orgId } = useAuthStore()

  const { data, isLoading, error } = useQuery<QTSPAssessment>({
    queryKey: ['qtsp-assessment', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/qtsp-assessment`).then(r => r.data),
    enabled: !!orgId,
    staleTime: 5 * 60_000,
  })

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 28 }}>
        <Award size={22} color="var(--clavex-primary)" />
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 700, margin: 0 }}>QTSP Readiness Assessment</h1>
          <p style={{ fontSize: 13, margin: 0, color: 'var(--clavex-neutral)' }}>
            eIDAS 2.0 / EU Regulation 910/2014 compliance checklist for Qualified Trust Service Provider status
          </p>
        </div>
      </div>

      {isLoading && (
        <div style={{ ...card, textAlign: 'center', padding: 60, color: 'var(--clavex-neutral)' }}>
          Analysing configuration…
        </div>
      )}

      {error && (
        <div style={{ ...card, background: '#fef2f2', borderColor: '#fecaca', padding: 24, color: '#b91c1c' }}>
          Failed to load assessment. Check your network and try refreshing.
        </div>
      )}

      {data && (
        <>
          {/* Summary banner */}
          <div style={{
            ...card, marginBottom: 24,
            background: data.ready_for_submission ? '#f0fdf4' : '#fff7ed',
            borderColor: data.ready_for_submission ? '#bbf7d0' : '#fed7aa',
            display: 'flex', alignItems: 'center', gap: 24,
          }}>
            <ScoreGauge score={data.overall_score} size={96} />
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                {data.ready_for_submission ? (
                  <span style={{ fontSize: 16, fontWeight: 700, color: '#15803d' }}>Ready for submission</span>
                ) : (
                  <span style={{ fontSize: 16, fontWeight: 700, color: '#c2410c' }}>Not ready for submission</span>
                )}
              </div>
              <p style={{ fontSize: 13, color: 'var(--clavex-neutral)', margin: 0 }}>{data.summary}</p>
              <p style={{ fontSize: 11, color: 'var(--clavex-neutral)', margin: '8px 0 0' }}>
                Last assessed: {new Date(data.assessed_at).toLocaleString()}
              </p>
            </div>
            <div style={{ textAlign: 'center', flexShrink: 0 }}>
              <div style={{ fontSize: 40, fontWeight: 800, color: data.overall_score >= 80 ? '#16a34a' : data.overall_score >= 55 ? '#d97706' : '#dc2626', lineHeight: 1 }}>
                {data.overall_score}
              </div>
              <div style={{ fontSize: 12, color: 'var(--clavex-neutral)' }}>/ 100</div>
            </div>
          </div>

          {/* Category breakdown */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {data.categories.map(cat => (
              <CategoryCard key={cat.id} cat={cat} />
            ))}
          </div>

          {/* Manual items note */}
          <div style={{ marginTop: 20, padding: '12px 16px', borderRadius: 8, background: '#f8fafc', border: '0.5px solid var(--clavex-border)', fontSize: 12, color: 'var(--clavex-neutral)' }}>
            <strong>Note:</strong> Items marked "Manual" require documentation submitted to the national supervisory body.
            Items with eIDAS article references are governed by EU Regulation 910/2014 as amended by Regulation 2024/1183.
          </div>
        </>
      )}
    </div>
  )
}
