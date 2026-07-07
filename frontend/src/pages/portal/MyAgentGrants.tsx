/**
 * My Active Agents — end-user self-service panel.
 *
 * Lists the AI agent grants delegated by the *currently authenticated user*
 * (via GET /api/v1/me/agent-tokens) and lets them revoke any of their own
 * without admin permission (DELETE /api/v1/me/agent-tokens/:id). This is the
 * user-facing counterpart to the admin Agent Tokens console, which shows every
 * token in the organization.
 */
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import { Cpu, Trash2, Clock, ShieldCheck } from 'lucide-react'

interface AgentToken {
  id: string
  agent_id: string
  agent_name: string
  scope: string
  created_at: string
  expires_at: string
  last_used_at?: string
  revoked_at?: string
}

// ── Styles (match SelfServePortal) ──────────────────────────────────────────────

const card: React.CSSProperties = {
  background: 'var(--clavex-surface)',
  border: '0.5px solid var(--clavex-border)',
  borderRadius: 12,
  padding: '18px 20px',
}

const btnGhost: React.CSSProperties = {
  display: 'inline-flex', alignItems: 'center', gap: 6,
  padding: '6px 12px', borderRadius: 8, fontSize: 12, fontWeight: 600,
  border: '0.5px solid var(--clavex-border)', cursor: 'pointer',
  background: 'var(--clavex-surface)', color: 'var(--clavex-danger)',
}

// ── Natural-language scope descriptions ─────────────────────────────────────────
// Translate raw OAuth/MCP scope strings into plain language the delegating user
// can actually reason about, instead of showing bare "mcp:write mcp:tools:call".
const SCOPE_LABELS: Record<string, string> = {
  openid: 'Confirm your identity',
  profile: 'Read your basic profile',
  email: 'Read your email address',
  'mcp:read': 'Read data from MCP servers',
  'mcp:write': 'Write and modify data on MCP servers',
  'mcp:tools:call': 'Invoke any tool on your behalf',
  'mcp:tools:list': 'See which tools are available',
  'mcp:resources:read': 'Read resources (files, databases, APIs)',
  'mcp:resources:write': 'Modify resources (files, databases, APIs)',
  'mcp:prompts:read': 'Read prompt templates',
  'mcp:admin': 'Full administrative access (superscope)',
}

function describeScope(scope: string): string[] {
  const parts = scope.trim().split(/\s+/).filter(Boolean)
  if (parts.length === 0) return ['No scopes granted']
  return parts.map(s => SCOPE_LABELS[s] ?? s)
}

function formatDate(iso?: string): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

// ── Panel ───────────────────────────────────────────────────────────────────────

export function MyAgentGrantsTab() {
  const qc = useQueryClient()

  const { data, isLoading } = useQuery<AgentToken[]>({
    queryKey: ['my-agent-tokens'],
    queryFn: () => api.get('/me/agent-tokens').then(r =>
      Array.isArray(r.data) ? r.data : (r.data?.items ?? [])),
  })

  const revokeMut = useMutation({
    mutationFn: (id: string) => api.delete(`/me/agent-tokens/${id}`),
    onSuccess: () => {
      toast.success('Agent access revoked')
      qc.invalidateQueries({ queryKey: ['my-agent-tokens'] })
    },
    onError: () => toast.error('Failed to revoke agent access'),
  })

  const tokens = (data ?? []).filter(t => !t.revoked_at)

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12, marginBottom: 20 }}>
        <div style={{ padding: 8, borderRadius: 10, background: 'var(--clavex-primary)12', flexShrink: 0 }}>
          <Cpu size={20} color="var(--clavex-primary)" />
        </div>
        <div>
          <h2 style={{ fontSize: 16, fontWeight: 700, margin: 0 }}>My Active Agents</h2>
          <p style={{ fontSize: 13, color: 'var(--clavex-neutral)', margin: '4px 0 0' }}>
            AI agents that can act on your behalf. Revoke any you no longer recognise or trust —
            revocation takes effect immediately.
          </p>
        </div>
      </div>

      {isLoading ? (
        <p style={{ fontSize: 13, color: 'var(--clavex-neutral)' }}>Loading…</p>
      ) : tokens.length === 0 ? (
        <div style={{ ...card, textAlign: 'center', padding: 40, color: 'var(--clavex-neutral)' }}>
          <ShieldCheck size={32} style={{ opacity: 0.3, marginBottom: 8 }} />
          <p style={{ fontSize: 13 }}>No agents currently have access on your behalf.</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {tokens.map(t => {
            const expired = new Date(t.expires_at) < new Date()
            return (
              <div key={t.id} style={card}>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                  <div style={{
                    width: 36, height: 36, borderRadius: 8, background: 'var(--clavex-primary)12',
                    display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                  }}>
                    <Cpu size={18} color="var(--clavex-primary)" />
                  </div>

                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                      <span style={{ fontSize: 14, fontWeight: 700 }}>{t.agent_name}</span>
                      <code style={{ fontSize: 11, color: 'var(--clavex-neutral)' }}>{t.agent_id}</code>
                      {expired && (
                        <span style={{
                          fontSize: 11, padding: '1px 6px', borderRadius: 4,
                          background: 'var(--clavex-border)', color: 'var(--clavex-neutral)',
                        }}>Expired</span>
                      )}
                    </div>

                    {/* Human-readable scope */}
                    <ul style={{ margin: '8px 0 0', padding: 0, listStyle: 'none',
                      display: 'flex', flexDirection: 'column', gap: 3 }}>
                      {describeScope(t.scope).map((line, i) => (
                        <li key={i} style={{ fontSize: 12, color: 'var(--clavex-text)',
                          display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span style={{ width: 4, height: 4, borderRadius: '50%',
                            background: 'var(--clavex-primary)', flexShrink: 0 }} />
                          {line}
                        </li>
                      ))}
                    </ul>

                    {/* Timeline */}
                    <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginTop: 10 }}>
                      <span style={{ fontSize: 11, color: 'var(--clavex-neutral)',
                        display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                        <Clock size={11} /> Granted {formatDate(t.created_at)}
                      </span>
                      <span style={{ fontSize: 11, color: 'var(--clavex-neutral)' }}>
                        Expires {formatDate(t.expires_at)}
                      </span>
                      <span style={{ fontSize: 11, color: 'var(--clavex-neutral)' }}>
                        Last used {formatDate(t.last_used_at)}
                      </span>
                    </div>
                  </div>

                  <button style={btnGhost}
                    onClick={() => {
                      if (confirm(`Revoke access for "${t.agent_name}"? It will no longer be able to act on your behalf.`)) {
                        revokeMut.mutate(t.id)
                      }
                    }}
                    disabled={revokeMut.isPending}>
                    <Trash2 size={13} /> Revoke
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// Route component — see App.tsx (/portal/:orgSlug/my-agents).
export function MyAgentGrantsPage() { return <MyAgentGrantsTab /> }
