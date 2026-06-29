import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import { Cpu, Plus, Trash2, Info } from 'lucide-react'

interface AgentToken {
  id: string
  agent_id: string
  agent_name: string
  scope: string
  expires_at: string
  created_at: string
  revoked_at?: string
  mcp_server_id?: string
  mcp_resource_url?: string
}

interface MCPScope {
  scope: string
  description: string
}

const card: React.CSSProperties = {
  background: 'var(--clavex-surface)',
  border: '0.5px solid var(--clavex-border)',
  borderRadius: 12,
  padding: '20px 24px',
}

const inputStyle: React.CSSProperties = {
  width: '100%',
  padding: '8px 12px',
  borderRadius: 8,
  border: '0.5px solid var(--clavex-border)',
  fontSize: 13,
  background: 'white',
  color: 'var(--clavex-text)',
  boxSizing: 'border-box',
}

const btnPrimary: React.CSSProperties = {
  display: 'flex', alignItems: 'center', gap: 6,
  padding: '8px 16px', borderRadius: 8, fontSize: 13, fontWeight: 500,
  background: 'var(--clavex-primary)', color: 'white', border: 'none', cursor: 'pointer',
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

export default function AgentTokensPage() {
  const { orgId } = useAuthStore()
  const qc = useQueryClient()
  const [issuing, setIssuing] = useState(false)
  const [showScopes, setShowScopes] = useState(false)
  const [form, setForm] = useState({
    user_id: '', agent_id: '', agent_name: '', scope: '', ttl_seconds: 86400,
    mcp_server_id: '', mcp_resource_url: '',
  })

  const { data: tokens = [], isLoading } = useQuery<AgentToken[]>({
    queryKey: ['agent-tokens', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/agent-tokens`).then(r =>
      Array.isArray(r.data) ? r.data : (r.data?.items ?? [])),
    enabled: !!orgId,
  })

  const { data: mcpScopes = [] } = useQuery<{ scopes: MCPScope[] }>({
    queryKey: ['mcp-scopes', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/agent-tokens/mcp-scopes`).then(r => r.data),
    enabled: !!orgId,
    staleTime: Infinity,
  })

  const issueMutation = useMutation({
    mutationFn: (body: object) => api.post(`/organizations/${orgId}/agent-tokens`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['agent-tokens', orgId] })
      toast.success('Agent token issued')
      setIssuing(false)
      setForm({ user_id: '', agent_id: '', agent_name: '', scope: '', ttl_seconds: 86400, mcp_server_id: '', mcp_resource_url: '' })
    },
    onError: () => toast.error('Failed to issue token'),
  })

  const revokeMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/organizations/${orgId}/agent-tokens/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['agent-tokens', orgId] })
      toast.success('Token revoked')
    },
    onError: () => toast.error('Failed to revoke'),
  })

  function handleIssue() {
    const body: Record<string, unknown> = {
      user_id: form.user_id,
      agent_id: form.agent_id,
      agent_name: form.agent_name,
      scope: form.scope,
      ttl_seconds: form.ttl_seconds,
    }
    if (form.mcp_server_id) body.mcp_server_id = form.mcp_server_id
    if (form.mcp_resource_url) body.mcp_resource_url = form.mcp_resource_url
    issueMutation.mutate(body)
  }

  const scopesList: MCPScope[] = (mcpScopes as { scopes?: MCPScope[] }).scopes ?? []

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 28 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <Cpu size={22} color="var(--clavex-primary)" />
          <div>
            <h1 style={{ fontSize: 20, fontWeight: 700, margin: 0 }}>Agent Tokens</h1>
            <p style={{ fontSize: 13, margin: 0, color: 'var(--clavex-neutral)' }}>
              Machine identity tokens for AI agents (MCP OAuth 2.0)
            </p>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button style={{ ...btnPrimary, background: 'white', color: 'var(--clavex-text)', border: '0.5px solid var(--clavex-border)' }}
            onClick={() => setShowScopes(s => !s)}>
            <Info size={14} /> MCP Scopes
          </button>
          <button style={btnPrimary} onClick={() => setIssuing(true)}>
            <Plus size={14} /> Issue token
          </button>
        </div>
      </div>

      {/* MCP Scopes reference */}
      {showScopes && scopesList.length > 0 && (
        <div style={{ ...card, marginBottom: 20, background: '#f8fafc' }}>
          <h2 style={{ fontSize: 13, fontWeight: 600, margin: '0 0 12px', color: 'var(--clavex-neutral)' }}>
            Predefined MCP OAuth 2.0 scopes
          </h2>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            {scopesList.map(s => (
              <div key={s.scope} style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                <code style={{ fontSize: 12, color: 'var(--clavex-primary)', fontWeight: 600 }}>{s.scope}</code>
                <span style={{ fontSize: 11, color: 'var(--clavex-neutral)' }}>{s.description}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Issue form */}
      {issuing && (
        <div style={{ ...card, marginBottom: 20 }}>
          <h2 style={{ fontSize: 14, fontWeight: 600, margin: '0 0 16px' }}>Issue agent token</h2>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div>
              <label style={{ fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 4 }}>User ID (UUID) *</label>
              <input style={inputStyle} value={form.user_id}
                onChange={e => setForm(f => ({ ...f, user_id: e.target.value }))}
                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" />
            </div>
            <div>
              <label style={{ fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 4 }}>Agent ID *</label>
              <input style={inputStyle} value={form.agent_id}
                onChange={e => setForm(f => ({ ...f, agent_id: e.target.value }))}
                placeholder="claude-mcp-v1" />
            </div>
            <div>
              <label style={{ fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 4 }}>Agent Name *</label>
              <input style={inputStyle} value={form.agent_name}
                onChange={e => setForm(f => ({ ...f, agent_name: e.target.value }))}
                placeholder="My MCP Assistant" />
            </div>
            <div>
              <label style={{ fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 4 }}>TTL (seconds)</label>
              <input style={inputStyle} type="number" value={form.ttl_seconds}
                onChange={e => setForm(f => ({ ...f, ttl_seconds: parseInt(e.target.value) || 86400 }))} />
            </div>
            <div style={{ gridColumn: 'span 2' }}>
              <label style={{ fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 4 }}>Scopes</label>
              <input style={inputStyle} value={form.scope}
                onChange={e => setForm(f => ({ ...f, scope: e.target.value }))}
                placeholder="mcp:read mcp:tools:call" />
            </div>
            <div>
              <label style={{ fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 4 }}>MCP Server ID <span style={{ fontWeight: 400, color: 'var(--clavex-neutral)' }}>(optional)</span></label>
              <input style={inputStyle} value={form.mcp_server_id}
                onChange={e => setForm(f => ({ ...f, mcp_server_id: e.target.value }))}
                placeholder="my-mcp-server" />
            </div>
            <div>
              <label style={{ fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 4 }}>MCP Resource URL <span style={{ fontWeight: 400, color: 'var(--clavex-neutral)' }}>(optional, RFC 8707)</span></label>
              <input style={inputStyle} value={form.mcp_resource_url}
                onChange={e => setForm(f => ({ ...f, mcp_resource_url: e.target.value }))}
                placeholder="https://api.example.com/mcp" />
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 16 }}>
            <button style={{ padding: '7px 14px', borderRadius: 8, fontSize: 13, border: '0.5px solid var(--clavex-border)', background: 'white', cursor: 'pointer' }}
              onClick={() => setIssuing(false)}>Cancel</button>
            <button style={btnPrimary} onClick={handleIssue}
              disabled={!form.user_id || !form.agent_id || !form.agent_name || issueMutation.isPending}>
              {issueMutation.isPending ? 'Issuing…' : 'Issue token'}
            </button>
          </div>
        </div>
      )}

      {/* Token list */}
      {isLoading ? (
        <p style={{ color: 'var(--clavex-neutral)', fontSize: 13 }}>Loading…</p>
      ) : tokens.length === 0 ? (
        <div style={{ ...card, textAlign: 'center', padding: 40, color: 'var(--clavex-neutral)' }}>
          <Cpu size={36} style={{ opacity: 0.3, marginBottom: 12 }} />
          <p style={{ fontSize: 14 }}>No agent tokens issued yet</p>
        </div>
      ) : (
        <div style={card}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: '0.5px solid var(--clavex-border)' }}>
                {['Agent', 'Scope', 'MCP Server', 'Expires', 'Status', ''].map(h => (
                  <th key={h} style={{ textAlign: 'left', padding: '8px 12px', fontSize: 11, fontWeight: 600, color: 'var(--clavex-neutral)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {tokens.map(t => {
                const expired = new Date(t.expires_at) < new Date()
                const revoked = !!t.revoked_at
                return (
                  <tr key={t.id} style={{ borderBottom: '0.5px solid var(--clavex-border)' }}>
                    <td style={{ padding: '10px 12px' }}>
                      <div style={{ fontWeight: 600 }}>{t.agent_name}</div>
                      <code style={{ fontSize: 11, color: 'var(--clavex-neutral)' }}>{t.agent_id}</code>
                    </td>
                    <td style={{ padding: '10px 12px', maxWidth: 200 }}>
                      <code style={{ fontSize: 11, wordBreak: 'break-word' }}>{t.scope || '—'}</code>
                    </td>
                    <td style={{ padding: '10px 12px' }}>
                      {t.mcp_server_id ? (
                        <div>
                          <code style={{ fontSize: 11 }}>{t.mcp_server_id}</code>
                          {t.mcp_resource_url && <div style={{ fontSize: 10, color: 'var(--clavex-neutral)', wordBreak: 'break-all' }}>{t.mcp_resource_url}</div>}
                        </div>
                      ) : <span style={{ color: 'var(--clavex-neutral)' }}>—</span>}
                    </td>
                    <td style={{ padding: '10px 12px', fontSize: 12, color: 'var(--clavex-neutral)' }}>{formatDate(t.expires_at)}</td>
                    <td style={{ padding: '10px 12px' }}>
                      <span style={{
                        fontSize: 11, padding: '2px 8px', borderRadius: 12,
                        background: revoked ? '#fee2e2' : expired ? '#fef9c3' : '#dcfce7',
                        color: revoked ? '#dc2626' : expired ? '#854d0e' : '#15803d',
                      }}>
                        {revoked ? 'revoked' : expired ? 'expired' : 'active'}
                      </span>
                    </td>
                    <td style={{ padding: '10px 12px' }}>
                      {!revoked && !expired && (
                        <button style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--clavex-neutral)' }}
                          onClick={() => { if (confirm('Revoke this token?')) revokeMutation.mutate(t.id) }}
                          title="Revoke">
                          <Trash2 size={14} />
                        </button>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
