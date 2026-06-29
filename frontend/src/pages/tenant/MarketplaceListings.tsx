import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Package, Plus, Trash2, ExternalLink, Tag, Clock, CheckCircle, XCircle, AlertCircle } from 'lucide-react'
import toast from 'react-hot-toast'
import api, { toArr } from '@/lib/api'
import { useAuthStore } from '@/stores/auth'
import { Badge, Button, PageHeader, Spinner, Modal } from '@/components/ui'

// ── Types ─────────────────────────────────────────────────────────────────────

interface Listing {
  id: string
  display_name: string
  description?: string
  issuer_name: string
  vct: string
  credential_format: string
  lang: string
  issuer_endpoint: string
  schema_json: Record<string, unknown>
  offer_template?: string
  tags: string[]
  status: 'pending' | 'verified' | 'rejected'
  is_public: boolean
  moderation_note?: string
  created_at: string
  updated_at: string
}

interface PublishForm {
  display_name: string
  description: string
  issuer_name: string
  vct: string
  credential_format: string
  lang: string
  issuer_endpoint: string
  schema_json: string
  offer_template: string
  tags: string
}

const EMPTY_FORM: PublishForm = {
  display_name: '',
  description: '',
  issuer_name: '',
  vct: '',
  credential_format: 'vc+sd-jwt',
  lang: 'it',
  issuer_endpoint: '',
  schema_json: '{}',
  offer_template: '',
  tags: '',
}

// ── Style helpers ─────────────────────────────────────────────────────────────

const card: React.CSSProperties = {
  background: 'white',
  border: '0.5px solid var(--clavex-border)',
  borderRadius: 12,
  padding: '20px 24px',
}

const inp: React.CSSProperties = {
  background: 'white',
  color: 'var(--clavex-ink)',
  border: '0.5px solid var(--clavex-border-subtle)',
  borderRadius: 8,
  padding: '7px 11px',
  fontSize: 13,
  outline: 'none',
  width: '100%',
}

const lbl: React.CSSProperties = {
  display: 'block',
  fontSize: 11,
  fontWeight: 600,
  textTransform: 'uppercase' as const,
  letterSpacing: '0.06em',
  color: 'var(--clavex-ink-muted)',
  marginBottom: 4,
}

const sel: React.CSSProperties = {
  ...inp,
  cursor: 'pointer',
  appearance: 'none' as const,
}

function statusBadge(status: Listing['status']) {
  if (status === 'verified') return <Badge variant="green"><CheckCircle className="h-3 w-3" /> Verified</Badge>
  if (status === 'rejected') return <Badge variant="red"><XCircle className="h-3 w-3" /> Rejected</Badge>
  return <Badge variant="yellow"><Clock className="h-3 w-3" /> Pending review</Badge>
}

// ── Publish form modal ────────────────────────────────────────────────────────

function PublishModal({ orgId, onClose }: { orgId: string; onClose: () => void }) {
  const qc = useQueryClient()
  const [form, setForm] = useState<PublishForm>(EMPTY_FORM)
  const [schemaError, setSchemaError] = useState('')

  const set = (field: keyof PublishForm) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    setForm(prev => ({ ...prev, [field]: e.target.value }))
    if (field === 'schema_json') setSchemaError('')
  }

  const publishMut = useMutation({
    mutationFn: (body: object) => api.post(`/organizations/${orgId}/marketplace/listings`, body),
    onSuccess: () => {
      toast.success('Listing submitted — awaiting moderation')
      qc.invalidateQueries({ queryKey: ['marketplace-listings', orgId] })
      onClose()
    },
    onError: () => toast.error('Failed to submit listing'),
  })

  const handleSubmit = () => {
    let schemaJSON: Record<string, unknown> = {}
    try {
      schemaJSON = JSON.parse(form.schema_json || '{}')
    } catch {
      setSchemaError('Invalid JSON schema')
      return
    }
    publishMut.mutate({
      display_name:      form.display_name,
      description:       form.description || undefined,
      issuer_name:       form.issuer_name,
      vct:               form.vct,
      credential_format: form.credential_format,
      lang:              form.lang,
      issuer_endpoint:   form.issuer_endpoint,
      schema_json:       schemaJSON,
      offer_template:    form.offer_template || undefined,
      tags:              form.tags ? form.tags.split(',').map(t => t.trim()).filter(Boolean) : [],
    })
  }

  const valid = form.display_name && form.issuer_name && form.vct && form.issuer_endpoint

  return (
    <Modal
      open
      title="Publish to Marketplace"
      onClose={onClose}
      size="xl"
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div style={{ padding: '10px 14px', background: '#eff6ff', borderRadius: 8, border: '0.5px solid #bfdbfe', fontSize: 13, color: '#1e40af' }}>
          <AlertCircle size={13} style={{ display: 'inline', marginRight: 6, verticalAlign: 'middle' }} />
          Your template will be reviewed by the Clavex team before appearing in the public catalog.
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
          <div>
            <label style={lbl}>Display Name *</label>
            <input style={inp} value={form.display_name} onChange={set('display_name')} placeholder="e.g. Certificato di Residenza" />
          </div>
          <div>
            <label style={lbl}>Issuer Name *</label>
            <input style={inp} value={form.issuer_name} onChange={set('issuer_name')} placeholder="e.g. Comune di Roma" />
          </div>
        </div>

        <div>
          <label style={lbl}>Description</label>
          <textarea style={{ ...inp, resize: 'vertical' }} rows={2} value={form.description} onChange={set('description')} placeholder="Short description of the credential and its use case" />
        </div>

        <div>
          <label style={lbl}>VCT (Credential Type URI) *</label>
          <input style={inp} value={form.vct} onChange={set('vct')} placeholder="https://credentials.example.it/residenza/v1" />
        </div>

        <div>
          <label style={lbl}>Issuer Endpoint (OID4VCI) *</label>
          <input style={inp} value={form.issuer_endpoint} onChange={set('issuer_endpoint')} placeholder="https://issuer.example.it" />
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 14 }}>
          <div>
            <label style={lbl}>Format</label>
            <select style={sel} value={form.credential_format} onChange={set('credential_format')}>
              <option value="vc+sd-jwt">vc+sd-jwt</option>
              <option value="mso_mdoc">mso_mdoc</option>
              <option value="jwt_vc_json">jwt_vc_json</option>
              <option value="ldp_vc">ldp_vc</option>
            </select>
          </div>
          <div>
            <label style={lbl}>Language</label>
            <select style={sel} value={form.lang} onChange={set('lang')}>
              <option value="it">🇮🇹 Italian</option>
              <option value="en">🇬🇧 English</option>
              <option value="de">🇩🇪 German</option>
              <option value="fr">🇫🇷 French</option>
              <option value="es">🇪🇸 Spanish</option>
            </select>
          </div>
          <div>
            <label style={lbl}>Tags (comma-separated)</label>
            <input style={inp} value={form.tags} onChange={set('tags')} placeholder="PA, residenza, anagrafe" />
          </div>
        </div>

        <div>
          <label style={lbl}>Schema JSON</label>
          <textarea
            style={{ ...inp, fontFamily: 'monospace', fontSize: 12, resize: 'vertical' }}
            rows={5}
            value={form.schema_json}
            onChange={set('schema_json')}
            placeholder='{"given_name": "string", "family_name": "string"}'
          />
          {schemaError && <div style={{ fontSize: 12, color: '#dc2626', marginTop: 4 }}>{schemaError}</div>}
        </div>

        <div>
          <label style={lbl}>Credential Offer URI Template (optional)</label>
          <input style={inp} value={form.offer_template} onChange={set('offer_template')} placeholder="openid-credential-offer://…" />
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 4 }}>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={handleSubmit} disabled={!valid || publishMut.isPending}>
            {publishMut.isPending ? 'Submitting…' : 'Submit for review'}
          </Button>
        </div>
      </div>
    </Modal>
  )
}

// ── Listing card ──────────────────────────────────────────────────────────────

function ListingCard({ listing, orgId, onDeleted }: { listing: Listing; orgId: string; onDeleted: () => void }) {
  const deleteMut = useMutation({
    mutationFn: () => api.delete(`/organizations/${orgId}/marketplace/listings/${listing.id}`),
    onSuccess: () => { toast.success('Listing removed'); onDeleted() },
    onError: () => toast.error('Failed to remove listing'),
  })

  return (
    <div style={{ ...card, display: 'flex', gap: 14 }}>
      <div style={{
        width: 40, height: 40, borderRadius: 8, flexShrink: 0,
        background: 'linear-gradient(135deg,#1D9E75,#3B6DCA)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
      }}>
        <Package size={18} color="#fff" />
      </div>

      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 }}>
          <div>
            <div style={{ fontWeight: 600, fontSize: 15, color: 'var(--clavex-ink)' }}>{listing.display_name}</div>
            <div style={{ fontSize: 12, color: 'var(--clavex-ink-muted)', marginTop: 2 }}>{listing.issuer_name}</div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {statusBadge(listing.status)}
            <a
              href={listing.issuer_endpoint}
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: 'var(--clavex-ink-muted)', padding: 4 }}
              title="Open issuer endpoint"
            >
              <ExternalLink size={14} />
            </a>
            <button
              onClick={() => deleteMut.mutate()}
              disabled={deleteMut.isPending}
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#dc2626', padding: 4, opacity: deleteMut.isPending ? 0.5 : 1 }}
              title="Remove listing"
            >
              <Trash2 size={14} />
            </button>
          </div>
        </div>

        {listing.description && (
          <p style={{ margin: '6px 0 0', fontSize: 13, color: 'var(--clavex-ink-muted)', lineHeight: 1.5 }}>{listing.description}</p>
        )}

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 8, alignItems: 'center' }}>
          <code style={{ fontSize: 11, color: 'var(--clavex-ink-muted)', background: 'var(--clavex-50)', padding: '2px 6px', borderRadius: 4, maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {listing.vct}
          </code>
          {listing.tags.map(t => (
            <span key={t} style={{ display: 'inline-flex', alignItems: 'center', gap: 3, fontSize: 11, color: 'var(--clavex-ink-muted)', background: 'var(--clavex-50)', padding: '2px 8px', borderRadius: 20, border: '0.5px solid var(--clavex-border)' }}>
              <Tag size={9} />{t}
            </span>
          ))}
        </div>

        {listing.moderation_note && (
          <div style={{ marginTop: 10, padding: '8px 12px', background: '#fef3cd', borderRadius: 8, border: '0.5px solid #f59e0b44', fontSize: 13 }}>
            <strong>Moderation note:</strong> {listing.moderation_note}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function MarketplaceListingsPage() {
  const orgId = useAuthStore(s => s.orgId)
  const qc = useQueryClient()
  const [showPublish, setShowPublish] = useState(false)

  const { data, isLoading } = useQuery<Listing[]>({
    queryKey: ['marketplace-listings', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/marketplace/listings`).then(r => toArr(r.data)),
    enabled: !!orgId,
  })

  const listings = data ?? []
  const pending  = listings.filter(l => l.status === 'pending')
  const verified = listings.filter(l => l.status === 'verified')
  const rejected = listings.filter(l => l.status === 'rejected')

  if (!orgId) return null

  return (
    <div>
      <PageHeader
        title="Marketplace"
        subtitle="Publish your credential templates to the Clavex public catalog"
        action={
          <Button onClick={() => setShowPublish(true)}>
            <Plus className="h-4 w-4" /> Publish template
          </Button>
        }
      />

      {/* Info banner */}
      <div style={{ marginBottom: 24, padding: '14px 18px', background: '#f0fdf4', borderRadius: 10, border: '0.5px solid #bbf7d0', fontSize: 13, color: '#166534', lineHeight: 1.6 }}>
        <strong>How it works:</strong> Submit a credential template and it will be reviewed by Clavex.
        Once approved, it appears in the public catalog at{' '}
        <a href="/credentials" style={{ color: '#166534', fontWeight: 600 }} target="_blank">/credentials</a>
        {' '}— discoverable by wallet developers and other issuers.
      </div>

      {isLoading ? (
        <Spinner />
      ) : listings.length === 0 ? (
        <div style={{ ...card, textAlign: 'center', padding: '48px 24px' }}>
          <Package size={36} style={{ margin: '0 auto 12px', color: 'var(--clavex-ink-muted)', opacity: 0.4 }} />
          <p style={{ margin: '0 0 16px', color: 'var(--clavex-ink-muted)' }}>No templates published yet</p>
          <Button onClick={() => setShowPublish(true)}>
            <Plus className="h-4 w-4" /> Publish your first template
          </Button>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {/* Stats row */}
          <div style={{ display: 'flex', gap: 10, marginBottom: 4 }}>
            {[
              { label: 'Total', count: listings.length, color: 'var(--clavex-ink-muted)' },
              { label: 'Published', count: verified.length, color: '#16a34a' },
              { label: 'Pending', count: pending.length, color: '#d97706' },
              { label: 'Rejected', count: rejected.length, color: '#dc2626' },
            ].map(s => (
              <div key={s.label} style={{ ...card, padding: '12px 18px', flex: 1 }}>
                <div style={{ fontSize: 22, fontWeight: 700, color: s.color }}>{s.count}</div>
                <div style={{ fontSize: 12, color: 'var(--clavex-ink-muted)' }}>{s.label}</div>
              </div>
            ))}
          </div>

          {listings.map(l => (
            <ListingCard
              key={l.id}
              listing={l}
              orgId={orgId}
              onDeleted={() => qc.invalidateQueries({ queryKey: ['marketplace-listings', orgId] })}
            />
          ))}
        </div>
      )}

      {showPublish && <PublishModal orgId={orgId} onClose={() => setShowPublish(false)} />}
    </div>
  )
}
