import { useEffect, useId, useState, type FormEvent, type ReactNode } from 'react'
import { Dialog, DialogBackdrop, DialogPanel, DialogTitle } from '@headlessui/react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import { AlertTriangle, ExternalLink, Plus, RefreshCw, ShieldCheck, Trash2, X } from 'lucide-react'
import toast from 'react-hot-toast'
import api from '@/lib/api'
import { Button, Card, Spinner } from '@/components/ui'
import { useAuthStore } from '@/stores/auth'

interface Authority {
  id: string
  label: string
  subject_dn: string
  sha256_fingerprint: string
  pem: string
  doc_types: string[]
  not_before?: string
  not_after?: string
}
interface Root extends Authority {
  is_active: boolean
  certificate_warning?: boolean
  certificate_error?: boolean
}
interface Catalog {
  name: string
  environment: 'test'
  reference_commit: string
  entries: (Authority & { country: string; source_url: string })[]
}
const MDL = 'org.iso.18013.5.1.mDL'
const PID = 'eu.europa.ec.eudi.pid.1'
const scopeName = (value: string) => value === MDL ? 'mDL' : value === PID ? 'PID mdoc' : value
const message = (error: unknown) => isAxiosError<{ error?: unknown }>(error) && typeof error.response?.data?.error === 'string'
  ? error.response.data.error.slice(0, 300) : 'The request could not be completed. Please try again.'
const currentOrg = (orgId: string) => useAuthStore.getState().orgId === orgId

function TrustDialog({ open, title, onClose, children }: { open: boolean; title: string; onClose: () => void; children: ReactNode }) {
  return <Dialog open={open} onClose={onClose} className="fixed inset-0 z-50">
    <DialogBackdrop className="fixed inset-0 bg-black/30 backdrop-blur-[2px]" />
    <div className="fixed inset-0 overflow-y-auto p-4 sm:p-8"><div className="flex min-h-full items-center justify-center">
      <DialogPanel className="w-full max-w-2xl rounded-2xl bg-white p-5 shadow-xl sm:p-7" style={{ color: 'var(--clavex-ink)' }}>
        <div className="mb-5 flex items-start justify-between gap-4"><DialogTitle className="text-lg font-semibold">{title}</DialogTitle>
          <button type="button" onClick={onClose} aria-label="Close dialogue" className="rounded p-1 focus-visible:outline-2"><X size={20} /></button>
        </div>{children}
      </DialogPanel>
    </div></div>
  </Dialog>
}

function authorityState(root: Root) {
  if (root.certificate_error) return 'Needs review'
  if (root.not_after && Date.parse(root.not_after) <= Date.now()) return 'Expired'
  if (!root.is_active) return 'Inactive'
  if (root.not_before && Date.parse(root.not_before) > Date.now()) return 'Not yet valid'
  return 'Configured'
}

export default function WalletTrust({ orgId }: { orgId: string | null }) {
  const queryClient = useQueryClient()
  const formId = useId()
  const [uploadOpen, setUploadOpen] = useState(false)
  const [catalogOpen, setCatalogOpen] = useState(false)
  const [deleting, setDeleting] = useState<Root | null>(null)
  const [label, setLabel] = useState('')
  const [pem, setPEM] = useState('')
  const [scope, setScope] = useState(`${MDL}\n${PID}`)
  const [allTypes, setAllTypes] = useState(false)
  const [error, setError] = useState('')
  const [testConsent, setTestConsent] = useState(false)
  const [importSummary, setImportSummary] = useState('')

  useEffect(() => {
    setUploadOpen(false); setCatalogOpen(false); setDeleting(null)
    setLabel(''); setPEM(''); setError(''); setTestConsent(false); setImportSummary('')
    setScope(`${MDL}\n${PID}`); setAllTypes(false)
  }, [orgId])

  const rootsQuery = useQuery({
    queryKey: ['wallet-iaca-roots', orgId],
    queryFn: () => api.get<Root[]>(`/organizations/${orgId}/mdoc/iaca-roots`).then(r => r.data),
    enabled: !!orgId,
  })
  const catalogQuery = useQuery({
    queryKey: ['wallet-iaca-catalog', orgId],
    queryFn: () => api.get<Catalog>(`/organizations/${orgId}/mdoc/iaca-catalog`).then(r => r.data),
    enabled: !!orgId && catalogOpen,
    staleTime: 300_000,
  })
  const roots = rootsQuery.data ?? []
  const fingerprints = new Set(roots.map(r => r.sha256_fingerprint))
  const entries = catalogQuery.data?.entries ?? []
  const usable = (a: Authority) => !!a.not_after && Date.parse(a.not_after) > Date.now() && !!a.not_before && Date.parse(a.not_before) <= Date.now()
  const missing = entries.filter(a => !fingerprints.has(a.sha256_fingerprint) && usable(a))
  const refresh = (id: string) => queryClient.invalidateQueries({ queryKey: ['wallet-iaca-roots', id] })

  const upload = useMutation({
    mutationFn: (v: { orgId: string; label: string; pem: string; doc_types: string[] }) =>
      api.post(`/organizations/${v.orgId}/mdoc/iaca-roots`, { label: v.label, pem: v.pem, doc_types: v.doc_types }),
    onSuccess: (_, v) => { void refresh(v.orgId); if (currentOrg(v.orgId)) { setUploadOpen(false); setPEM(''); toast.success('Authority added') } },
    onError: (err, v) => { if (currentOrg(v.orgId)) setError(message(err)) },
  })
  const remove = useMutation({
    mutationFn: (v: { orgId: string; id: string }) => api.delete(`/organizations/${v.orgId}/mdoc/iaca-roots/${v.id}`),
    onSuccess: (_, v) => { void refresh(v.orgId); if (currentOrg(v.orgId)) { setDeleting(null); toast.success('Authority removed') } },
    onError: (err, v) => { if (currentOrg(v.orgId)) setError(message(err)) },
  })
  const restore = useMutation({
    mutationFn: async (v: { orgId: string; authorities: Authority[] }) => {
      let imported = 0, existing = 0
      for (const a of v.authorities) {
        try {
          await api.post(`/organizations/${v.orgId}/mdoc/iaca-roots`, { label: a.label, pem: a.pem, doc_types: a.doc_types })
          imported++
        } catch (err) {
          if (isAxiosError(err) && err.response?.status === 409) { existing++; continue }
          return { imported, existing, failed: `${a.label}: ${message(err)}` }
        }
      }
      return { imported, existing, failed: '' }
    },
    onSuccess: (result, v) => {
      void refresh(v.orgId)
      if (!currentOrg(v.orgId)) return
      setImportSummary(`${result.imported} imported; ${result.existing} already registered.`)
      setError(result.failed)
      if (!result.failed) toast.success(`${result.imported} development authorities imported`)
    },
  })
  const busy = upload.isPending || remove.isPending || restore.isPending

  function submit(event: FormEvent) {
    event.preventDefault(); setError('')
    if (!orgId) return
    if (!label.trim()) { setError('Enter a label for this authority.'); return }
    if (/-----BEGIN [^-]*PRIVATE KEY-----/.test(pem) || !pem.trim().startsWith('-----BEGIN CERTIFICATE-----')) {
      setError('Provide a public CA certificate in PEM format. Do not upload a private key.'); return
    }
    if (new TextEncoder().encode(pem).length > 64 * 1024) { setError('The certificate must be smaller than 64 KiB.'); return }
    const docTypes = [...new Set(scope.split(/[\n,]/).map(x => x.trim()).filter(Boolean))]
    if (!allTypes && !docTypes.length) { setError('Specify at least one document type, or explicitly allow all types.'); return }
    upload.mutate({ orgId, label: label.trim(), pem: pem.trim(), doc_types: allTypes ? [] : docTypes })
  }
  async function readCertificate(file?: File) {
    if (!file) return
    const selectedOrg = orgId
    if (file.size > 64 * 1024) { setError('The certificate must be smaller than 64 KiB.'); return }
    const text = await file.text()
    if (useAuthStore.getState().orgId !== selectedOrg) return
    if (!text.trim().startsWith('-----BEGIN CERTIFICATE-----') || /-----BEGIN [^-]*PRIVATE KEY-----/.test(text)) {
      setError('Select a public PEM certificate. Export DER certificates to PEM first; private keys are not accepted.'); return
    }
    setPEM(text); setError('')
  }

  return <section aria-label="mdoc issuer trust" className="space-y-5">
    <Card className="p-5 sm:p-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="max-w-2xl"><h2 className="flex items-center gap-2 text-base font-semibold"><ShieldCheck size={18} /> Issuer authorities</h2>
          <p className="mt-2 text-sm leading-relaxed" style={{ color: 'var(--clavex-neutral)' }}>These CA certificates let this tenant verify mdoc credentials from trusted issuers. They do not make a wallet trust credentials issued by Clavex. SD-JWT issuers and wallet attestations have separate trust settings.</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="secondary" size="sm" disabled={!orgId || busy || rootsQuery.isPending || rootsQuery.isError} onClick={() => { setError(''); setImportSummary(''); setTestConsent(false); setCatalogOpen(true) }}><RefreshCw size={14} /> Reference catalogue</Button>
          <Button size="sm" disabled={!orgId || busy} onClick={() => { setError(''); setLabel(''); setPEM(''); setScope(`${MDL}\n${PID}`); setAllTypes(false); setUploadOpen(true) }}><Plus size={14} /> Add custom CA</Button>
        </div>
      </div>
    </Card>

    {rootsQuery.isPending && orgId ? <Spinner /> : rootsQuery.isError ? <Card className="p-5"><p role="alert">Could not load this tenant's authorities.</p><Button variant="secondary" size="sm" className="mt-3" onClick={() => void rootsQuery.refetch()}>Retry</Button></Card> :
      roots.length === 0 ? <Card className="p-8 text-center"><ShieldCheck size={28} className="mx-auto mb-3" style={{ color: 'var(--clavex-primary)' }} /><h3 className="font-semibold">No mdoc authorities configured</h3><p className="mx-auto mt-2 max-w-lg text-sm" style={{ color: 'var(--clavex-neutral)' }}>Add your own issuer CA or explicitly import development authorities from the reference catalogue. No catalogue is enabled automatically.</p></Card> :
        <Card><ul className="divide-y" style={{ borderColor: 'var(--clavex-border)' }}>{roots.map(root => <li key={root.id} className="p-5 sm:p-6">
          <div className="flex items-start justify-between gap-4"><div className="min-w-0"><h3 className="break-words font-semibold">{root.label}</h3><p className="mt-1 break-words text-xs" style={{ color: 'var(--clavex-neutral)' }}>{root.subject_dn}</p></div>
            <Button variant="ghost" size="sm" aria-label={`Remove ${root.label}`} disabled={busy} onClick={() => { setError(''); setDeleting(root) }}><Trash2 size={15} /><span className="hidden sm:inline">Remove</span></Button></div>
          <div className="mt-3 flex flex-wrap items-center gap-2 text-xs"><span className="rounded-full px-2 py-1" style={{ background: authorityState(root) === 'Configured' ? 'var(--clavex-50)' : '#fff4de' }}>{authorityState(root)}</span>
            {(root.doc_types?.length ? root.doc_types : ['All mdoc document types']).map(kind => <span key={kind} className="max-w-full break-all rounded border px-2 py-1" style={{ borderColor: 'var(--clavex-border)' }}>{scopeName(kind)}</span>)}
            {root.not_after && <span style={{ color: 'var(--clavex-neutral)' }}>Expires <time dateTime={root.not_after}>{new Date(root.not_after).toLocaleDateString()}</time></span>}</div>
          <p className="mt-3 text-xs" style={{ color: 'var(--clavex-neutral)' }}>SHA-256 <code className="break-all">{root.sha256_fingerprint}</code></p>
          {root.certificate_warning && <p role="status" className="mt-2 text-xs" style={{ color: 'var(--clavex-danger)' }}>This stored record contains additional material. Reimport only the public certificate; existing data has not been changed.</p>}
          {root.certificate_error && <p role="status" className="mt-2 text-xs" style={{ color: 'var(--clavex-danger)' }}>The stored certificate needs review before it can be relied on.</p>}
        </li>)}</ul></Card>}

    <TrustDialog open={uploadOpen} title="Add issuer CA" onClose={() => { if (!busy) setUploadOpen(false) }}>
      <form onSubmit={submit} className="space-y-4">
        <div><label htmlFor={formId + '-label'} className="mb-1 block text-sm font-semibold">Label</label><input id={formId + '-label'} className="input-base" value={label} onChange={e => setLabel(e.target.value)} maxLength={200} required /></div>
        <div><label htmlFor={formId + '-file'} className="mb-1 block text-sm font-semibold">Public certificate file</label><input id={formId + '-file'} type="file" accept=".pem,.crt,.cer" className="max-w-full text-sm" onChange={e => { void readCertificate(e.target.files?.[0]).catch(() => setError('The file could not be read.')) }} /></div>
        <div><label htmlFor={formId + '-pem'} className="mb-1 block text-sm font-semibold">Certificate (PEM)</label><textarea id={formId + '-pem'} className="input-base min-h-32 font-mono text-xs" value={pem} onChange={e => setPEM(e.target.value)} required spellCheck={false} placeholder="-----BEGIN CERTIFICATE-----" /><p className="mt-1 text-xs" style={{ color: 'var(--clavex-neutral)' }}>One CA certificate, maximum 64 KiB. No private key or certificate bundle.</p></div>
        <div><label htmlFor={formId + '-scope'} className="mb-1 block text-sm font-semibold">Allowed mdoc document types</label><textarea id={formId + '-scope'} className="input-base font-mono text-xs" value={scope} onChange={e => setScope(e.target.value)} disabled={allTypes} rows={2} /><p className="mt-1 text-xs" style={{ color: 'var(--clavex-neutral)' }}>One document type per line. The scope belongs to this tenant only.</p></div>
        <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={allTypes} onChange={e => setAllTypes(e.target.checked)} className="mt-1" /> Allow this authority for all mdoc document types</label>
        {error && <p role="alert" className="text-sm" style={{ color: 'var(--clavex-danger)' }}>{error}</p>}
        <div className="flex justify-end gap-2"><Button type="button" variant="secondary" onClick={() => setUploadOpen(false)} disabled={busy}>Cancel</Button><Button type="submit" loading={upload.isPending} disabled={busy || !orgId}>Add authority</Button></div>
      </form>
    </TrustDialog>

    <TrustDialog open={catalogOpen} title="EUDI reference development catalogue" onClose={() => { if (!busy) setCatalogOpen(false) }}>
      <div className="mb-4 flex items-start gap-2 rounded-lg border p-3 text-sm" style={{ background: '#fffaf0', borderColor: '#f2d59b' }}><AlertTriangle size={18} className="mt-0.5 shrink-0" /><p>Development/test authorities from the EUDI reference wallet. This is not a production national trust list or a certification. Import only into a tenant intended for tests.</p></div>
      <p className="mb-4 text-sm" style={{ color: 'var(--clavex-neutral)' }}>Import restores missing catalogue entries. Existing authorities retain their scope and active state; custom authorities are preserved.</p>
      {catalogQuery.isPending ? <Spinner /> : catalogQuery.isError ? <div role="alert" className="space-y-3 text-sm"><p>The catalogue could not be loaded. Custom CA management remains available.</p><Button variant="secondary" size="sm" onClick={() => void catalogQuery.refetch()}>Retry catalogue</Button></div> :
        <ul className="divide-y rounded-lg border" style={{ borderColor: 'var(--clavex-border)' }}>{entries.map(a => <li key={a.id} className="p-3">
          <div className="flex flex-wrap items-center justify-between gap-2 text-sm"><strong>{a.label}</strong><span style={{ color: 'var(--clavex-neutral)' }}>{fingerprints.has(a.sha256_fingerprint) ? 'Already registered' : usable(a) ? 'Available to import' : 'Outside validity period'}</span></div>
          <p className="mt-1 text-xs" style={{ color: 'var(--clavex-neutral)' }}>{a.doc_types.map(scopeName).join(' · ')}{a.not_after && ` · Expires ${new Date(a.not_after).toLocaleDateString()}`}</p>
          <code className="mt-2 block break-all text-[11px]" style={{ color: 'var(--clavex-neutral)' }}>{a.sha256_fingerprint}</code>
          <a className="mt-2 inline-flex items-center gap-1 text-xs underline" href={a.source_url} target="_blank" rel="noopener noreferrer">Pinned reference source <ExternalLink size={11} /></a>
        </li>)}</ul>}
      <label className="mt-4 flex items-start gap-2 text-sm"><input type="checkbox" disabled={busy} checked={testConsent} onChange={e => setTestConsent(e.target.checked)} className="mt-1" /> This tenant is intended for development/testing, and I want to trust these authorities for mDL and PID mdoc.</label>
      {importSummary && <p role="status" className="mt-3 text-sm">{importSummary}</p>}
      {error && <p role="alert" className="mt-3 text-sm" style={{ color: 'var(--clavex-danger)' }}>{error}</p>}
      <div className="mt-5 flex flex-wrap justify-end gap-2"><Button variant="secondary" disabled={busy} onClick={() => setCatalogOpen(false)}>Close</Button><Button loading={restore.isPending} disabled={busy || !orgId || !testConsent || !missing.length || rootsQuery.isError || catalogQuery.isError || catalogQuery.isPending} onClick={() => { if (orgId) { setError(''); setImportSummary(''); restore.mutate({ orgId, authorities: missing }) } }}>Import missing authorities ({missing.length})</Button></div>
    </TrustDialog>

    <TrustDialog open={!!deleting} title="Remove issuer authority?" onClose={() => { if (!busy) setDeleting(null) }}>
      <p className="text-sm leading-relaxed">Remove <strong>{deleting?.label}</strong> from this tenant? Verification can fail for credentials that rely on this authority. Other tenants are unaffected.</p>
      {error && <p role="alert" className="mt-3 text-sm" style={{ color: 'var(--clavex-danger)' }}>{error}</p>}
      <div className="mt-5 flex justify-end gap-2"><Button variant="secondary" disabled={busy} onClick={() => setDeleting(null)}>Cancel</Button><Button variant="danger" loading={remove.isPending} disabled={busy || !orgId} onClick={() => { if (orgId && deleting) remove.mutate({ orgId, id: deleting.id }) }}>Remove authority</Button></div>
    </TrustDialog>
  </section>
}
