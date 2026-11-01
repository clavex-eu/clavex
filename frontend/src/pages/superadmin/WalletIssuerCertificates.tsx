import { useId, useState, type FormEvent } from 'react'
import { Dialog, DialogBackdrop, DialogPanel, DialogTitle } from '@headlessui/react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import { KeyRound, Plus, RefreshCw, Trash2, X } from 'lucide-react'
import api from '@/lib/api'
import { Button, Card } from '@/components/ui'
import { useAuthStore } from '@/stores/auth'

interface Issuer {
  id: string; display_name: string; doc_type: string; key_backend: string
  vault_signer_ref?: string; not_after?: string; sha256_fingerprint?: string
  certificate_error: boolean; is_active: boolean
}
interface Profile { id: string; label: string; version: number }
const MDL = 'org.iso.18013.5.1.mDL'
const PID = 'eu.europa.ec.eudi.pid.1'
const input = 'w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm focus-visible:outline-2'
const errorMessage = (error: unknown) => isAxiosError<{ message?: string }>(error) && typeof error.response?.data?.message === 'string'
  ? error.response.data.message.slice(0, 300) : 'Unable to save the signing configuration. Check the certificate and backend.'

function CertificateForm({ orgId, issuers, onClose }: { orgId: string; issuers: Issuer[]; onClose: () => void }) {
  const id = useId()
  const cache = useQueryClient()
  const [name, setName] = useState('')
  const [docType, setDocType] = useState(MDL)
  const [backend, setBackend] = useState('local')
  const [profile, setProfile] = useState('')
  const [cert, setCert] = useState('')
  const [ca, setCA] = useState('')
  const [key, setKey] = useState<File | null>(null)
  const [hours, setHours] = useState(720)
  const [replace, setReplace] = useState(false)
  const [error, setError] = useState('')
  const profiles = useQuery({ queryKey: ['wallet-vault-profiles', orgId], queryFn: () => api.get<Profile[]>(`/superadmin/organizations/${orgId}/mdoc/vault-signers`).then(r => r.data) })
  const existing = issuers.find(i => i.doc_type === docType.trim() && i.is_active)
  const save = useMutation({
    mutationFn: async () => {
      if (!useAuthStore.getState().isSuperAdmin) throw new Error('Superadmin access required')
      let privateKey = ''
      if (backend === 'local') {
        if (!key || key.size > 64 * 1024) throw new Error('Select one PEM private key, at most 64 KiB.')
        privateKey = await key.text()
        if (!/^\s*-----BEGIN (EC )?PRIVATE KEY-----/.test(privateKey)) throw new Error('Select an unencrypted PKCS#8 or EC PEM private key.')
      }
      if (!useAuthStore.getState().isSuperAdmin) throw new Error('Superadmin access required')
      return api.post(`/superadmin/organizations/${orgId}/mdoc/issuers`, {
        display_name: name.trim(), doc_type: docType.trim(), ds_certificate_pem: cert.trim(),
        iaca_certificate_pem: ca.trim(), validity_hours: hours,
        ...(backend === 'local' ? { ds_private_key_pem: privateKey } : { vault_signer_ref: profile }),
        replace_existing: !!existing && replace,
      })
    },
    onSuccess: () => { cache.invalidateQueries({ queryKey: ['wallet-mdoc-issuers', orgId] }); onClose() },
    onError: (e) => setError(isAxiosError(e) ? errorMessage(e) : e instanceof Error ? e.message : 'Unable to read signing material'),
  })
  const submit = (e: FormEvent) => { e.preventDefault(); setError(''); save.mutate() }
  return <form onSubmit={submit} className="space-y-4">
    <p className="text-sm text-slate-600">Configure a Document Signer for mdoc issuance. The receiving wallet must independently trust its IACA. Importing a certificate does not grant national issuer status.</p>
    <label className="block text-sm" htmlFor={`${id}-name`}>Display name<input id={`${id}-name`} className={input} required maxLength={200} value={name} onChange={e => setName(e.target.value)} /></label>
    <label className="block text-sm" htmlFor={`${id}-type`}>Document type<input id={`${id}-type`} list={`${id}-types`} className={input} required maxLength={512} value={docType} onChange={e => { setDocType(e.target.value); setReplace(false) }} /><datalist id={`${id}-types`}><option value={MDL}>mDL mdoc</option><option value={PID}>PID mdoc</option></datalist></label>
    <label className="block text-sm" htmlFor={`${id}-backend`}>Signing backend<select aria-label="Signing backend" id={`${id}-backend`} className={input} value={backend} onChange={e => { setBackend(e.target.value); setKey(null) }}><option value="local">Encrypted local key</option><option value="vault">Vault Transit — non-exportable key</option></select></label>
    {backend === 'vault' ? <label className="block text-sm" htmlFor={`${id}-profile`}>Authorised Vault key<select aria-label="Authorised Vault key" id={`${id}-profile`} className={input} required value={profile} onChange={e => setProfile(e.target.value)}><option value="">Select a key</option>{profiles.data?.map(p => <option key={p.id} value={p.id}>{p.label || p.id} · version {p.version}</option>)}</select><span className="mt-1 block text-xs text-slate-600">{profiles.isError ? 'Unable to load authorised keys.' : !profiles.data?.length ? 'No key is available. Ask the installation administrator to authorise a Vault profile for this tenant.' : 'The private key stays in Vault. The certificate must match the selected key version.'}</span></label>
      : <label className="block text-sm" htmlFor={`${id}-key`}>Private key (PEM)<input aria-label="Private key (PEM)" id={`${id}-key`} className={input} type="file" accept=".pem,.key" required onChange={e => setKey(e.target.files?.[0] ?? null)} /><span className="mt-1 block text-xs text-slate-600">Sent only when you save, then encrypted in the database. It is never returned by the API.</span></label>}
    <label className="block text-sm" htmlFor={`${id}-cert`}>DS certificate (PEM)<textarea id={`${id}-cert`} className={`${input} font-mono`} rows={5} required maxLength={262144} value={cert} onChange={e => setCert(e.target.value)} spellCheck={false} /></label>
    <label className="block text-sm" htmlFor={`${id}-ca`}>IACA chain (PEM, root last)<textarea id={`${id}-ca`} className={`${input} font-mono`} rows={4} required maxLength={262144} value={ca} onChange={e => setCA(e.target.value)} spellCheck={false} /></label>
    <label className="block text-sm" htmlFor={`${id}-hours`}>Credential validity (hours)<input id={`${id}-hours`} className={input} type="number" min={1} max={8760} required value={hours} onChange={e => setHours(Number(e.target.value))} /></label>
    {existing && <label className="flex items-start gap-2 rounded-lg bg-amber-50 p-3 text-sm"><input type="checkbox" checked={replace} onChange={e => setReplace(e.target.checked)} />Replace the active signer “{existing.display_name}” for this document type. Existing credentials are not reissued or revoked; wallets must also trust the replacement chain.</label>}
    {error && <p role="alert" className="text-sm text-red-700">{error}</p>}
    <div className="flex flex-wrap justify-end gap-3"><Button type="button" variant="secondary" disabled={save.isPending} onClick={onClose}>Cancel</Button><Button type="submit" disabled={save.isPending || (!!existing && !replace) || (backend === 'vault' && (!profile || profiles.isError))}>{save.isPending ? 'Checking and saving…' : 'Save signing configuration'}</Button></div>
  </form>
}

export default function WalletIssuerCertificates({ orgId }: { orgId: string | null }) {
  const [open, setOpen] = useState(false)
  const [removing, setRemoving] = useState<Issuer | null>(null)
  const cache = useQueryClient()
  const issuers = useQuery({ queryKey: ['wallet-mdoc-issuers', orgId], queryFn: () => api.get<Issuer[]>(`/superadmin/organizations/${orgId}/mdoc/issuers`).then(r => r.data), enabled: !!orgId })
  const deletion = useMutation({ mutationFn: (issuer: Issuer) => api.delete(`/superadmin/organizations/${orgId}/mdoc/issuers/${issuer.id}`), onSuccess: () => { setRemoving(null); cache.invalidateQueries({ queryKey: ['wallet-mdoc-issuers', orgId] }) } })
  if (!orgId) return null
  return <Card><div className="flex flex-wrap items-start justify-between gap-4"><div><h2 className="flex items-center gap-2 font-semibold"><KeyRound size={18} /> Issuing certificates · mdoc</h2><p className="mt-1 text-sm text-slate-600">Configure your signing material here. Verifier trust anchors are managed separately in Wallet verifier → Issuer trust.</p></div><Button onClick={() => setOpen(true)}><Plus size={15} /> Add signer</Button></div>
    <p className="mt-3 text-xs text-slate-600">Metadata and SD-JWT signing certificates currently use installation configuration. Vault PKI certificate issuance and renewal are separate from Transit signing.</p>
    {issuers.isPending && <p className="mt-4 text-sm">Loading signing certificates…</p>}
    {issuers.isError && <div role="alert" className="mt-4 flex items-center gap-3 text-sm text-red-700">Unable to load signing certificates.<Button variant="secondary" onClick={() => issuers.refetch()}><RefreshCw size={14} /> Retry</Button></div>}
    {issuers.isSuccess && !issuers.data.length && <p className="mt-4 text-sm text-slate-600">No mdoc signer configured for this tenant.</p>}
    <ul className="mt-4 space-y-3">{issuers.data?.map(issuer => <li key={issuer.id} className="rounded-lg border border-slate-200 p-3"><div className="flex items-start justify-between gap-3"><div className="min-w-0"><h3 className="font-medium break-words">{issuer.display_name}</h3><p className="break-all text-xs text-slate-600">{issuer.doc_type}</p></div><Button variant="secondary" aria-label={`Remove ${issuer.display_name}`} onClick={() => setRemoving(issuer)}><Trash2 size={15} /></Button></div><p className="mt-2 text-xs">{issuer.key_backend === 'vault_transit' ? `Vault Transit · ${issuer.vault_signer_ref}` : 'Local key'} · {issuer.certificate_error ? 'Certificate needs review' : `Expires ${issuer.not_after ? new Date(issuer.not_after).toLocaleDateString() : 'unknown'}`}</p>{issuer.sha256_fingerprint && <p className="mt-1 break-all font-mono text-[11px] text-slate-500">SHA-256 {issuer.sha256_fingerprint}</p>}</li>)}</ul>
    <Dialog open={open || !!removing} onClose={() => { if (!deletion.isPending) { setOpen(false); setRemoving(null) } }} className="fixed inset-0 z-50"><DialogBackdrop className="fixed inset-0 bg-black/30" /><div className="fixed inset-0 overflow-y-auto p-4 sm:p-8"><div className="flex min-h-full items-center justify-center"><DialogPanel className="w-full max-w-2xl rounded-2xl bg-white p-5 shadow-xl sm:p-7"><div className="mb-4 flex items-center justify-between gap-3"><DialogTitle className="font-semibold">{removing ? 'Remove mdoc signer?' : 'Configure mdoc signer'}</DialogTitle><button type="button" aria-label="Close dialogue" onClick={() => { setOpen(false); setRemoving(null) }}><X size={20} /></button></div>{removing ? <div className="space-y-4"><p className="text-sm">Future issuance of {removing.doc_type} will fail until another signer is configured. Existing credentials are not revoked.</p>{deletion.isError && <p role="alert" className="text-sm text-red-700">Unable to remove the signer.</p>}<div className="flex justify-end gap-3"><Button variant="secondary" onClick={() => setRemoving(null)}>Cancel</Button><Button disabled={deletion.isPending} onClick={() => deletion.mutate(removing)}>Remove signer</Button></div></div> : <CertificateForm key={orgId} orgId={orgId} issuers={issuers.data ?? []} onClose={() => setOpen(false)} />}</DialogPanel></div></div></Dialog>
  </Card>
}
