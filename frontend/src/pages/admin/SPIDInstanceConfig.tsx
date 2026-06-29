import { useState, useEffect } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { Download, ShieldCheck } from 'lucide-react'
import toast from 'react-hot-toast'
import api from '@/lib/api'
import { Button, Input, Select, Card, PageHeader, Spinner } from '@/components/ui'

interface SPIDInstanceConfig {
  id: string
  entity_id: string
  org_name: string
  org_display_name: string
  org_locality: string
  org_url: string
  contact_email: string
  contact_phone?: string
  vat_number?: string
  ipa_code?: string
  entity_type: 'private' | 'public'
  created_at?: string
  updated_at?: string
}

type FormState = Omit<SPIDInstanceConfig, 'id' | 'created_at' | 'updated_at'>

const DEFAULT_FORM: FormState = {
  entity_id: '',
  org_name: '',
  org_display_name: '',
  org_locality: '',
  org_url: '',
  contact_email: '',
  contact_phone: '',
  vat_number: '',
  ipa_code: '',
  entity_type: 'private',
}

export default function SPIDInstanceConfigPage() {
  const [form, setForm] = useState<FormState>(DEFAULT_FORM)
  const [isNew, setIsNew] = useState(false)

  const { data, isLoading } = useQuery<SPIDInstanceConfig>({
    queryKey: ['spid-instance-config'],
    queryFn: async () => {
      try {
        const r = await api.get('/admin/spid/instance-config')
        return r.data
      } catch (err: any) {
        if (err?.response?.status === 404) {
          setIsNew(true)
          return null
        }
        throw err
      }
    },
    retry: false,
  })

  useEffect(() => {
    if (data) {
      setForm({
        entity_id: data.entity_id,
        org_name: data.org_name,
        org_display_name: data.org_display_name,
        org_locality: data.org_locality,
        org_url: data.org_url,
        contact_email: data.contact_email,
        contact_phone: data.contact_phone ?? '',
        vat_number: data.vat_number ?? '',
        ipa_code: data.ipa_code ?? '',
        entity_type: data.entity_type,
      })
      setIsNew(false)
    }
  }, [data])

  const save = useMutation({
    mutationFn: (body: FormState) => {
      const payload = {
        ...body,
        contact_phone: body.contact_phone || undefined,
        vat_number: body.vat_number || undefined,
        ipa_code: body.ipa_code || undefined,
      }
      return api.put('/admin/spid/instance-config', payload)
    },
    onSuccess: (res) => {
      const saved: SPIDInstanceConfig = res.data
      setForm({
        entity_id: saved.entity_id,
        org_name: saved.org_name,
        org_display_name: saved.org_display_name,
        org_locality: saved.org_locality,
        org_url: saved.org_url,
        contact_email: saved.contact_email,
        contact_phone: saved.contact_phone ?? '',
        vat_number: saved.vat_number ?? '',
        ipa_code: saved.ipa_code ?? '',
        entity_type: saved.entity_type,
      })
      setIsNew(false)
      toast.success(isNew ? 'SPID instance configured' : 'SPID instance config saved')
    },
    onError: () => toast.error('Failed to save SPID instance configuration'),
  })

  const downloadMetadata = async () => {
    try {
      const res = await api.get('/admin/spid/metadata', { responseType: 'blob' })
      const url = window.URL.createObjectURL(new Blob([res.data], { type: 'application/xml' }))
      const a = document.createElement('a')
      a.href = url
      a.download = 'spid-metadata.xml'
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      window.URL.revokeObjectURL(url)
    } catch {
      toast.error('Failed to download SP metadata')
    }
  }

  const set = <K extends keyof FormState>(key: K, value: FormState[K]) =>
    setForm((prev) => ({ ...prev, [key]: value }))

  if (isLoading) return <Spinner />

  return (
    <div>
      <PageHeader
        title="SPID Service Provider"
        subtitle="Instance-level SP identity and signing certificate — submitted to AgID for accreditation"
        action={
          <div className="flex gap-2">
            {!isNew && (
              <Button variant="secondary" onClick={downloadMetadata}>
                <Download className="h-4 w-4" />
                Download Metadata
              </Button>
            )}
            <Button onClick={() => save.mutate(form)} disabled={save.isPending}>
              {save.isPending ? 'Saving…' : isNew ? 'Configure SP' : 'Save changes'}
            </Button>
          </div>
        }
      />

      {isNew && (
        <div className="mb-6 rounded-lg border border-blue-200 bg-blue-50 px-4 py-3 text-sm text-blue-800">
          No SPID SP configured for this instance. Fill in the form and click <strong>Configure SP</strong> — a signing certificate will be auto-generated. This configuration is shared by all organizations.
        </div>
      )}

      <div className="space-y-6">
        <Card className="p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-gray-700">SP Identity</h3>
            {!isNew && (
              <div className="flex items-center gap-2 text-xs text-gray-500">
                <ShieldCheck className="h-4 w-4 text-green-500" />
                Signing certificate auto-generated
              </div>
            )}
          </div>
          <Input
            label="Entity ID (SP URI)"
            value={form.entity_id}
            onChange={(e) => set('entity_id', e.target.value)}
            placeholder="https://myapp.example.com/spid"
            required
          />
          <div className="grid grid-cols-2 gap-4">
            <Input
              label="Organization name"
              value={form.org_name}
              onChange={(e) => set('org_name', e.target.value)}
              placeholder="Acme S.r.l."
              required
            />
            <Input
              label="Organization display name"
              value={form.org_display_name}
              onChange={(e) => set('org_display_name', e.target.value)}
              placeholder="Acme"
              required
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <Input
              label="Locality (città)"
              value={form.org_locality}
              onChange={(e) => set('org_locality', e.target.value)}
              placeholder="Roma"
              required
            />
            <Input
              label="Organization URL"
              value={form.org_url}
              onChange={(e) => set('org_url', e.target.value)}
              placeholder="https://www.example.com"
              required
            />
          </div>
        </Card>

        <Card className="p-6 space-y-4">
          <h3 className="text-sm font-semibold text-gray-700">Contact & Legal</h3>
          <div className="grid grid-cols-2 gap-4">
            <Input
              label="Contact email"
              type="email"
              value={form.contact_email}
              onChange={(e) => set('contact_email', e.target.value)}
              placeholder="admin@example.com"
              required
            />
            <Input
              label="Contact phone"
              value={form.contact_phone ?? ''}
              onChange={(e) => set('contact_phone', e.target.value)}
              placeholder="+39 02 1234567"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <Select
              label="Entity type"
              value={form.entity_type}
              onChange={(e) => set('entity_type', e.target.value as 'private' | 'public')}
            >
              <option value="private">Private</option>
              <option value="public">Public Administration</option>
            </Select>

            {form.entity_type === 'private' ? (
              <Input
                label="VAT number (P.IVA)"
                value={form.vat_number ?? ''}
                onChange={(e) => set('vat_number', e.target.value)}
                placeholder="IT01234567890"
              />
            ) : (
              <Input
                label="IPA code"
                value={form.ipa_code ?? ''}
                onChange={(e) => set('ipa_code', e.target.value)}
                placeholder="c_h501"
              />
            )}
          </div>
        </Card>

        <Card className="p-6">
          <h3 className="text-sm font-semibold text-gray-700 mb-2">Metadata URL</h3>
          <p className="text-sm text-gray-500">
            Submit this URL to AgID during SP accreditation:
          </p>
          <code className="mt-2 block rounded bg-gray-50 px-3 py-2 text-sm text-gray-800 border border-gray-200">
            {window.location.origin}/spid/metadata
          </code>
        </Card>
      </div>
    </div>
  )
}
