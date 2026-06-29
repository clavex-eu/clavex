import { useState, useEffect } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import api from '@/lib/api'
import { Button, Select, Card, PageHeader, Spinner, Badge } from '@/components/ui'
import { useAuthStore } from '@/stores/auth'

interface SPIDConfig {
  org_id: string
  authn_level: number
  attribute_set: string[]
  is_active: boolean
  created_at?: string
  updated_at?: string
}

type FormState = Pick<SPIDConfig, 'authn_level' | 'attribute_set' | 'is_active'>

const ATTR_PRESETS: Record<string, string[]> = {
  minimo: ['spidCode', 'name', 'familyName', 'fiscalNumber'],
  base: ['spidCode', 'name', 'familyName', 'fiscalNumber', 'email', 'mobilePhone', 'address', 'dateOfBirth', 'placeOfBirth', 'gender'],
  full: [
    'spidCode', 'name', 'familyName', 'fiscalNumber', 'email', 'mobilePhone',
    'address', 'dateOfBirth', 'placeOfBirth', 'gender',
    'domicileAddress', 'registeredOffice', 'ivaCode', 'idCard', 'expirationDate', 'digitalAddress',
  ],
}

function detectPreset(attrs: string[]): string {
  const sorted = [...attrs].sort().join(',')
  for (const [name, preset] of Object.entries(ATTR_PRESETS)) {
    if ([...preset].sort().join(',') === sorted) return name
  }
  return 'custom'
}

const DEFAULT_FORM: FormState = {
  authn_level: 2,
  attribute_set: ATTR_PRESETS.minimo,
  is_active: true,
}

export default function SPIDConfigPage() {
  const orgId = useAuthStore((s) => s.orgId)!
  const [form, setForm] = useState<FormState>(DEFAULT_FORM)
  const [isNew, setIsNew] = useState(false)

  const { data, isLoading } = useQuery<SPIDConfig>({
    queryKey: ['spid-config', orgId],
    queryFn: async () => {
      try {
        const r = await api.get(`/organizations/${orgId}/spid/config`)
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
        authn_level: data.authn_level,
        attribute_set: data.attribute_set,
        is_active: data.is_active,
      })
      setIsNew(false)
    }
  }, [data])

  const save = useMutation({
    mutationFn: (body: FormState) => api.put(`/organizations/${orgId}/spid/config`, body),
    onSuccess: (res) => {
      const saved: SPIDConfig = res.data
      setForm({
        authn_level: saved.authn_level,
        attribute_set: saved.attribute_set,
        is_active: saved.is_active,
      })
      setIsNew(false)
      toast.success(isNew ? 'SPID configuration created' : 'SPID configuration saved')
    },
    onError: () => toast.error('Failed to save SPID configuration'),
  })

  const set = <K extends keyof FormState>(key: K, value: FormState[K]) =>
    setForm((prev) => ({ ...prev, [key]: value }))

  if (isLoading) return <Spinner />

  const preset = detectPreset(form.attribute_set)

  return (
    <div>
      <PageHeader
        title="SPID"
        subtitle="Authentication preferences for this organization"
        action={
          <Button onClick={() => save.mutate(form)} disabled={save.isPending}>
            {save.isPending ? 'Saving…' : isNew ? 'Enable SPID' : 'Save changes'}
          </Button>
        }
      />

      {isNew && (
        <div className="mb-6 rounded-lg border border-blue-200 bg-blue-50 px-4 py-3 text-sm text-blue-800">
          SPID not yet configured for this organization. The instance-level SP identity and signing certificate are managed globally by the platform administrator.
        </div>
      )}

      <div className="space-y-6">
        <Card className="p-6 space-y-4">
          <h3 className="text-sm font-semibold text-gray-700">Authentication</h3>
          <Select
            label="SPID authentication level"
            value={String(form.authn_level)}
            onChange={(e) => set('authn_level', Number(e.target.value))}
          >
            <option value="1">Level 1 — username + password</option>
            <option value="2">Level 2 — username + password + OTP (recommended)</option>
            <option value="3">Level 3 — hardware token / smart card</option>
          </Select>

          <div>
            <Select
              label="Requested attribute set"
              value={preset}
              onChange={(e) => {
                const v = e.target.value
                if (v !== 'custom') set('attribute_set', ATTR_PRESETS[v])
              }}
            >
              <option value="minimo">Minimo — SPID code + fiscal number</option>
              <option value="base">Base — + email, phone, address, date of birth</option>
              <option value="full">Full — all SPID attributes</option>
              {preset === 'custom' && <option value="custom">Custom</option>}
            </Select>
            <p className="mt-1 text-xs text-gray-400">{form.attribute_set.join(', ')}</p>
          </div>
        </Card>

        <Card className="p-6">
          <h3 className="text-sm font-semibold text-gray-700 mb-3">Status</h3>
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={form.is_active}
              onChange={(e) => set('is_active', e.target.checked)}
              className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
            />
            <div>
              <span className="text-sm font-medium text-gray-700">Active</span>
              <p className="text-xs text-gray-400">
                When disabled, SPID login is not offered to users of this organization.
              </p>
            </div>
            {!isNew && (
              <Badge variant={form.is_active ? 'green' : 'gray'} className="ml-auto">
                {form.is_active ? 'Active' : 'Disabled'}
              </Badge>
            )}
          </label>
        </Card>
      </div>
    </div>
  )
}
