import { useState, useEffect } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { Eye } from 'lucide-react'
import toast from 'react-hot-toast'
import api from '@/lib/api'
import { Button, Input, Card, PageHeader, Spinner } from '@/components/ui'

interface Branding {
  org_id: string
  company_name?: string
  logo_url?: string
  favicon_url?: string
  primary_color: string
  bg_color: string
  text_color: string
  welcome_title: string
  welcome_subtitle?: string
  custom_css?: string
}

interface Props {
  orgId: string
  breadcrumb?: React.ReactNode
}

export default function BrandingPage({ orgId, breadcrumb }: Props) {
  const [form, setForm] = useState<Branding | null>(null)
  const [preview, setPreview] = useState(false)

  const { data, isLoading } = useQuery<Branding>({
    queryKey: ['branding', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/branding`).then((r) => r.data),
  })

  useEffect(() => {
    if (data && !form) setForm(data)
  }, [data])

  const save = useMutation({
    mutationFn: (body: Branding) => api.put(`/organizations/${orgId}/branding`, body),
    onSuccess: (res) => {
      setForm(res.data)
      toast.success('Branding saved')
    },
    onError: () => toast.error('Failed to save branding'),
  })

  if (isLoading || !form) return <Spinner />

  const set = (key: keyof Branding, value: string) =>
    setForm((prev) => prev ? { ...prev, [key]: value || undefined } : prev)

  return (
    <div>
      {breadcrumb}
      <PageHeader
        title="Login Page Branding"
        action={
          <div className="flex gap-2">
            <Button variant="secondary" onClick={() => setPreview(!preview)}>
              <Eye className="h-4 w-4" />
              {preview ? 'Hide preview' : 'Preview'}
            </Button>
            <Button onClick={() => save.mutate(form!)} disabled={save.isPending}>
              {save.isPending ? 'Saving…' : 'Save changes'}
            </Button>
          </div>
        }
      />

      <div className={`flex gap-6 ${preview ? 'items-start' : ''}`}>
        {/* Form */}
        <Card className="flex-1 p-6 space-y-6">
          {/* Brand identity */}
          <section>
            <h3 className="text-sm font-semibold text-gray-700 mb-3">Brand identity</h3>
            <div className="space-y-3">
              <Input
                label="Company name"
                value={form.company_name ?? ''}
                onChange={(e) => set('company_name', e.target.value)}
                placeholder="Acme Corp"
              />
              <Input
                label="Logo URL"
                value={form.logo_url ?? ''}
                onChange={(e) => set('logo_url', e.target.value)}
                placeholder="https://cdn.example.com/logo.svg"
              />
              <Input
                label="Favicon URL"
                value={form.favicon_url ?? ''}
                onChange={(e) => set('favicon_url', e.target.value)}
                placeholder="https://cdn.example.com/favicon.ico"
              />
            </div>
          </section>

          {/* Content */}
          <section>
            <h3 className="text-sm font-semibold text-gray-700 mb-3">Login page content</h3>
            <div className="space-y-3">
              <Input
                label="Welcome title"
                value={form.welcome_title}
                onChange={(e) => setForm((f) => f ? { ...f, welcome_title: e.target.value } : f)}
                required
              />
              <Input
                label="Welcome subtitle"
                value={form.welcome_subtitle ?? ''}
                onChange={(e) => set('welcome_subtitle', e.target.value)}
                placeholder="Sign in to your account"
              />
            </div>
          </section>

          {/* Colors */}
          <section>
            <h3 className="text-sm font-semibold text-gray-700 mb-3">Colors</h3>
            <div className="grid grid-cols-3 gap-4">
              {(
                [
                  { key: 'primary_color', label: 'Primary' },
                  { key: 'bg_color',      label: 'Background' },
                  { key: 'text_color',    label: 'Text' },
                ] as const
              ).map(({ key, label }) => (
                <div key={key}>
                  <label className="block text-xs font-medium text-gray-600 mb-1">{label}</label>
                  <div className="flex items-center gap-2">
                    <input
                      type="color"
                      value={form[key]}
                      onChange={(e) => setForm((f) => f ? { ...f, [key]: e.target.value } : f)}
                      className="h-9 w-10 rounded cursor-pointer border border-gray-300 p-0.5"
                    />
                    <input
                      type="text"
                      value={form[key]}
                      onChange={(e) => setForm((f) => f ? { ...f, [key]: e.target.value } : f)}
                      className="flex-1 rounded-lg border border-gray-300 px-2 py-1.5 text-xs font-mono focus:ring-1 focus:ring-indigo-500 focus:outline-none"
                    />
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* Custom CSS */}
          <section>
            <h3 className="text-sm font-semibold text-gray-700 mb-2">Custom CSS <span className="text-gray-400 font-normal text-xs">(optional)</span></h3>
            <textarea
              value={form.custom_css ?? ''}
              onChange={(e) => set('custom_css', e.target.value)}
              rows={6}
              className="w-full rounded-lg border border-gray-300 px-3 py-2 text-xs font-mono focus:ring-2 focus:ring-indigo-500 focus:outline-none"
              placeholder=".login-card { border-radius: 24px; }"
            />
          </section>
        </Card>

        {/* Live preview */}
        {preview && (
          <div className="w-80 flex-shrink-0">
            <p className="text-xs font-medium text-gray-500 mb-2">Preview</p>
            <div
              className="w-full rounded-xl overflow-hidden shadow-sm border border-gray-200"
              style={{ backgroundColor: form.bg_color, color: form.text_color }}
            >
              <div className="p-6">
                {form.logo_url && (
                  <img src={form.logo_url} alt="logo" className="h-8 mb-4 object-contain" />
                )}
                <h2 className="text-lg font-bold" style={{ color: form.text_color }}>
                  {form.welcome_title || 'Sign in'}
                </h2>
                {form.welcome_subtitle && (
                  <p className="text-sm mt-0.5 opacity-70">{form.welcome_subtitle}</p>
                )}
                <div className="mt-4 space-y-3">
                  <input
                    readOnly
                    className="w-full rounded-lg border border-gray-200 px-3 py-2 text-sm"
                    placeholder="Email"
                  />
                  <input
                    readOnly
                    type="password"
                    className="w-full rounded-lg border border-gray-200 px-3 py-2 text-sm"
                    placeholder="Password"
                  />
                  <button
                    className="w-full rounded-lg px-4 py-2 text-sm font-semibold text-white"
                    style={{ backgroundColor: form.primary_color }}
                  >
                    Sign in
                  </button>
                </div>
              </div>
              {form.custom_css && <style>{form.custom_css}</style>}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
