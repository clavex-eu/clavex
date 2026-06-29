import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import { LayoutTemplate, RotateCcw } from 'lucide-react'
import { Button, Card, PageHeader, Spinner, AlertBanner, Badge } from '@/components/ui'

interface LoginTemplateInfo {
  has_custom_template: boolean
  preview?: string
}

export default function LoginTemplatePage() {
  const orgId = useAuthStore((s) => s.orgId)
  const qc = useQueryClient()
  const [html, setHtml] = useState('')
  const [isDirty, setIsDirty] = useState(false)

  const { data, isLoading } = useQuery<LoginTemplateInfo>({
    queryKey: ['login-template', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/login-template`).then((r) => r.data),
    enabled: !!orgId,
  })

  // Load the raw template so the editor shows the full content
  const { data: rawData, isLoading: rawLoading } = useQuery<string>({
    queryKey: ['login-template-raw', orgId],
    queryFn: () =>
      api
        .get(`/organizations/${orgId}/login-template/raw`, { responseType: 'text' })
        .then((r) => r.data as string)
        .catch(() => ''),
    enabled: !!orgId && !!data?.has_custom_template,
  })

  useEffect(() => {
    if (rawData !== undefined && !isDirty) setHtml(rawData)
  }, [rawData])

  useEffect(() => {
    if (data && !data.has_custom_template && !isDirty) setHtml('')
  }, [data])

  const save = useMutation({
    mutationFn: (body: { html: string }) =>
      api.put(`/organizations/${orgId}/login-template`, body).then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['login-template', orgId] })
      qc.invalidateQueries({ queryKey: ['login-template-raw', orgId] })
      toast.success('Login template saved')
      setIsDirty(false)
    },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: string } })?.response?.data ?? 'Failed to save template'
      toast.error(typeof msg === 'string' ? msg : 'Failed to save template')
    },
  })

  const remove = useMutation({
    mutationFn: () => api.delete(`/organizations/${orgId}/login-template`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['login-template', orgId] })
      qc.invalidateQueries({ queryKey: ['login-template-raw', orgId] })
      toast.success('Reverted to built-in login page')
      setHtml('')
      setIsDirty(false)
    },
    onError: () => toast.error('Failed to revert template'),
  })

  if (isLoading) return <Spinner />

  return (
    <div className="space-y-6">
      <PageHeader
        title="Custom Login Template"
        subtitle="Replace the built-in login page with a fully custom Go html/template."
        action={
          data?.has_custom_template ? (
            <Badge variant="green">Custom template active</Badge>
          ) : (
            <Badge variant="gray">Using built-in login page</Badge>
          )
        }
      />

      <AlertBanner variant="warning">
        The template is rendered with Go's <code>html/template</code> engine. Syntax errors will
        be caught on save. A broken template will fall back to the built-in login page automatically.
      </AlertBanner>

      <Card className="p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <LayoutTemplate size={18} style={{ color: 'var(--clavex-accent, #5DCAA5)' }} />
            <p className="text-sm font-semibold">HTML template</p>
          </div>
          <div className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--clavex-ink-subtle)' }}>
            {html.length.toLocaleString()} chars
            {html.length > 256 * 1024 && (
              <span className="text-red-500 ml-1">· exceeds 256 KB limit</span>
            )}
          </div>
        </div>

        <textarea
          className="w-full rounded-lg px-4 py-3 font-mono text-xs resize-y outline-none"
          style={{
            minHeight: 360,
            border: '0.5px solid var(--clavex-border)',
            background: 'var(--clavex-dark, #0D1F2D)',
            color: '#C4DFF0',
            lineHeight: 1.6,
          }}
          placeholder={`<!DOCTYPE html>\n<html>\n<head><title>Sign in</title></head>\n<body>\n  <!-- Use {{.Error}} {{.FormAction}} template variables -->\n</body>\n</html>`}
          value={rawLoading && !isDirty ? '⏳ Loading…' : html}
          onChange={(e) => { setHtml(e.target.value); setIsDirty(true) }}
          spellCheck={false}
        />

        <div className="flex items-center justify-between pt-1">
          {data?.has_custom_template && (
            <Button
              variant="danger"
              size="sm"
              onClick={() => { if (confirm('Revert to the built-in login page?')) remove.mutate() }}
              loading={remove.isPending}
            >
              <RotateCcw size={14} /> Revert to default
            </Button>
          )}
          {!data?.has_custom_template && <span />}
          <Button
            onClick={() => save.mutate({ html })}
            loading={save.isPending}
            disabled={!isDirty && html === ''}
          >
            Save template
          </Button>
        </div>
      </Card>

      <Card className="p-5">
        <p className="text-xs font-semibold uppercase tracking-wide mb-3" style={{ color: 'var(--clavex-ink-subtle)' }}>
          Available template variables
        </p>
        <div className="grid grid-cols-2 gap-x-6 gap-y-1 text-xs font-mono">
          {[
            ['{{.FormAction}}', 'POST URL for the form'],
            ['{{.Error}}', 'Login error message (empty if none)'],
            ['{{.OrgName}}', 'Organization display name'],
            ['{{.OrgSlug}}', 'Organization URL slug'],
            ['{{.LogoURL}}', 'Branded logo URL (may be empty)'],
            ['{{.PrimaryColor}}', 'Branded primary color hex'],
            ['{{.ClientName}}', 'Requesting application name'],
            ['{{.RelayState}}', 'Hidden relay state field value'],
          ].map(([v, desc]) => (
            <div key={v} className="flex gap-3 py-1" style={{ borderBottom: '0.5px solid var(--clavex-border)' }}>
              <span style={{ color: 'var(--clavex-primary)' }}>{v}</span>
              <span style={{ color: 'var(--clavex-ink-subtle)' }}>{desc}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  )
}
