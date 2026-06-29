import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/auth'
import api from '@/lib/api'
import toast from 'react-hot-toast'
import { Plus, Trash2, ToggleLeft, ToggleRight, ChevronDown, ChevronUp } from 'lucide-react'
import { Badge, Button, Card, Input, Modal, PageHeader, Select, Spinner } from '@/components/ui'
import { toArr } from '@/lib/api'

const SINK_TYPES = [
  { value: 'webhook',     label: 'Webhook (POST JSON)' },
  { value: 'http',        label: 'HTTP (raw)' },
  { value: 'mqtt',        label: 'MQTT' },
  { value: 'kafka',       label: 'Apache Kafka' },
  { value: 'splunk_hec',  label: 'Splunk HEC' },
  { value: 'sentinel',    label: 'Microsoft Sentinel' },
  { value: 'elastic_ecs', label: 'Elastic ECS' },
]

interface AuditSink {
  id: string
  org_id: string
  name: string
  sink_type: string
  is_active: boolean
  config: Record<string, unknown>
  filter_actions?: string[]
  filter_statuses?: string[]
  last_success_at?: string
  last_error_at?: string
  last_error_msg?: string
  success_count: number
  failure_count: number
  created_at: string
  updated_at: string
}

interface SinkFormState {
  name: string
  sink_type: string
  config: string
  filter_actions: string
  filter_statuses: string
}

const defaultConfig: Record<string, string> = {
  webhook:     '{\n  "url": "https://example.com/hook",\n  "secret": ""\n}',
  http:        '{\n  "url": "https://example.com/events",\n  "headers": {}\n}',
  mqtt:        '{\n  "broker": "mqtt://broker:1883",\n  "topic": "clavex/audit",\n  "username": "",\n  "password": ""\n}',
  kafka:       '{\n  "brokers": ["kafka:9092"],\n  "topic": "clavex-audit",\n  "sasl_username": "",\n  "sasl_password": ""\n}',
  splunk_hec:  '{\n  "url": "https://splunk:8088",\n  "token": "",\n  "index": "main"\n}',
  sentinel:    '{\n  "workspace_id": "",\n  "shared_key": "",\n  "log_type": "ClavexAudit"\n}',
  elastic_ecs: '{\n  "url": "https://elastic:9200",\n  "index": "clavex-audit",\n  "api_key": ""\n}',
}

function fmt(iso?: string) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

function SinkCard({ sink, onToggle, onDelete }: {
  sink: AuditSink
  onToggle: (id: string, active: boolean) => void
  onDelete: (id: string) => void
}) {
  const [expanded, setExpanded] = useState(false)

  const typeMeta = SINK_TYPES.find((t) => t.value === sink.sink_type)
  const hasError = !!sink.last_error_at && (!sink.last_success_at || new Date(sink.last_error_at) > new Date(sink.last_success_at))

  return (
    <div className="rounded-xl overflow-hidden" style={{ border: '0.5px solid var(--clavex-border)' }}>
      <div className="flex items-center justify-between px-5 py-4 bg-white">
        <div className="flex items-center gap-3 min-w-0">
          <div>
            <p className="font-semibold text-sm">{sink.name}</p>
            <p className="text-xs mt-0.5" style={{ color: 'var(--clavex-ink-subtle)' }}>
              {typeMeta?.label ?? sink.sink_type}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0 ml-4">
          {hasError && <Badge variant="red">Error</Badge>}
          <Badge variant={sink.is_active ? 'green' : 'gray'}>{sink.is_active ? 'Active' : 'Paused'}</Badge>
          <button
            onClick={() => onToggle(sink.id, !sink.is_active)}
            style={{ color: sink.is_active ? 'var(--clavex-primary)' : 'var(--clavex-neutral)' }}
            title={sink.is_active ? 'Pause' : 'Activate'}
          >
            {sink.is_active ? <ToggleRight size={22} /> : <ToggleLeft size={22} />}
          </button>
          <button
            onClick={() => setExpanded((v) => !v)}
            style={{ color: 'var(--clavex-ink-subtle)' }}
            className="hover:text-[var(--clavex-ink)]"
          >
            {expanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </button>
          <button
            onClick={() => { if (confirm(`Delete sink "${sink.name}"?`)) onDelete(sink.id) }}
            className="text-red-400 hover:text-red-600"
          >
            <Trash2 size={15} />
          </button>
        </div>
      </div>

      {expanded && (
        <div className="px-5 pb-4 pt-1 space-y-3 bg-white" style={{ borderTop: '0.5px solid var(--clavex-surface)' }}>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div>
              <p style={{ color: 'var(--clavex-ink-subtle)' }}>Successes</p>
              <p className="font-semibold text-sm mt-0.5">{sink.success_count.toLocaleString()}</p>
            </div>
            <div>
              <p style={{ color: 'var(--clavex-ink-subtle)' }}>Failures</p>
              <p className="font-semibold text-sm mt-0.5" style={{ color: sink.failure_count > 0 ? '#A32D2D' : undefined }}>
                {sink.failure_count.toLocaleString()}
              </p>
            </div>
            <div>
              <p style={{ color: 'var(--clavex-ink-subtle)' }}>Last success</p>
              <p className="mt-0.5">{fmt(sink.last_success_at)}</p>
            </div>
            <div>
              <p style={{ color: 'var(--clavex-ink-subtle)' }}>Last error</p>
              <p className="mt-0.5" style={{ color: sink.last_error_at ? '#A32D2D' : undefined }}>{fmt(sink.last_error_at)}</p>
            </div>
          </div>

          {sink.last_error_msg && (
            <pre className="text-xs rounded-lg px-3 py-2 overflow-x-auto" style={{ background: '#FCEBEB', color: '#A32D2D' }}>
              {sink.last_error_msg}
            </pre>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
            <div>
              <p style={{ color: 'var(--clavex-ink-subtle)' }} className="mb-1">Config</p>
              <pre className="text-[11px] rounded-lg px-3 py-2 overflow-x-auto" style={{ background: 'var(--clavex-surface)', color: 'var(--clavex-ink)' }}>
                {JSON.stringify(sink.config, null, 2)}
              </pre>
            </div>
            <div className="space-y-2">
              {sink.filter_actions && sink.filter_actions.length > 0 && (
                <div>
                  <p style={{ color: 'var(--clavex-ink-subtle)' }} className="mb-1">Action filter</p>
                  <p className="font-mono">{sink.filter_actions.join(', ')}</p>
                </div>
              )}
              {sink.filter_statuses && sink.filter_statuses.length > 0 && (
                <div>
                  <p style={{ color: 'var(--clavex-ink-subtle)' }} className="mb-1">Status filter</p>
                  <p className="font-mono">{sink.filter_statuses.join(', ')}</p>
                </div>
              )}
              <div>
                <p style={{ color: 'var(--clavex-ink-subtle)' }} className="mb-1">Created</p>
                <p>{fmt(sink.created_at)}</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default function AuditSinksPage() {
  const orgId = useAuthStore((s) => s.orgId)
  const qc = useQueryClient()
  const [showModal, setShowModal] = useState(false)
  const [form, setForm] = useState<SinkFormState>({
    name: '',
    sink_type: 'webhook',
    config: defaultConfig.webhook,
    filter_actions: '',
    filter_statuses: '',
  })
  const [configError, setConfigError] = useState('')

  const { data: sinks = [], isLoading } = useQuery<AuditSink[]>({
    queryKey: ['audit-sinks', orgId],
    queryFn: () => api.get(`/organizations/${orgId}/audit/sinks`).then((r) => toArr<AuditSink>(r.data)),
    enabled: !!orgId,
  })

  const create = useMutation({
    mutationFn: (body: unknown) =>
      api.post(`/organizations/${orgId}/audit/sinks`, body).then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['audit-sinks', orgId] })
      toast.success('Audit sink created')
      setShowModal(false)
      resetForm()
    },
    onError: () => toast.error('Failed to create audit sink'),
  })

  const toggle = useMutation({
    mutationFn: ({ id, active }: { id: string; active: boolean }) =>
      api.patch(`/organizations/${orgId}/audit/sinks/${id}`, { is_active: active }).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['audit-sinks', orgId] }),
    onError: () => toast.error('Failed to update sink'),
  })

  const remove = useMutation({
    mutationFn: (id: string) => api.delete(`/organizations/${orgId}/audit/sinks/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['audit-sinks', orgId] })
      toast.success('Sink deleted')
    },
    onError: () => toast.error('Failed to delete sink'),
  })

  function resetForm() {
    setForm({ name: '', sink_type: 'webhook', config: defaultConfig.webhook, filter_actions: '', filter_statuses: '' })
    setConfigError('')
  }

  function handleSinkTypeChange(type: string) {
    setForm((f) => ({ ...f, sink_type: type, config: defaultConfig[type] ?? '{}' }))
    setConfigError('')
  }

  function handleCreate() {
    let parsedConfig: unknown
    try {
      parsedConfig = JSON.parse(form.config)
      setConfigError('')
    } catch {
      setConfigError('Invalid JSON')
      return
    }
    const body: Record<string, unknown> = {
      name: form.name.trim(),
      sink_type: form.sink_type,
      config: parsedConfig,
    }
    const actions = form.filter_actions.split(',').map((s) => s.trim()).filter(Boolean)
    const statuses = form.filter_statuses.split(',').map((s) => s.trim()).filter(Boolean)
    if (actions.length > 0)  body.filter_actions  = actions
    if (statuses.length > 0) body.filter_statuses = statuses
    create.mutate(body)
  }

  if (isLoading) return <Spinner />

  return (
    <div className="space-y-6">
      <PageHeader
        title="Audit Sinks"
        subtitle="Stream audit events to external systems in real time."
        action={
          <Button onClick={() => setShowModal(true)}>
            <Plus className="h-4 w-4" /> Add sink
          </Button>
        }
      />

      {sinks.length === 0 ? (
        <Card className="py-14 text-center">
          <p className="text-sm font-medium">No audit sinks configured</p>
          <p className="text-xs mt-1" style={{ color: 'var(--clavex-ink-subtle)' }}>
            Create a sink to forward audit events to Webhook, Kafka, Splunk, Sentinel, and more.
          </p>
        </Card>
      ) : (
        <div className="space-y-3">
          {sinks.map((s) => (
            <SinkCard
              key={s.id}
              sink={s}
              onToggle={(id, active) => toggle.mutate({ id, active })}
              onDelete={(id) => remove.mutate(id)}
            />
          ))}
        </div>
      )}

      <Modal
        open={showModal}
        title="Add audit sink"
        description="Configure a new destination for audit events."
        onClose={() => { setShowModal(false); resetForm() }}
        size="lg"
      >
        <div className="space-y-4">
          <Input
            label="Name"
            placeholder="My Splunk sink"
            value={form.name}
            onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
          />

          <Select
            label="Sink type"
            value={form.sink_type}
            onChange={(e) => handleSinkTypeChange(e.target.value)}
          >
            {SINK_TYPES.map((t) => (
              <option key={t.value} value={t.value}>{t.label}</option>
            ))}
          </Select>

          <div className="space-y-1.5">
            <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: 'var(--clavex-ink)', marginBottom: 6 }}>
              Config (JSON)
            </label>
            <textarea
              className="w-full rounded-lg px-3 py-2 font-mono text-xs resize-y outline-none"
              style={{
                minHeight: 160,
                border: configError ? '0.5px solid #E24B4A' : '0.5px solid var(--clavex-border)',
                background: 'var(--clavex-dark, #0D1F2D)',
                color: '#C4DFF0',
                lineHeight: 1.6,
              }}
              value={form.config}
              onChange={(e) => { setForm((f) => ({ ...f, config: e.target.value })); setConfigError('') }}
              spellCheck={false}
            />
            {configError && <p style={{ fontSize: 12, color: '#A32D2D' }}>{configError}</p>}
          </div>

          <Input
            label="Filter by action (optional)"
            placeholder="login, token_issue, user_create …"
            hint="Comma-separated action names. Leave empty to capture all."
            value={form.filter_actions}
            onChange={(e) => setForm((f) => ({ ...f, filter_actions: e.target.value }))}
          />

          <Input
            label="Filter by status (optional)"
            placeholder="success, failure …"
            hint="Comma-separated statuses. Leave empty to capture all."
            value={form.filter_statuses}
            onChange={(e) => setForm((f) => ({ ...f, filter_statuses: e.target.value }))}
          />

          <div className="flex justify-end gap-2 pt-2">
            <Button variant="secondary" onClick={() => { setShowModal(false); resetForm() }}>Cancel</Button>
            <Button onClick={handleCreate} loading={create.isPending} disabled={!form.name.trim()}>
              Create sink
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}
