import React from 'react'
import { cn } from '@/lib/cn'

// ── Badge ─────────────────────────────────────────────────────────────────────
interface BadgeProps { variant?: 'green' | 'gray' | 'red' | 'yellow' | 'blue' | 'purple'; children: React.ReactNode; className?: string }
const badgeVariants = {
  green:  'bg-[#E1F5EE] text-[#0F6E56]',
  gray:   'bg-[#F5F4F0] text-[#5F5E5A]',
  red:    'bg-[#FCEBEB] text-[#A32D2D]',
  yellow: 'bg-[#FAEEDA] text-[#854F0B]',
  blue:   'bg-[#E8F0FB] text-[#185FA5]',
  purple: 'bg-[#EEEDFE] text-[#534AB7]',
}
export function Badge({ variant = 'gray', children, className }: BadgeProps) {
  return (
    <span className={cn('inline-flex items-center rounded-full px-2.5 py-0.5 text-[10px] font-bold tracking-wide', badgeVariants[variant], className)}>
      {children}
    </span>
  )
}

// ── ManagedBadge ────────────────────────────────────────────────────────────────
// Shown next to a resource that is owned by an external declarative system
// (today: the Kubernetes operator, managed_by="k8s-operator"). Renders nothing
// when the resource is hand-managed. The native title tooltip warns that
// out-of-band edits here will be reverted at the next reconcile.
interface ManagedBadgeProps { managedBy?: string | null; managedRef?: string | null; className?: string }
export function ManagedBadge({ managedBy, managedRef, className }: ManagedBadgeProps) {
  if (!managedBy) return null
  const label = managedBy === 'k8s-operator'
    ? 'Managed by Kubernetes Operator'
    : `Managed by ${managedBy}`
  const via = managedRef ? ` via ${managedRef}` : ''
  const tooltip = `This resource is managed declaratively${via}. Changes made here will be reverted automatically. Edit the Kubernetes resource instead.`
  return (
    <span title={tooltip} className={cn('cursor-help', className)}>
      <Badge variant="blue" className="gap-1">
        <span aria-hidden="true">⚙</span>
        {label}
      </Badge>
    </span>
  )
}

// ── Button ────────────────────────────────────────────────────────────────────
interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost'
  size?: 'xs' | 'sm' | 'md'
  loading?: boolean
}
const btnBase = 'inline-flex items-center justify-center gap-1.5 font-semibold whitespace-nowrap transition-colors duration-150 focus-visible:outline-none disabled:opacity-60 disabled:cursor-not-allowed select-none'
const btnVariants = {
  primary:   'text-white',
  secondary: 'bg-white border text-[#1A2332] hover:bg-[#F0FAF6]',
  danger:    'text-white bg-[#E24B4A] hover:bg-[#C03C3B]',
  ghost:     'text-[#5F5E5A] hover:text-[#1A2332] hover:bg-[#F0FAF6]',
}
const btnSizes = {
  xs: 'px-2.5 py-1 text-xs rounded-md',
  sm: 'px-3 py-1.5 text-sm rounded-md',
  md: 'px-4 py-2.5 text-sm rounded-lg',
}

export function Button({ variant = 'primary', size = 'md', loading, className, children, style, ...props }: ButtonProps) {
  const isPrimary = variant === 'primary'
  const isSecondary = variant === 'secondary'
  return (
    <button
      {...props}
      disabled={loading || props.disabled}
      className={cn(btnBase, btnVariants[variant], btnSizes[size], className)}
      style={{
        ...(isPrimary ? { background: 'var(--clavex-primary)' } : {}),
        ...(isPrimary ? { borderRadius: 'var(--clavex-radius-md)' } : {}),
        ...(isSecondary ? { border: '0.5px solid var(--clavex-border-subtle)', borderRadius: 'var(--clavex-radius-md)' } : {}),
        ...style,
      }}
      onMouseEnter={(e) => { if (isPrimary && !loading && !props.disabled) (e.currentTarget.style.background = 'var(--clavex-700)'); props.onMouseEnter?.(e) }}
      onMouseLeave={(e) => { if (isPrimary && !loading && !props.disabled) (e.currentTarget.style.background = 'var(--clavex-primary)'); props.onMouseLeave?.(e) }}
    >
      {loading && <Spinner size="xs" />}
      {children}
    </button>
  )
}

// ── Input ─────────────────────────────────────────────────────────────────────
interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string
  error?: string
  hint?: string
  icon?: React.ReactNode
}
export function Input({ label, error, hint, icon, className, ...props }: InputProps) {
  return (
    <div className="space-y-1.5">
      {label && <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: 'var(--clavex-ink)', marginBottom: 6 }}>{label}</label>}
      <div className="relative">
        {icon && <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3.5" style={{ color: 'var(--clavex-neutral)' }}>{icon}</div>}
        <input
          {...props}
          className={cn('input-base', icon && 'pl-9', error && '!border-[#E24B4A]', className)}
        />
      </div>
      {error && <p style={{ fontSize: 12, color: 'var(--clavex-danger)', marginTop: 4 }}>{error}</p>}
      {hint && !error && <p style={{ fontSize: 12, color: 'var(--clavex-neutral)', marginTop: 4 }}>{hint}</p>}
    </div>
  )
}

// ── Textarea ──────────────────────────────────────────────────────────────────
interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string; error?: string; hint?: string
}
export function Textarea({ label, error, hint, className, ...props }: TextareaProps) {
  return (
    <div className="space-y-1.5">
      {label && <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: 'var(--clavex-ink)', marginBottom: 6 }}>{label}</label>}
      <textarea {...props} className={cn('input-base resize-none', error && '!border-[#E24B4A]', className)} />
      {error && <p style={{ fontSize: 12, color: 'var(--clavex-danger)', marginTop: 4 }}>{error}</p>}
      {hint && !error && <p style={{ fontSize: 12, color: 'var(--clavex-neutral)', marginTop: 4 }}>{hint}</p>}
    </div>
  )
}

// ── Select ────────────────────────────────────────────────────────────────────
interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> { label?: string; error?: string }
export function Select({ label, error, className, children, ...props }: SelectProps) {
  return (
    <div className="space-y-1.5">
      {label && <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: 'var(--clavex-ink)', marginBottom: 6 }}>{label}</label>}
      <select {...props} className={cn('input-base bg-white cursor-pointer', error && '!border-[#E24B4A]', className)}>{children}</select>
      {error && <p style={{ fontSize: 12, color: 'var(--clavex-danger)', marginTop: 4 }}>{error}</p>}
    </div>
  )
}

// ── Card ──────────────────────────────────────────────────────────────────────
export function Card({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div
      className={cn('bg-white', className)}
      style={{ border: '0.5px solid var(--clavex-border)', borderRadius: 'var(--clavex-radius-lg)' }}
    >
      {children}
    </div>
  )
}

// ── Spinner ───────────────────────────────────────────────────────────────────
export function Spinner({ size = 'md', className }: { size?: 'xs' | 'sm' | 'md' | 'lg'; className?: string }) {
  const sizes = { xs: 'h-3 w-3 border', sm: 'h-4 w-4 border-2', md: 'h-6 w-6 border-2', lg: 'h-8 w-8 border-2' }
  return (
    <div className={cn('flex justify-center', size === 'md' || size === 'lg' ? 'py-10' : '')}>
      <div
        className={cn('animate-spin rounded-full', sizes[size], className)}
        style={{ borderColor: 'var(--clavex-200)', borderTopColor: 'var(--clavex-primary)' }}
      />
    </div>
  )
}

// ── Modal ─────────────────────────────────────────────────────────────────────
interface ModalProps { open: boolean; title: string; description?: string; onClose: () => void; children: React.ReactNode; size?: 'sm' | 'md' | 'lg' | 'xl' | '2xl' }
const modalSizes = { sm: 'max-w-sm', md: 'max-w-md', lg: 'max-w-lg', xl: 'max-w-xl', '2xl': 'max-w-2xl' }
export function Modal({ open, title, description, onClose, children, size = 'md' }: ModalProps) {
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/30 backdrop-blur-[2px]" style={{ animation: 'fadeIn 0.15s ease-out' }} onClick={onClose} />
      <div
        className={cn('relative z-10 w-full bg-white overflow-hidden', modalSizes[size])}
        style={{
          borderRadius: 'var(--clavex-radius-xl)',
          border: '0.5px solid var(--clavex-border)',
          boxShadow: '0 20px 60px -10px rgba(0,0,0,0.18)',
          animation: 'slideUp 0.2s ease-out',
        }}
      >
        <div className="px-6 pt-6 pb-5" style={{ borderBottom: '0.5px solid var(--clavex-surface)' }}>
          <h3 style={{ fontSize: 15, fontWeight: 600, color: 'var(--clavex-ink)' }}>{title}</h3>
          {description && <p style={{ fontSize: 13, color: 'var(--clavex-ink-subtle)', marginTop: 4 }}>{description}</p>}
        </div>
        <div className="px-6 py-5 overflow-y-auto max-h-[70vh]">{children}</div>
      </div>
    </div>
  )
}

// ── PageHeader ────────────────────────────────────────────────────────────────
export function PageHeader({ title, subtitle, action }: { title: string; subtitle?: string; action?: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between mb-6">
      <div>
        <h1 style={{ fontSize: 20, fontWeight: 700, color: 'var(--clavex-ink)', letterSpacing: '-0.3px' }}>{title}</h1>
        {subtitle && <p style={{ fontSize: 13, color: 'var(--clavex-ink-subtle)', marginTop: 2 }}>{subtitle}</p>}
      </div>
      {action && <div className="flex items-center gap-2">{action}</div>}
    </div>
  )
}

// ── EmptyState ────────────────────────────────────────────────────────────────
export function EmptyState({ icon: Icon, title, message }: { icon?: React.ElementType; title?: string; message: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-14 px-6 text-center">
      {Icon && (
        <div
          className="h-10 w-10 flex items-center justify-center mb-3"
          style={{ background: 'var(--clavex-50)', borderRadius: 10 }}
        >
          <Icon className="h-5 w-5" style={{ color: 'var(--clavex-700)' }} />
        </div>
      )}
      {title && <p style={{ fontWeight: 600, color: 'var(--clavex-ink)', marginBottom: 4 }}>{title}</p>}
      <p style={{ fontSize: 13, color: 'var(--clavex-neutral)' }}>{message}</p>
    </div>
  )
}

// ── StatCard ──────────────────────────────────────────────────────────────────
export function StatCard({ label, value, icon: Icon }: { label: string; value: string | number; icon?: React.ElementType; color?: string }) {
  return (
    <Card className="px-5 py-4 flex items-center gap-4">
      {Icon && (
        <div
          className="h-10 w-10 flex items-center justify-center flex-shrink-0"
          style={{ background: 'var(--clavex-50)', borderRadius: 10 }}
        >
          <Icon className="h-5 w-5" style={{ color: 'var(--clavex-700)' }} />
        </div>
      )}
      <div>
        <p style={{ fontSize: 24, fontWeight: 700, color: 'var(--clavex-ink)', letterSpacing: '-0.5px', lineHeight: 1 }}>{value}</p>
        <p style={{ fontSize: 11, color: 'var(--clavex-neutral)', marginTop: 4, fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.5px' }}>{label}</p>
      </div>
    </Card>
  )
}

// ── Divider ───────────────────────────────────────────────────────────────────
export function Divider({ className }: { className?: string }) {
  return <div className={cn(className)} style={{ borderTop: '0.5px solid var(--clavex-surface)' }} />
}

// ── AlertBanner ───────────────────────────────────────────────────────────────
export function AlertBanner({ variant = 'info', children }: { variant?: 'info' | 'warning' | 'danger'; children: React.ReactNode }) {
  const styles = {
    info:    { background: '#E8F0FB', border: '0.5px solid #185FA5', color: '#185FA5' },
    warning: { background: '#FAEEDA', border: '0.5px solid #BA7517', color: '#854F0B' },
    danger:  { background: '#FCEBEB', border: '0.5px solid #E24B4A', color: '#A32D2D' },
  }
  return (
    <div
      style={{ ...styles[variant], borderRadius: 'var(--clavex-radius-md)', padding: '10px 14px', fontSize: 13 }}
    >
      {children}
    </div>
  )
}
