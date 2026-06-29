import { useState } from 'react'
import {
  Check, X, ChevronDown,
  Shield, Globe, FileText, RefreshCw, GitFork,
} from 'lucide-react'

// ── Scoped styles (marketing dark theme) ─────────────────────────────────────
// CSS variables are set on the .pr root so every child can consume them via
// var(--…). Hover states and pseudo-elements that can't be expressed with
// inline styles are handled here.

const STYLES = `
.pr {
  --bg:      #0D1F2D;
  --bg-2:    #112233;
  --bg-3:    #162B40;
  --rule:    #1E3448;
  --body:    #7AAABB;
  --bright:  #E8F4F8;
  --muted:   #4A7890;
  --teal:    #5DCAA5;
  --teal-d:  #1D9E75;
  --teal-p:  rgba(93,202,165,.07);
  background: var(--bg);
  color: var(--body);
  font-family: 'Plus Jakarta Sans', ui-sans-serif, system-ui, sans-serif;
  min-height: 100vh;
  overflow-x: hidden;
  position: relative;
}
.pr::before {
  content: '';
  position: fixed;
  inset: 0;
  z-index: 0;
  pointer-events: none;
  background-image:
    linear-gradient(rgba(93,202,165,.02) 1px, transparent 1px),
    linear-gradient(90deg, rgba(93,202,165,.02) 1px, transparent 1px);
  background-size: 60px 60px;
}
.pr > * { position: relative; z-index: 1; }

/* Tier cards */
.pr-tier {
  background: var(--bg-2);
  border: 1px solid var(--rule);
  border-radius: 12px;
  padding: 2rem;
  display: flex;
  flex-direction: column;
  transition: border-color .2s, box-shadow .2s;
}
.pr-tier:hover { border-color: rgba(93,202,165,.25); }
.pr-tier-featured {
  background: var(--bg-3);
  border-color: var(--teal) !important;
  box-shadow: 0 0 48px rgba(93,202,165,.12);
  transform: translateY(-4px);
}

/* Buttons */
.pr-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: .5rem;
  font-family: inherit;
  font-size: .78rem;
  font-weight: 600;
  letter-spacing: .07em;
  text-transform: uppercase;
  padding: .72rem 1.4rem;
  border-radius: 6px;
  text-decoration: none;
  transition: all .18s;
  cursor: pointer;
  border: none;
  white-space: nowrap;
}
.pr-btn-ghost {
  border: 1px solid var(--rule);
  color: var(--body);
  background: transparent;
}
.pr-btn-ghost:hover { border-color: var(--teal); color: var(--teal); }
.pr-btn-primary { background: var(--teal); color: var(--bg); }
.pr-btn-primary:hover { background: var(--teal-d); }
.pr-btn-outline {
  border: 1px solid rgba(93,202,165,.5);
  color: var(--teal);
  background: transparent;
}
.pr-btn-outline:hover { background: var(--teal-p); border-color: var(--teal); }

/* FAQ */
.pr-faq-q {
  width: 100%;
  text-align: left;
  background: transparent;
  border: none;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 1.2rem 0;
  color: var(--bright);
  font-family: inherit;
  font-size: .95rem;
  font-weight: 500;
  line-height: 1.4;
  transition: color .15s;
}
.pr-faq-q:hover { color: var(--teal); }
.pr-faq-chevron { color: var(--teal); transition: transform .2s; flex-shrink: 0; margin-left: 1rem; }
.pr-faq-chevron-open { transform: rotate(180deg); }

/* Mono spans */
.pr-mono { font-family: 'JetBrains Mono', 'Fira Code', ui-monospace, monospace; }

/* Responsive grid */
@media (max-width: 900px) {
  .pr-grid { grid-template-columns: 1fr !important; }
  .pr-tier-featured { transform: none !important; }
  .pr-trust { flex-direction: column !important; align-items: flex-start !important; }
}
@media (max-width: 540px) {
  .pr-footer-cta { flex-direction: column !important; }
}
`

// ── Data ──────────────────────────────────────────────────────────────────────

interface Feature { text: string; ok: boolean }
interface Tier {
  name: string
  badge?: string          // filled teal badge (Most popular)
  badgeSmall?: string     // outline badge (Coming soon)
  tagline: string
  price: string
  priceSub?: string
  cta: string
  ctaHref: string
  ctaVariant: 'ghost' | 'primary' | 'outline'
  featured?: boolean
  valueProp?: string
  features: Feature[]
}

const tiers: Tier[] = [
  {
    name: 'Community',
    tagline: 'BSL 1.1 · 1 production org · unlimited dev/staging',
    price: 'Free, forever',
    cta: 'Download on GitHub',
    ctaHref: 'https://github.com/clavex-eu/clavex/releases',
    ctaVariant: 'ghost',
    features: [
      { text: 'OIDC / OAuth 2.0 + FAPI 2.0 (JAR · PAR · DPoP · JARM)', ok: true },
      { text: 'SPID + CIE (Italy) · FranceConnect (France) · itsme® (Belgium)', ok: true },
      { text: 'eIDAS node — all 27 EU member states', ok: true },
      { text: 'eIDAS 2.0 Wallet: OID4VCI · OID4VP · SD-JWT-VC', ok: true },
      { text: 'GDPR Art.30 RoPA · Art.15 DSAR · Art.17 Erasure — REST API', ok: true },
      { text: 'NIS2 Art.21 evidence + Merkle audit chain (RS256-signed)', ok: true },
      { text: 'Auth policy engine with dry-run simulate', ok: true },
      { text: 'Identity risk score (impossible travel, VPN, device fingerprint)', ok: true },
      { text: 'Passkeys (resident keys · conditional UI · iCloud/Google sync)', ok: true },
      { text: 'SAML 2.0 IdP + SP · SCIM 2.0 · LDAP federation', ok: true },
      { text: 'MQTT · Webhook · HTTP · Kafka event fan-out', ok: true },
      { text: 'Community support (GitHub Issues)', ok: true },
      { text: 'More than 1 production organisation', ok: false },
      { text: 'Contractual SLA', ok: false },
    ],
  },
  {
    name: 'Enterprise',
    badge: 'Most popular',
    tagline: '≤10 orgs · volume pricing available',
    price: 'From €8,000',
    priceSub: '/ year',
    cta: 'Talk to sales',
    ctaHref: 'mailto:sales@clavex.eu',
    ctaVariant: 'primary',
    featured: true,
    valueProp:
      'Everything in Community, plus the support and compliance documentation a regulated organisation needs.',
    features: [
      { text: 'Everything in Community', ok: true },
      { text: 'Unlimited production organisations', ok: true },
      { text: '99.9% SLA · <4h response · named support contact', ok: true },
      { text: 'Priority CVE patches + security advisories', ok: true },
      { text: 'NIS2 / ISO 27001 audit readiness report (annual)', ok: true },
      { text: 'Onboarding + migration assistance', ok: true },
      { text: 'Dedicated Slack/Teams channel', ok: true },
      { text: '2 training sessions / year', ok: true },
      { text: 'Sub-processor list + DPA on request', ok: true },
      { text: 'Managed hosting', ok: false },
    ],
  },
  {
    name: 'Cloud',
    badgeSmall: 'Coming soon',
    tagline: 'per tenant · up to 10k MAU',
    price: '€49',
    priceSub: '/ month',
    cta: 'Join waitlist',
    ctaHref: 'mailto:cloud@clavex.eu',
    ctaVariant: 'outline',
    features: [
      { text: 'Everything in Enterprise', ok: true },
      { text: 'Hosted in EU (Frankfurt · Dublin) — GDPR Art.28 DPA included', ok: true },
      { text: 'Automatic updates + zero-downtime deploys', ok: true },
      { text: 'Daily backups with PITR (30-day retention)', ok: true },
      { text: 'Free tier: 1 tenant · 1k MAU', ok: true },
      { text: 'Pay-as-you-grow billing', ok: true },
      { text: 'Self-hosted deployment option', ok: false },
    ],
  },
]

const trustBar = [
  { icon: Shield,    label: 'SOC 2 Type II in progress' },
  { icon: Globe,     label: 'EU data residency by architecture' },
  { icon: FileText,  label: 'GDPR Article 28 DPA available' },
  { icon: RefreshCw, label: 'BSL 1.1 → Apache 2.0 after 4 years' },
  { icon: GitFork,   label: 'Source code auditable on GitHub' },
]

const keycloakPoints = [
  {
    tag: '[coverage]',
    text: "Keycloak is a great product. It doesn't ship SPID, CIE, FranceConnect, itsme®, or eIDAS wallet flows out of the box. Clavex does.",
  },
  {
    tag: '[compliance]',
    text: "Keycloak's compliance story stops at OIDC conformance. Clavex ships GDPR Art.30/15/17 and NIS2 Art.21 as REST endpoints — ready for your DPO on day one.",
  },
  {
    tag: '[ops]',
    text: 'Keycloak requires JVM tuning and Infinispan clustering. Clavex is a single Go binary. Postgres + Redis. Done.',
  },
]

const faqs = [
  {
    q: 'Is it really free?',
    a: 'Yes. BSL 1.1 allows unlimited use for a single production organisation — development and staging are always free. No credit card required.',
  },
  {
    q: 'What counts as an "organisation"?',
    a: 'An isolated tenant with its own users, OIDC clients, policies, and branding. One company with one IdP = 1 org. Ten SaaS customers on one Clavex instance = 10 orgs.',
  },
  {
    q: 'When do I need a commercial licence?',
    a: 'When you run more than one production organisation on a single Clavex instance — typically multi-tenant SaaS platforms or multi-entity enterprise deployments.',
  },
  {
    q: 'How does the BSL → Apache 2.0 conversion work?',
    a: 'Every release converts to Apache 2.0 four years after its release date (see CHANGELOG). You can always use any version that has already converted.',
  },
  {
    q: 'Does Clavex have a security disclosure process?',
    a: 'Yes. See SECURITY.md. Report vulnerabilities via GitHub private advisory or security@clavex.eu (GPG key available). We target a 30-day fix window for Critical/High.',
  },
  {
    q: 'Where is data stored on the Cloud plan?',
    a: 'EU-only: AWS eu-central-1 (Frankfurt) and eu-west-1 (Dublin). GDPR Art.28 DPA and sub-processor list available on request.',
  },
]

// ── Sub-components ────────────────────────────────────────────────────────────

function Eyebrow({ children }: { children: React.ReactNode }) {
  return (
    <p
      className="pr-mono"
      style={{
        fontSize: '.68rem',
        color: 'var(--teal)',
        letterSpacing: '.22em',
        textTransform: 'uppercase',
        marginBottom: '1.25rem',
        display: 'flex',
        alignItems: 'center',
        gap: '.75rem',
      }}
    >
      <span style={{ display: 'block', width: 24, height: 1, background: 'var(--teal)', flexShrink: 0 }} />
      {children}
    </p>
  )
}

function TierCard({ tier }: { tier: Tier }) {
  return (
    <div className={`pr-tier${tier.featured ? ' pr-tier-featured' : ''}`}>
      {/* Name + badges */}
      <div style={{ marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '.5rem', marginBottom: '.4rem', flexWrap: 'wrap' }}>
          <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 600, color: 'var(--bright)' }}>
            {tier.name}
          </h3>
          {tier.badge && (
            <span style={{
              fontSize: '.6rem', fontWeight: 700, letterSpacing: '.1em',
              textTransform: 'uppercase',
              background: 'var(--teal)', color: 'var(--bg)',
              borderRadius: '3px', padding: '.18rem .5rem',
            }}>
              {tier.badge}
            </span>
          )}
          {tier.badgeSmall && (
            <span style={{
              fontSize: '.6rem', fontWeight: 600, letterSpacing: '.08em',
              textTransform: 'uppercase',
              border: '1px solid rgba(93,202,165,.4)', color: 'var(--teal)',
              borderRadius: '3px', padding: '.15rem .45rem',
            }}>
              {tier.badgeSmall}
            </span>
          )}
        </div>
        <p style={{ margin: 0, fontSize: '.83rem', color: 'var(--body)', lineHeight: 1.5 }}>
          {tier.tagline}
        </p>
      </div>

      {/* Price */}
      <div style={{ marginBottom: '1.5rem', display: 'flex', alignItems: 'baseline', gap: '.35rem' }}>
        <span style={{ fontSize: '2rem', fontWeight: 700, color: 'var(--bright)', lineHeight: 1 }}>
          {tier.price}
        </span>
        {tier.priceSub && (
          <span style={{ fontSize: '.85rem', color: 'var(--body)' }}>{tier.priceSub}</span>
        )}
      </div>

      {/* CTA */}
      <a
        href={tier.ctaHref}
        className={`pr-btn pr-btn-${tier.ctaVariant}`}
        style={{ width: '100%', marginBottom: '1.5rem' }}
        {...(tier.ctaHref.startsWith('http') ? { target: '_blank', rel: 'noopener noreferrer' } : {})}
      >
        {tier.cta}
      </a>

      {/* Value prop */}
      {tier.valueProp && (
        <p style={{
          margin: '0 0 1.25rem',
          fontSize: '.8rem', lineHeight: 1.65, color: 'var(--body)',
          padding: '.75rem .9rem',
          background: 'rgba(93,202,165,.06)',
          border: '1px solid rgba(93,202,165,.14)',
          borderRadius: '6px',
        }}>
          {tier.valueProp}
        </p>
      )}

      {/* Divider */}
      <div style={{ borderTop: '1px solid var(--rule)', marginBottom: '1.1rem' }} />

      {/* Features */}
      <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: '.6rem' }}>
        {tier.features.map((f) => (
          <li
            key={f.text}
            style={{ display: 'flex', alignItems: 'flex-start', gap: '.55rem', opacity: f.ok ? 1 : 0.38 }}
          >
            {f.ok
              ? <Check size={13} style={{ color: 'var(--teal)', flexShrink: 0, marginTop: '.18rem' }} />
              : <X     size={13} style={{ color: 'var(--body)', flexShrink: 0, marginTop: '.18rem' }} />
            }
            <span style={{ fontSize: '.8rem', color: 'var(--body)', lineHeight: 1.5 }}>{f.text}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function PricingPage() {
  const [openFaq, setOpenFaq] = useState<number | null>(null)

  return (
    <>
      <style dangerouslySetInnerHTML={{ __html: STYLES }} />

      <div className="pr">

        {/* ── Hero ──────────────────────────────────────────────────────── */}
        <section style={{ padding: '7rem 2rem 4rem', textAlign: 'center' }}>
          <div style={{ maxWidth: '660px', margin: '0 auto' }}>
            <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '1.5rem' }}>
              <Eyebrow>Pricing</Eyebrow>
            </div>
            <h1 style={{
              fontSize: 'clamp(2.2rem, 4.5vw, 3.4rem)',
              fontWeight: 300,
              lineHeight: 1.1,
              color: 'var(--bright)',
              letterSpacing: '-.03em',
              marginBottom: '1.1rem',
            }}>
              Simple,{' '}
              <strong style={{ fontWeight: 700, color: 'var(--teal)' }}>transparent</strong>{' '}
              pricing.
            </h1>
            <p style={{ fontSize: '1.05rem', color: 'var(--body)', lineHeight: 1.75, marginBottom: '2rem' }}>
              Open-source core. Commercial tiers for teams that scale.
              <br />EU data residency on every plan.
            </p>
            <span
              className="pr-mono"
              style={{
                display: 'inline-block',
                fontSize: '.68rem',
                letterSpacing: '.1em',
                color: 'var(--teal)',
                background: 'rgba(93,202,165,.07)',
                border: '1px solid rgba(93,202,165,.28)',
                borderRadius: '4px',
                padding: '.32rem .8rem',
              }}
            >
              BSL 1.1 — converts to Apache 2.0 after 4 years
            </span>
          </div>
        </section>

        {/* ── Tiers ─────────────────────────────────────────────────────── */}
        <section style={{ padding: '0 2rem 5rem' }}>
          <div
            className="pr-grid"
            style={{
              maxWidth: '1160px',
              margin: '0 auto',
              display: 'grid',
              gridTemplateColumns: 'repeat(3, 1fr)',
              gap: '1.25rem',
              alignItems: 'start',
            }}
          >
            {tiers.map((t) => <TierCard key={t.name} tier={t} />)}
          </div>
        </section>

        {/* ── Trust bar ─────────────────────────────────────────────────── */}
        <section style={{
          borderTop: '1px solid var(--rule)',
          borderBottom: '1px solid var(--rule)',
          background: 'var(--bg-2)',
          padding: '2.25rem 2rem',
        }}>
          <div
            className="pr-trust"
            style={{
              maxWidth: '960px',
              margin: '0 auto',
              display: 'flex',
              flexWrap: 'wrap',
              gap: '2rem',
              justifyContent: 'center',
              alignItems: 'center',
            }}
          >
            {trustBar.map(({ icon: Icon, label }) => (
              <div key={label} style={{ display: 'flex', alignItems: 'center', gap: '.55rem', fontSize: '.8rem', color: 'var(--body)' }}>
                <Icon size={14} style={{ color: 'var(--teal)', flexShrink: 0 }} />
                {label}
              </div>
            ))}
          </div>
        </section>

        {/* ── Why not Keycloak? ─────────────────────────────────────────── */}
        <section style={{ padding: '5.5rem 2rem' }}>
          <div style={{ maxWidth: '740px', margin: '0 auto' }}>
            <p
              className="pr-mono"
              style={{
                fontSize: '.68rem',
                color: 'var(--teal)',
                letterSpacing: '.18em',
                textTransform: 'uppercase',
                marginBottom: '.9rem',
              }}
            >
              # honest comparison
            </p>
            <h2 style={{
              fontSize: 'clamp(1.6rem, 3vw, 2.4rem)',
              fontWeight: 300,
              color: 'var(--bright)',
              letterSpacing: '-.02em',
              marginBottom: '.6rem',
            }}>
              Why not <strong style={{ fontWeight: 700 }}>Keycloak?</strong>
            </h2>
            <p style={{ fontSize: '.88rem', color: 'var(--muted)', marginBottom: '2.5rem', fontStyle: 'italic' }}>
              From one open-source project to another — no FUD, just facts.
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.4rem' }}>
              {keycloakPoints.map(({ tag, text }) => (
                <div key={tag} style={{ display: 'flex', gap: '1.2rem', alignItems: 'flex-start' }}>
                  <span
                    className="pr-mono"
                    style={{
                      fontSize: '.72rem',
                      fontWeight: 600,
                      color: 'var(--teal)',
                      flexShrink: 0,
                      paddingTop: '.22rem',
                      minWidth: '104px',
                    }}
                  >
                    {tag}
                  </span>
                  <p style={{ margin: 0, color: 'var(--body)', lineHeight: 1.72, fontSize: '.9rem' }}>
                    {text}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── FAQ ───────────────────────────────────────────────────────── */}
        <section style={{ borderTop: '1px solid var(--rule)', padding: '4rem 2rem 5.5rem' }}>
          <div style={{ maxWidth: '680px', margin: '0 auto' }}>
            <h2 style={{
              fontSize: 'clamp(1.4rem, 2.5vw, 2rem)',
              fontWeight: 300,
              color: 'var(--bright)',
              letterSpacing: '-.02em',
              textAlign: 'center',
              marginBottom: '2.5rem',
            }}>
              Frequently asked questions
            </h2>
            <div>
              {faqs.map((faq, i) => {
                const isOpen = openFaq === i
                return (
                  <div key={i} style={{ borderBottom: '1px solid var(--rule)' }}>
                    <button
                      className="pr-faq-q"
                      onClick={() => setOpenFaq(isOpen ? null : i)}
                      aria-expanded={isOpen}
                    >
                      <span>{faq.q}</span>
                      <ChevronDown
                        size={16}
                        className={`pr-faq-chevron${isOpen ? ' pr-faq-chevron-open' : ''}`}
                      />
                    </button>
                    {isOpen && (
                      <p style={{
                        margin: 0,
                        paddingBottom: '1.25rem',
                        color: 'var(--body)',
                        lineHeight: 1.75,
                        fontSize: '.9rem',
                      }}>
                        {faq.a}
                      </p>
                    )}
                  </div>
                )
              })}
            </div>
          </div>
        </section>

        {/* ── Footer CTA ────────────────────────────────────────────────── */}
        <section style={{
          borderTop: '1px solid var(--rule)',
          background: 'var(--bg-2)',
          padding: '5rem 2rem',
          textAlign: 'center',
        }}>
          <div style={{ maxWidth: '580px', margin: '0 auto' }}>
            <p
              className="pr-mono"
              style={{
                fontSize: '.78rem',
                lineHeight: 1.9,
                color: 'var(--body)',
                marginBottom: '2.25rem',
              }}
            >
              One binary. Postgres + Redis.{' '}
              <span style={{ color: 'var(--teal)' }}>
                Full eIDAS 2.0, FAPI 2.0,<br />and GDPR compliance
              </span>{' '}
              from day one.
            </p>
            <div
              className="pr-footer-cta"
              style={{ display: 'flex', gap: '1rem', justifyContent: 'center', flexWrap: 'wrap' }}
            >
              <a
                href="https://github.com/clavex-eu/clavex/releases"
                className="pr-btn pr-btn-ghost"
                target="_blank"
                rel="noopener noreferrer"
              >
                Download free
              </a>
              <a href="mailto:sales@clavex.eu" className="pr-btn pr-btn-primary">
                Talk to sales
              </a>
            </div>
          </div>
        </section>

      </div>
    </>
  )
}
