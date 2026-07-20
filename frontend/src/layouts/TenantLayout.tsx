import { Outlet, NavLink, useNavigate, useParams } from 'react-router-dom'
import { useAuthStore } from '@/stores/auth'
import { doLogout } from '@/lib/logout'
import { Users, Shield, KeyRound, Palette, FileText, LogOut, LayoutDashboard, ArrowLeft, Network, FolderOpen, Activity, Settings2, Globe, Layers, ShieldCheck, ShieldAlert, Award, BadgeCheck, BarChart2, FlaskConical, Webhook, Share2, ScrollText, Radio, Brain, SlidersHorizontal, QrCode, Rocket, ScanLine, Zap, Database, ClipboardCheck, GitBranch, ShieldOff, Sparkles, Bot, Cpu, Share, ArrowRightLeft, MailCheck, Gauge, LayoutTemplate, UserPlus, PieChart, Antenna, Store, RotateCw } from 'lucide-react'
import { ClavexLogo } from '@/components/logo/ClavexLogo'

export default function TenantLayout() {
  const { orgSlug } = useParams<{ orgSlug: string }>()
  const { email, isSuperAdmin } = useAuthStore()
  const navigate = useNavigate()
  const base = `/admin/${orgSlug}`

  const navGroups = [
    {
      label: 'Get Started',
      items: [
        { to: `${base}/onboarding`, icon: Rocket, label: 'Launch' },
      ],
    },
    {
      label: 'Directory',
      items: [
        { to: base,              icon: LayoutDashboard, label: 'Overview',  end: true },
        { to: `${base}/users`,   icon: Users,           label: 'Users'               },
        { to: `${base}/roles`,   icon: Shield,          label: 'Roles'               },
        { to: `${base}/groups`,  icon: FolderOpen,      label: 'Groups'              },
      ],
    },
    {
      label: 'Applications',
      items: [
        { to: `${base}/clients`,          icon: KeyRound, label: 'OIDC Clients'       },
        { to: `${base}/client-scopes`,    icon: Layers,   label: 'Client Scopes'      },
        { to: `${base}/service-accounts`, icon: Bot,      label: 'Service Accounts'   },
        { to: `${base}/agent-tokens`,     icon: Cpu,      label: 'Agent Tokens (MCP)' },
        { to: `${base}/api-keys`,         icon: KeyRound, label: 'API Keys'           },
        { to: `${base}/wsfed-rps`,        icon: Globe,    label: 'WS-Federation'      },
        { to: `${base}/app-families`,     icon: Layers,   label: 'App Families'       },
        { to: `${base}/ldap`,             icon: Network,  label: 'Sync (LDAP)'        },
      ],
    },
    {
      label: 'Identity & Access',
      items: [
        { to: `${base}/login-flows`,      icon: GitBranch,      label: 'Login Flows'      },
        { to: `${base}/actions`,          icon: Zap,            label: 'Actions V2'       },
        { to: `${base}/lifecycle-rules`,  icon: Zap,            label: 'Lifecycle Rules'  },
        { to: `${base}/lifecycle-report`, icon: PieChart,       label: 'Lifecycle Report' },
        { to: `${base}/access-reviews`,   icon: ClipboardCheck, label: 'Access Reviews'   },
        { to: `${base}/admin-delegation`, icon: Shield,         label: 'Delegated Admins' },
        { to: `${base}/cross-org-trust`,  icon: ArrowRightLeft, label: 'Cross-Org Trust'  },
        { to: `${base}/ai-assistant`,     icon: Sparkles,       label: 'AI Assistant'     },
      ],
    },
    {
      label: 'EU Identity',
      items: [
        { to: `${base}/identity-providers`,   icon: Globe,       label: 'EuroID'            },
        { to: `${base}/spid`,                 icon: ShieldCheck, label: 'SPID SP'           },
        { to: `${base}/eidas`,                icon: Globe,       label: 'eIDAS Node'        },
        { to: `${base}/eidas-rp-metadata`,    icon: Shield,      label: 'eIDAS RP Metadata' },
        { to: `${base}/credential-offers`,    icon: QrCode,      label: 'Wallet'            },
        { to: `${base}/verified-credentials`, icon: Award,       label: 'Clavex Verified'   },
        { to: `${base}/marketplace`,          icon: Store,       label: 'Marketplace'       },
        { to: `${base}/wallet-verifier`,      icon: ScanLine,    label: 'Wallet Verifier'   },
        { to: `${base}/qtsp-assessment`,      icon: Award,       label: 'QTSP Readiness'    },
      ],
    },
    {
      label: 'Security',
      items: [
        { to: `${base}/security-center`,             icon: ShieldCheck, label: 'Security Center'     },
        { to: `${base}/shield-dashboard`,            icon: ShieldAlert, label: 'Threat Intelligence' },
        { to: `${base}/risk-dashboard`,              icon: BarChart2,   label: 'Risk Dashboard'      },
        { to: `${base}/login-intelligence`,          icon: Brain,       label: 'Login Intelligence'  },
        { to: `${base}/lockout-admin`,               icon: ShieldOff,   label: 'Guard Unlock'        },
        { to: `${base}/ip-rules`,                    icon: Network,     label: 'IP Rules'            },
        { to: `${base}/security/breached-passwords`, icon: ShieldAlert, label: 'Breached Passwords'  },
        { to: `${base}/captcha`,                     icon: ShieldCheck, label: 'CAPTCHA'             },
        { to: `${base}/passkey-policy`,              icon: ShieldCheck, label: 'Keys'                },
        { to: `${base}/passkey-exchange`,            icon: KeyRound,    label: 'Keys Portability'    },
        { to: `${base}/mds-catalog`,                 icon: Database,    label: 'TrustScore (MDS3)'   },
        { to: `${base}/key-rotation`,                icon: RotateCw,    label: 'Key Rotation'        },
      ],
    },
    {
      label: 'Authorization',
      items: [
        { to: `${base}/fga`,                   icon: Share,            label: 'Fine-Grained Authz' },
        { to: `${base}/policy-editor`,         icon: SlidersHorizontal,label: 'Shield'             },
        { to: `${base}/policy-simulate`,       icon: FlaskConical,     label: 'Policy Dry-Run'     },
        { to: `${base}/policy-batch-simulate`, icon: BarChart2,        label: 'Batch Simulate'     },
        { to: `${base}/pam`,                   icon: KeyRound,         label: 'Privileged Access'  },
        { to: `${base}/grants`,                icon: ScrollText,       label: 'Consent Grants'     },
      ],
    },
    {
      label: 'Compliance',
      items: [
        { to: `${base}/compliance`,      icon: FileText,       label: 'GDPR Compliance'   },
        { to: `${base}/audit`,           icon: FileText,       label: 'Audit Log'         },
        { to: `${base}/audit-sinks`,     icon: Antenna,        label: 'Audit Sinks'       },
        { to: `${base}/scim-compliance`, icon: ClipboardCheck, label: 'SCIM Audit Trail'  },
        { to: `${base}/ssf-streams`,     icon: Radio,          label: 'Signals (SSF/CAEP)'},
        { to: `${base}/cae-monitor`,     icon: Zap,            label: 'CAE Token Push'    },
        { to: `${base}/entity-review`,   icon: ClipboardCheck, label: 'Entity Review'     },
        { to: `${base}/credentials`,     icon: BadgeCheck,     label: 'Credential Status' },
      ],
    },
    {
      label: 'Configuration',
      items: [
        { to: `${base}/settings`,        icon: Settings2,      label: 'Settings'          },
        { to: `${base}/branding`,        icon: Palette,        label: 'Branding'          },
        { to: `${base}/login-template`,  icon: LayoutTemplate, label: 'Login Template'    },
        { to: `${base}/email-policy`,    icon: MailCheck,      label: 'Email Policy'      },
        { to: `${base}/rate-limits`,     icon: Gauge,          label: 'Rate Limits'       },
        { to: `${base}/enrichment-hook`, icon: Zap,            label: 'Claims Enrichment' },
        { to: `${base}/auto-enroll`,     icon: UserPlus,       label: 'Auto-Enroll'       },
        { to: `${base}/scim-push`,       icon: Share2,         label: 'Sync'              },
        { to: `${base}/stream`,          icon: Zap,            label: 'Clavex Stream'     },
        { to: `${base}/webhooks`,        icon: Webhook,        label: 'Webhooks'          },
        { to: `${base}/sessions`,        icon: Activity,       label: 'Sessions'          },
      ],
    },
  ]

  return (
    <div className="flex h-screen" style={{ background: 'var(--clavex-surface)' }}>
      <aside
        className="w-56 flex flex-col flex-shrink-0"
        style={{ background: 'var(--clavex-dark)', borderRight: '0.5px solid rgba(93,202,165,0.15)' }}
      >
        {/* Logo */}
        <div className="h-16 flex items-center px-5" style={{ borderBottom: '0.5px solid rgba(93,202,165,0.12)' }}>
          <ClavexLogo variant="dark" size={0.55} />
        </div>

        {/* Realm indicator */}
        <div className="px-4 py-3" style={{ borderBottom: '0.5px solid rgba(93,202,165,0.08)' }}>
          <div className="flex items-center gap-2">
            <span
              className="block h-1.5 w-1.5 rounded-full flex-shrink-0"
              style={{ background: 'var(--clavex-primary)' }}
            />
            <span style={{ fontSize: 12, fontWeight: 600, color: '#C4DFF0' }} className="truncate">{orgSlug}</span>
          </div>
          <p style={{ fontSize: 10, color: 'rgba(196, 223, 240, 0.35)', marginTop: 2 }}>Active Space</p>
        </div>

        {/* Nav */}
        <nav className="flex-1 p-3 space-y-4 overflow-y-auto">
          {navGroups.map((group) => (
            <div key={group.label}>
              <p style={{
                fontSize: 10, fontWeight: 700, letterSpacing: '1.5px',
                color: 'rgba(196, 223, 240, 0.35)',
                padding: '4px 12px',
                textTransform: 'uppercase',
              }}>{group.label}</p>
              <div className="space-y-0.5 mt-1">
                {group.items.map(({ to, icon: Icon, label, end }) => (
                  <NavLink
                    key={to}
                    to={to}
                    end={end}
                    className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
                  >
                    <Icon className="h-4 w-4" />
                    {label}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>

        {/* Footer */}
        <div className="p-4" style={{ borderTop: '0.5px solid rgba(93,202,165,0.12)' }}>
          {isSuperAdmin && (
            <button
              onClick={() => navigate('/admin/orgs')}
              style={{ color: 'rgba(196, 223, 240, 0.45)', fontSize: 12 }}
              className="flex items-center gap-2 w-full px-2 py-1.5 rounded-lg hover:text-[#9FE1CB] transition-colors mb-3"
            >
              <ArrowLeft className="h-3.5 w-3.5" />
              All Spaces
            </button>
          )}
          <div className="flex items-center gap-3">
            <div
              className="h-8 w-8 rounded-full flex items-center justify-center flex-shrink-0"
              style={{ background: 'var(--clavex-dark-surface)', border: '0.5px solid var(--clavex-primary)' }}
            >
              <span style={{ color: 'var(--clavex-400)', fontSize: 11, fontWeight: 700 }}>
                {email?.[0]?.toUpperCase() ?? 'A'}
              </span>
            </div>
            <div className="flex-1 min-w-0">
              <p style={{ fontSize: 12, fontWeight: 500, color: '#C4DFF0' }} className="truncate">{email}</p>
              <p style={{ fontSize: 10, color: 'rgba(196, 223, 240, 0.4)' }}>Admin</p>
            </div>
            <button
              onClick={async () => { await doLogout(); navigate('/login') }}
              style={{ color: 'rgba(196, 223, 240, 0.35)', padding: 4, borderRadius: 6 }}
              className="hover:text-red-400 transition-colors"
              title="Sign out"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </div>
      </aside>

      <main className="flex-1 overflow-y-auto">
        <div className="max-w-6xl mx-auto p-8">
          <Outlet />
        </div>
      </main>
    </div>
  )
}
