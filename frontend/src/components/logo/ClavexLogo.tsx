interface ClavexLogoProps {
  variant?: 'light' | 'dark' | 'icon-light' | 'icon-teal' | 'icon-dark'
  size?: number
}

export function ClavexLogo({ variant = 'light', size = 1 }: ClavexLogoProps) {
  if (variant === 'icon-teal') {
    return (
      <svg width={48 * size} height={48 * size} viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect width="48" height="48" rx="12" fill="#1D9E75"/>
        <g transform="translate(24, 24) rotate(-45)">
          <circle cx="0" cy="0" r="9" fill="none" stroke="white" strokeWidth="3.5" strokeDasharray="42 12"/>
          <circle cx="0" cy="0" r="4" fill="none" stroke="rgba(255,255,255,0.6)" strokeWidth="2"/>
          <line x1="8.5" y1="0" x2="22" y2="0" stroke="white" strokeWidth="3.5" strokeLinecap="round"/>
          <rect x="14" y="-5.5" width="3.5" height="5.5" rx="1" fill="white"/>
          <rect x="19" y="-5.5" width="3.5" height="5.5" rx="1" fill="white"/>
        </g>
      </svg>
    )
  }

  if (variant === 'icon-light') {
    return (
      <svg width={48 * size} height={48 * size} viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect width="48" height="48" rx="12" fill="#E1F5EE"/>
        <g transform="translate(24, 24) rotate(-45)">
          <circle cx="0" cy="0" r="9" fill="none" stroke="#1D9E75" strokeWidth="3.5" strokeDasharray="42 12"/>
          <circle cx="0" cy="0" r="4" fill="none" stroke="#0F6E56" strokeWidth="2"/>
          <line x1="8.5" y1="0" x2="22" y2="0" stroke="#1D9E75" strokeWidth="3.5" strokeLinecap="round"/>
          <rect x="14" y="-5.5" width="3.5" height="5.5" rx="1" fill="#1D9E75"/>
          <rect x="19" y="-5.5" width="3.5" height="5.5" rx="1" fill="#1D9E75"/>
        </g>
      </svg>
    )
  }

  if (variant === 'icon-dark') {
    return (
      <svg width={48 * size} height={48 * size} viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect width="48" height="48" rx="12" fill="#0D1F2D"/>
        <g transform="translate(24, 24) rotate(-45)">
          <circle cx="0" cy="0" r="9" fill="none" stroke="#5DCAA5" strokeWidth="3.5" strokeDasharray="42 12"/>
          <circle cx="0" cy="0" r="4" fill="none" stroke="#1D9E75" strokeWidth="2"/>
          <line x1="8.5" y1="0" x2="22" y2="0" stroke="#5DCAA5" strokeWidth="3.5" strokeLinecap="round"/>
          <rect x="14" y="-5.5" width="3.5" height="5.5" rx="1" fill="#5DCAA5"/>
          <rect x="19" y="-5.5" width="3.5" height="5.5" rx="1" fill="#5DCAA5"/>
        </g>
      </svg>
    )
  }

  const isDark = variant === 'dark'
  const ink = isDark ? '#C4DFF0' : '#1A2332'
  const accent = isDark ? '#5DCAA5' : '#0F6E56'
  const primary = isDark ? '#5DCAA5' : '#1D9E75'

  return (
    <svg width={220 * size} height={60 * size} viewBox="0 0 220 60" fill="none" xmlns="http://www.w3.org/2000/svg">
      <g transform="translate(14, 30) rotate(-45)">
        <circle cx="0" cy="0" r="12" fill="none" stroke={primary} strokeWidth="4" strokeDasharray="56 16"/>
        <circle cx="0" cy="0" r="5.5" fill="none" stroke={accent} strokeWidth="2.5"/>
        <line x1="11" y1="0" x2="30" y2="0" stroke={primary} strokeWidth="4" strokeLinecap="round"/>
        <rect x="20" y="-7" width="4" height="7" rx="1.2" fill={primary}/>
        <rect x="26" y="-7" width="4" height="7" rx="1.2" fill={primary}/>
      </g>
      <text
        x="46" y="38"
        fontFamily="'Plus Jakarta Sans', sans-serif"
        fontSize="34" fontWeight="300" fill={ink} letterSpacing="-0.5"
      >cl</text>
      <text
        x="74" y="38"
        fontFamily="'Plus Jakarta Sans', sans-serif"
        fontSize="34" fontWeight="700" fill={accent} letterSpacing="-0.5"
      >avex</text>
      <rect x="46" y="44" width="26" height="3" rx="1.5" fill={primary}/>
    </svg>
  )
}
