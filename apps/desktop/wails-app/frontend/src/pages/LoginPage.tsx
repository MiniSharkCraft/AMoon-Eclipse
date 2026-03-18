import { useState, useEffect } from 'react'
import { useAuthStore, API } from '../stores/authStore'
import { hashPassword } from '../lib/crypto'

// Wails runtime types
declare const window: Window & {
  go?: { main: { App: { StartGoogleOAuth: () => Promise<void> } } }
  runtime?: { EventsOn: (e: string, cb: (data: unknown) => void) => void }
}

type Tab    = 'password' | 'google'
type Mode   = 'login' | 'register'
type Screen = 'main' | 'forgot' | 'reset'

export function LoginPage() {
  const [tab,    setTab]    = useState<Tab>('password')
  const [mode,   setMode]   = useState<Mode>('login')
  const [screen, setScreen] = useState<Screen>('main')

  const [username,          setUsername]          = useState('')
  const [email,             setEmail]             = useState('')
  const [password,          setPassword]          = useState('')
  const [passphrase,        setPassphrase]        = useState('')
  const [confirmPassphrase, setConfirmPassphrase] = useState('')

  // Forgot password
  const [fpEmail,   setFpEmail]   = useState('')
  const [fpOtp,     setFpOtp]     = useState('')
  const [fpNewPass, setFpNewPass] = useState('')
  const [fpStep,    setFpStep]    = useState<'email' | 'otp'>('email')

  const [error,   setError]   = useState<string | null>(null)
  const [info,    setInfo]    = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const { login, register, loginWithOAuth } = useAuthStore()

  // Listen for Google OAuth token from Go (Wails event)
  useEffect(() => {
    window.runtime?.EventsOn('oauth:google', async (token: unknown) => {
      setLoading(true); setError(null)
      try {
        await loginWithOAuth(token as string, passphrase || undefined)
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : 'Google login failed')
      } finally { setLoading(false) }
    })
  }, [passphrase])

  const wrap = async (fn: () => Promise<void>) => {
    setError(null); setInfo(null); setLoading(true)
    try { await fn() } catch (e: unknown) { setError(e instanceof Error ? e.message : String(e)) }
    finally { setLoading(false) }
  }

  // ── Password auth ─────────────────────────────────────────────────────────
  const submitPassword = (e: React.FormEvent) => {
    e.preventDefault()
    wrap(async () => {
      if (mode === 'register') {
        if (!email.trim())       throw new Error('Email is required (for password recovery)')
        if (!passphrase.trim())  throw new Error('Passphrase is required (protects your E2EE keys)')
        if (passphrase !== confirmPassphrase) throw new Error('Passphrases do not match')
        await register(username, email, password, passphrase)
      } else {
        await login(username, password)
      }
    })
  }

  // ── Google OAuth ──────────────────────────────────────────────────────────
  const startGoogle = () => {
    if (mode === 'register' && passphrase !== confirmPassphrase) {
      setError('Passphrases do not match'); return
    }
    wrap(async () => {
      if (window.go?.main?.App?.StartGoogleOAuth) {
        await window.go.main.App.StartGoogleOAuth()
        setInfo('Browser opened — complete sign-in then return here.')
      } else {
        throw new Error('Wails runtime not available')
      }
    })
  }

  // ── Forgot password ───────────────────────────────────────────────────────
  const submitForgotEmail = (e: React.FormEvent) => {
    e.preventDefault()
    wrap(async () => {
      const res = await fetch(`${API}/api/auth/forgot-password`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: fpEmail }),
      })
      if (!res.ok) throw new Error((await res.json()).error)
      setInfo('OTP sent! Check your inbox (expires in 10 min).')
      setFpStep('otp')
    })
  }

  const submitForgotReset = (e: React.FormEvent) => {
    e.preventDefault()
    wrap(async () => {
      const passwordHash = await hashPassword(fpNewPass)
      const res = await fetch(`${API}/api/auth/reset-password`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: fpEmail, otp: fpOtp, password: passwordHash }),
      })
      if (!res.ok) throw new Error((await res.json()).error)
      setInfo('Password reset! You can now log in.')
      setScreen('main'); setFpStep('email'); setFpEmail(''); setFpOtp(''); setFpNewPass('')
    })
  }

  // ─────────────────────────────────────────────────────────────────────────
  return (
    <div className="flex h-screen bg-dark-900 font-mono overflow-hidden">
      {/* ── Left: Brand panel ─────────────────────────────────────────────── */}
      <div className="w-[420px] shrink-0 flex flex-col justify-between p-10 border-r border-dark-400 relative overflow-hidden">
        {/* Background glow */}
        <div className="absolute -top-32 -left-32 w-80 h-80 bg-neon-cyan/5 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute -bottom-32 -right-16 w-64 h-64 bg-neon-magenta/5 rounded-full blur-3xl pointer-events-none" />

        {/* Logo */}
        <div>
          <div className="flex items-center gap-3 mb-10">
            {/* Moon icon */}
            <div className="relative w-10 h-10">
              <div className="w-10 h-10 rounded-full bg-neon-cyan/20 border border-neon-cyan/40 flex items-end justify-end p-1">
                <div className="w-6 h-6 rounded-full bg-dark-900" />
              </div>
              <div className="absolute top-0.5 right-0.5 w-2 h-2 rounded-full bg-neon-cyan animate-pulse-neon" />
            </div>
            <div>
              <p className="text-neon-cyan text-lg font-bold tracking-wider leading-none">AMoon</p>
              <p className="text-neon-magenta text-xs tracking-[0.3em] leading-none mt-0.5">ECLIPSE</p>
            </div>
          </div>

          <h1 className="text-white text-3xl font-bold leading-tight mb-4">
            Secure.<br/>Private.<br/>Encrypted.
          </h1>
          <p className="text-dark-400 text-sm leading-relaxed">
            End-to-end encrypted messenger. Your keys never leave your device — not even we can read your messages.
          </p>
        </div>

        {/* Features */}
        <div className="space-y-4">
          {[
            { icon: '🔐', title: 'Zero-Knowledge E2EE', desc: 'RSA-2048 + AES-256-GCM per message' },
            { icon: '🔑', title: 'Passphrase Recovery', desc: 'Restore keys on new devices securely' },
            { icon: '🌐', title: 'Google Sign-In', desc: 'OAuth 2.0 via system browser' },
          ].map(f => (
            <div key={f.title} className="flex gap-3">
              <span className="text-lg shrink-0">{f.icon}</span>
              <div>
                <p className="text-neon-cyan text-xs font-semibold tracking-wider">{f.title}</p>
                <p className="text-dark-400 text-xs mt-0.5">{f.desc}</p>
              </div>
            </div>
          ))}
        </div>

        {/* Version */}
        <p className="text-dark-400/50 text-xs">Beta v1.0</p>
      </div>

      {/* ── Right: Form panel ─────────────────────────────────────────────── */}
      <div className="flex-1 flex items-center justify-center p-12 overflow-y-auto">
        <div className="w-full max-w-md">

          {/* ── Forgot password screens ────────────────────────────────── */}
          {screen !== 'main' ? (
            <div className="space-y-6">
              <button onClick={() => setScreen('main')} className="text-xs text-dark-400 hover:text-neon-cyan transition-colors flex items-center gap-1">
                ← Back to login
              </button>
              <div>
                <h2 className="text-white text-xl font-bold mb-1">Forgot Password</h2>
                <p className="text-dark-400 text-sm">
                  {fpStep === 'email' ? 'Enter your registered email to receive an OTP.' : 'Enter the OTP from your email and set a new password.'}
                </p>
              </div>

              <Feedback error={error} info={info} />

              {fpStep === 'email' ? (
                <form onSubmit={submitForgotEmail} className="space-y-4">
                  <FormField label="Email address" type="email" value={fpEmail} onChange={setFpEmail} placeholder="you@example.com" />
                  <Btn loading={loading} label="Send OTP" />
                </form>
              ) : (
                <form onSubmit={submitForgotReset} className="space-y-4">
                  <FormField label="OTP Code" value={fpOtp} onChange={setFpOtp} placeholder="6-digit code" />
                  <FormField label="New Password" type="password" value={fpNewPass} onChange={setFpNewPass} placeholder="new password" />
                  <Btn loading={loading} label="Reset Password" />
                  <button type="button" onClick={() => setFpStep('email')} className="text-xs text-dark-400 hover:text-neon-cyan w-full text-center transition-colors">
                    Resend OTP
                  </button>
                </form>
              )}
            </div>
          ) : (
            <>
              <h2 className="text-white text-2xl font-bold mb-2">
                {mode === 'login' ? 'Welcome back' : 'Create account'}
              </h2>
              <p className="text-dark-400 text-sm mb-7">
                {mode === 'login' ? 'Sign in to your encrypted workspace.' : 'Set up your zero-knowledge identity.'}
              </p>

              {/* ── Tab: Password / Google ────────────────────────────── */}
              <div className="flex bg-dark-800 rounded-cyber p-0.5 mb-6 border border-dark-400">
                {(['password', 'google'] as Tab[]).map(t => (
                  <button key={t} onClick={() => setTab(t)}
                    className={`flex-1 py-2 text-xs rounded-cyber transition-all font-semibold uppercase tracking-widest ${
                      tab === t ? 'bg-dark-600 text-neon-cyan shadow-sm border border-dark-400' : 'text-dark-400 hover:text-neon-cyan'
                    }`}
                  >
                    {t === 'password' ? 'Password' : 'Google'}
                  </button>
                ))}
              </div>

              {/* ── Mode: Login / Register ────────────────────────────── */}
              <div className="flex gap-3 mb-6">
                {(['login', 'register'] as Mode[]).map(m => (
                  <button key={m} onClick={() => setMode(m)}
                    className={`px-4 py-1.5 text-xs rounded-cyber border transition-all ${
                      mode === m ? 'border-neon-cyan text-neon-cyan' : 'border-dark-400 text-dark-400 hover:border-dark-400/70 hover:text-neon-cyan/60'
                    }`}
                  >
                    {m === 'login' ? 'Sign In' : 'Register'}
                  </button>
                ))}
              </div>

              <Feedback error={error} info={info} />

              {/* ── Passphrase fields (shared for both tabs when registering) ── */}
              {tab === 'google' ? (
                <div className="space-y-4">
                  {mode === 'register' && (
                    <div className="space-y-3">
                      <PassphraseFields
                        passphrase={passphrase} setPassphrase={setPassphrase}
                        confirm={confirmPassphrase} setConfirm={setConfirmPassphrase}
                      />
                    </div>
                  )}

                  <button
                    type="button"
                    onClick={startGoogle}
                    disabled={loading}
                    className="w-full flex items-center justify-center gap-3 bg-white/5 border border-dark-400 text-white py-3 rounded-cyber hover:bg-white/10 hover:border-neon-cyan/40 transition-all disabled:opacity-40"
                  >
                    <span className="w-5 h-5 rounded-full bg-white flex items-center justify-center text-xs font-black text-gray-800">G</span>
                    <span className="text-sm font-semibold">{loading ? 'Opening browser...' : 'Continue with Google'}</span>
                  </button>

                  <p className="text-dark-400/60 text-xs text-center">
                    Opens your system browser to authenticate with Google.
                  </p>
                </div>
              ) : (
                <form onSubmit={submitPassword} className="space-y-4">
                  <FormField label="Username" value={username} onChange={setUsername} placeholder="your_username" autoComplete="username" />

                  {mode === 'register' && (
                    <FormField label="Email" type="email" value={email} onChange={setEmail} placeholder="you@example.com" autoComplete="email" />
                  )}

                  <FormField label="Password" type="password" value={password} onChange={setPassword} placeholder="••••••••"
                    autoComplete={mode === 'register' ? 'new-password' : 'current-password'} />

                  {mode === 'register' && (
                    <PassphraseFields
                      passphrase={passphrase} setPassphrase={setPassphrase}
                      confirm={confirmPassphrase} setConfirm={setConfirmPassphrase}
                    />
                  )}

                  <Btn loading={loading} label={mode === 'login' ? 'Sign In' : 'Create Account'} />

                  {mode === 'login' && (
                    <button type="button" onClick={() => setScreen('forgot')}
                      className="w-full text-center text-xs text-dark-400 hover:text-neon-cyan transition-colors mt-1"
                    >
                      Forgot password?
                    </button>
                  )}

                  {mode === 'register' && (
                    <p className="text-xs text-dark-400/70 text-center leading-relaxed">
                      Your private key is generated locally.<br/>
                      <span className="text-neon-yellow/80">The server never sees it.</span>
                    </p>
                  )}
                </form>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Shared subcomponents ─────────────────────────────────────────────────────
function FormField({ label, value, onChange, type = 'text', placeholder, autoComplete }: {
  label: string; value: string; onChange: (v: string) => void
  type?: string; placeholder?: string; autoComplete?: string
}) {
  return (
    <div>
      <label className="block text-xs text-dark-400 tracking-wider mb-1.5 uppercase">{label}</label>
      <input
        type={type} value={value} onChange={e => onChange(e.target.value)}
        placeholder={placeholder} autoComplete={autoComplete} required
        className="cyber-input w-full text-sm"
      />
    </div>
  )
}

function PassphraseFields({ passphrase, setPassphrase, confirm, setConfirm }: {
  passphrase: string; setPassphrase: (v: string) => void
  confirm: string;    setConfirm:    (v: string) => void
}) {
  return (
    <div className="rounded-cyber border border-neon-yellow/20 bg-neon-yellow/5 p-4 space-y-3">
      <div className="flex items-start gap-2">
        <span className="text-neon-yellow text-xs mt-0.5">⚠</span>
        <p className="text-xs text-neon-yellow/80 leading-relaxed">
          <strong>Passphrase</strong> protects your E2EE key backup. If you forget it, you cannot read old messages on new devices.
        </p>
      </div>
      <FormField label="Passphrase" type="password" value={passphrase} onChange={setPassphrase} placeholder="memorable secret phrase" autoComplete="new-password" />
      <FormField label="Confirm Passphrase" type="password" value={confirm} onChange={setConfirm} placeholder="repeat passphrase" autoComplete="new-password" />
    </div>
  )
}

function Feedback({ error, info }: { error: string | null; info: string | null }) {
  if (!error && !info) return null
  return (
    <div className="mb-4">
      {error && <p className="text-red-400 text-xs border border-red-900 bg-red-950/30 rounded-cyber px-3 py-2.5">⚠ {error}</p>}
      {info  && <p className="text-neon-green text-xs border border-neon-green/30 bg-neon-green/10 rounded-cyber px-3 py-2.5">✓ {info}</p>}
    </div>
  )
}

function Btn({ loading, label }: { loading: boolean; label: string }) {
  return (
    <button type="submit" className="cyber-btn w-full py-3" disabled={loading}>
      {loading ? 'Processing...' : label}
    </button>
  )
}
