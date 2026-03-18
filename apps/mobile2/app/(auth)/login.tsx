import 'expo-standard-web-crypto'
import { useState } from 'react'
import {
  View, Text, TextInput, TouchableOpacity, Alert,
  KeyboardAvoidingView, Platform, ScrollView,
  ActivityIndicator, StatusBar, StyleSheet, SafeAreaView,
} from 'react-native'
import { router } from 'expo-router'
import * as SecureStore from 'expo-secure-store'
import * as WebBrowser from 'expo-web-browser'
import * as Linking from 'expo-linking'
import {
  generateRsaKeyPair, exportRsaKeyPair,
  importRsaPrivateKey, publicKeyFingerprint,
  encryptPrivateKeyWithPassphrase,
} from '../../src/lib/crypto'

const API = process.env.EXPO_PUBLIC_API_URL ?? process.env.EXPO_PUBLIC_API_URL ?? 'http://localhost:8080'

async function setupAndSaveKey(userId: string, token: string, passphrase?: string) {
  const existing = await SecureStore.getItemAsync(`privateKey_${userId}`)
  if (existing) return

  const kp = await generateRsaKeyPair()
  const { publicKey, privateKey } = await exportRsaKeyPair(kp)
  const fingerprint = await publicKeyFingerprint(publicKey)

  await SecureStore.setItemAsync(`privateKey_${userId}`, privateKey)
  await fetch(`${API}/api/auth/register-key`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ publicKey, fingerprint }),
  })

  if (passphrase) {
    const { encryptedKey, keySalt } = await encryptPrivateKeyWithPassphrase(privateKey, passphrase)
    await fetch(`${API}/api/auth/store-encrypted-key`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ encryptedKey, keySalt }),
    })
  }
}

type Screen = 'main' | 'forgotPassword' | 'forgotUsername'

export default function LoginScreen() {
  const [tab,    setTab]    = useState<'oauth' | 'password'>('oauth')
  const [mode,   setMode]   = useState<'login' | 'register'>('login')
  const [screen, setScreen] = useState<Screen>('main')

  const [username,          setUsername]          = useState('')
  const [email,             setEmail]             = useState('')
  const [password,          setPassword]          = useState('')
  const [passphrase,        setPassphrase]        = useState('')
  const [confirmPassphrase, setConfirmPassphrase] = useState('')

  const [fpEmail,   setFpEmail]   = useState('')
  const [fpOtp,     setFpOtp]     = useState('')
  const [fpNewPass, setFpNewPass] = useState('')
  const [fpStep,    setFpStep]    = useState<'email' | 'otp'>('email')

  const [loading, setLoading] = useState<string | null>(null)
  const [focused, setFocused] = useState<string | null>(null)

  const isLoading = loading !== null

  // ── Google OAuth (server-side) ───────────────────────────────────────────
  const handleGoogle = async () => {
    if (mode === 'register' && passphrase !== confirmPassphrase) {
      Alert.alert('Lỗi', 'PIN không khớp'); return
    }
    setLoading('google')
    try {
      const result = await WebBrowser.openAuthSessionAsync(
        `${API}/api/auth/google/start`,
        'amoon-eclipse://auth'
      )
      if (result.type !== 'success') { setLoading(null); return }
      const { queryParams } = Linking.parse(result.url)
      if (!queryParams) { setLoading(null); return }
      if (queryParams.error) throw new Error(String(queryParams.error))
      const { token, userId, username } = queryParams as Record<string, string>
      await setupAndSaveKey(userId, token, passphrase || undefined)
      await Promise.all([
        SecureStore.setItemAsync('amoon_userId', userId),
        SecureStore.setItemAsync('amoon_username', username ?? ''),
        SecureStore.setItemAsync('amoon_token', token),
      ])
      router.replace('/(app)/(tabs)')
    } catch (err: unknown) {
      Alert.alert('Lỗi Google', err instanceof Error ? err.message : 'Thất bại')
    } finally { setLoading(null) }
  }

  // ── Password register/login ──────────────────────────────────────────────────
  const handlePassword = async () => {
    if (!username.trim() || !password.trim()) {
      Alert.alert('Thiếu thông tin', 'Điền đủ username và mật khẩu nha.'); return
    }
    if (mode === 'register') {
      if (!email.trim()) { Alert.alert('Thiếu email'); return }
      if (!/^\d{6}$/.test(passphrase)) { Alert.alert('PIN không hợp lệ', 'PIN bảo vệ E2EE phải đúng 6 chữ số'); return }
      if (passphrase !== confirmPassphrase) { Alert.alert('Lỗi', 'PIN không khớp'); return }
    }
    setLoading('password')
    try {
      if (mode === 'register') {
        const kp = await generateRsaKeyPair()
        const { publicKey, privateKey } = await exportRsaKeyPair(kp)
        const fingerprint = await publicKeyFingerprint(publicKey)
        const res = await fetch(`${API}/api/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: username.trim(), email: email.trim(), password, publicKey, fingerprint }),
        })
        if (!res.ok) {
          const body = await res.json()
          console.error('[register 400]', JSON.stringify(body))
          throw new Error(body.error ?? body.message ?? `Server ${res.status}`)
        }
        const data = await res.json() as { token: string; userId: string; username: string }
        await SecureStore.setItemAsync(`privateKey_${data.userId}`, privateKey)
        const { encryptedKey, keySalt } = await encryptPrivateKeyWithPassphrase(privateKey, passphrase)
        await fetch(`${API}/api/auth/store-encrypted-key`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${data.token}` },
          body: JSON.stringify({ encryptedKey, keySalt }),
        })
        await Promise.all([
          SecureStore.setItemAsync('amoon_userId', data.userId),
          SecureStore.setItemAsync('amoon_username', data.username),
          SecureStore.setItemAsync('amoon_token', data.token),
        ])
      } else {
        const res = await fetch(`${API}/api/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: username.trim(), password }),
        })
        if (!res.ok) {
          const body = await res.json()
          console.error('[login 400]', JSON.stringify(body))
          throw new Error(body.error ?? body.message ?? `Server ${res.status}`)
        }
        const data = await res.json() as { token: string; userId: string; id: string; username: string }
        const uid = data.userId ?? data.id
        const pk = await SecureStore.getItemAsync(`privateKey_${uid}`)
        await Promise.all([
          SecureStore.setItemAsync('amoon_userId', uid),
          SecureStore.setItemAsync('amoon_username', data.username),
          SecureStore.setItemAsync('amoon_token', data.token),
        ])
        if (!pk) {
          router.replace('/(auth)/recover-key'); return
        }
        await importRsaPrivateKey(pk)
      }
      router.replace('/(app)/(tabs)')
    } catch (err: unknown) {
      Alert.alert('Lỗi', err instanceof Error ? err.message : 'Có gì đó sai sai')
    } finally { setLoading(null) }
  }

  // ── Forgot username ──────────────────────────────────────────────────────────
  const handleForgotUsername = async () => {
    if (!fpEmail.trim()) { Alert.alert('Nhập email'); return }
    setLoading('fp')
    try {
      const res = await fetch(`${API}/api/auth/forgot-username`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: fpEmail.trim() }),
      })
      if (!res.ok) {
        const body = await res.json()
        throw new Error(body.error ?? `Lỗi ${res.status}`)
      }
      Alert.alert('Đã gửi', 'Kiểm tra email — username được gửi về hộp thư của bạn')
      setScreen('main')
      setFpEmail('')
    } catch (err: unknown) {
      Alert.alert('Lỗi', err instanceof Error ? err.message : 'Không gửi được')
    } finally { setLoading(null) }
  }

  // ── Forgot password ──────────────────────────────────────────────────────────
  const handleForgotSendOTP = async () => {
    if (!fpEmail.trim()) { Alert.alert('Nhập email'); return }
    setLoading('fp')
    try {
      const res = await fetch(`${API}/api/auth/forgot-password`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: fpEmail.trim() }),
      })
      if (!res.ok) {
        const body = await res.json()
        throw new Error(body.error ?? body.message ?? `Lỗi ${res.status}`)
      }
      setFpStep('otp')
      Alert.alert('Đã gửi', 'Kiểm tra email lấy mã OTP (10 phút)')
    } catch (err: unknown) {
      Alert.alert('Lỗi', err instanceof Error ? err.message : 'Không gửi được OTP')
    } finally { setLoading(null) }
  }

  const handleForgotReset = async () => {
    if (!fpOtp.trim() || !fpNewPass.trim()) { Alert.alert('Điền đủ thông tin'); return }
    setLoading('fp')
    try {
      const res = await fetch(`${API}/api/auth/reset-password`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: fpEmail, otp: fpOtp, password: fpNewPass }),
      })
      if (!res.ok) throw new Error(((await res.json()) as { error: string }).error)
      Alert.alert('Thành công', 'Mật khẩu đã được đặt lại')
      setScreen('main'); setFpStep('email'); setFpEmail(''); setFpOtp(''); setFpNewPass('')
    } catch (err: unknown) {
      Alert.alert('Lỗi', err instanceof Error ? err.message : 'OTP sai hoặc hết hạn')
    } finally { setLoading(null) }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  if (screen === 'forgotUsername') {
    return (
      <SafeAreaView style={s.root}>
        <StatusBar barStyle="light-content" backgroundColor="#08080F" />
        <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
          <ScrollView contentContainerStyle={s.scroll} keyboardShouldPersistTaps="handled">
            <TouchableOpacity onPress={() => setScreen('main')} style={{ marginBottom: 24 }}>
              <Text style={{ color: '#818CF8', fontSize: 15 }}>‹ Quay lại</Text>
            </TouchableOpacity>
            <Text style={[s.appName, { marginBottom: 8 }]}>Quên username?</Text>
            <Text style={{ color: '#64748B', fontSize: 13, marginBottom: 24 }}>Nhập email đăng ký — username sẽ được gửi về hộp thư.</Text>
            <Field label="Email đăng ký" value={fpEmail} onChange={setFpEmail}
              placeholder="email@example.com" focused={focused} focusKey="fpu"
              onFocus={() => setFocused('fpu')} onBlur={() => setFocused(null)} keyboardType="email-address" />
            <Btn label="Gửi username về email" onPress={handleForgotUsername} loading={loading === 'fp'} />
          </ScrollView>
        </KeyboardAvoidingView>
      </SafeAreaView>
    )
  }

  if (screen === 'forgotPassword') {
    return (
      <SafeAreaView style={s.root}>
        <StatusBar barStyle="light-content" backgroundColor="#08080F" />
        <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
          <ScrollView contentContainerStyle={s.scroll} keyboardShouldPersistTaps="handled">
            <TouchableOpacity onPress={() => setScreen('main')} style={{ marginBottom: 24 }}>
              <Text style={{ color: '#818CF8', fontSize: 15 }}>‹ Quay lại</Text>
            </TouchableOpacity>
            <Text style={[s.appName, { marginBottom: 24 }]}>Quên mật khẩu</Text>
            {fpStep === 'email' ? (
              <>
                <Field label="Email đăng ký" value={fpEmail} onChange={setFpEmail}
                  placeholder="email@example.com" focused={focused} focusKey="fpe"
                  onFocus={() => setFocused('fpe')} onBlur={() => setFocused(null)} keyboardType="email-address" />
                <Btn label="Gửi mã OTP" onPress={handleForgotSendOTP} loading={loading === 'fp'} />
              </>
            ) : (
              <>
                <Field label="Mã OTP (6 số)" value={fpOtp} onChange={setFpOtp}
                  placeholder="123456" focused={focused} focusKey="fpotp"
                  onFocus={() => setFocused('fpotp')} onBlur={() => setFocused(null)} keyboardType="numeric" />
                <Field label="Mật khẩu mới" value={fpNewPass} onChange={setFpNewPass}
                  placeholder="mật khẩu mới..." focused={focused} focusKey="fpnp"
                  onFocus={() => setFocused('fpnp')} onBlur={() => setFocused(null)} secure />
                <Btn label="Đặt lại mật khẩu" onPress={handleForgotReset} loading={loading === 'fp'} />
                <TouchableOpacity onPress={() => setFpStep('email')} style={{ marginTop: 12, alignItems: 'center' }}>
                  <Text style={{ color: '#64748B', fontSize: 13 }}>Gửi lại mã OTP</Text>
                </TouchableOpacity>
              </>
            )}
          </ScrollView>
        </KeyboardAvoidingView>
      </SafeAreaView>
    )
  }

  return (
    <SafeAreaView style={s.root}>
      <StatusBar barStyle="light-content" backgroundColor="#08080F" />
      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
        <ScrollView contentContainerStyle={s.scroll} keyboardShouldPersistTaps="handled" showsVerticalScrollIndicator={false}>

          {/* Logo */}
          <View style={s.hero}>
            <View style={s.moonWrap}>
              <View style={s.moonOuter}>
                <View style={s.moonInner} />
              </View>
              <View style={[s.orbitDot, { top: 4, right: 12 }]} />
              <View style={[s.orbitDot, { bottom: 10, left: 8, backgroundColor: '#EC4899', width: 5, height: 5 }]} />
            </View>
            <Text style={s.appName}>AMoon Eclipse</Text>
            <Text style={s.tagline}>Nhắn tin · Ẩn danh · An toàn</Text>
          </View>

          <View style={s.card}>
            {/* Tab */}
            <View style={s.tabRow}>
              {(['oauth', 'password'] as const).map(t => (
                <TouchableOpacity key={t} onPress={() => setTab(t)} style={[s.tab, tab === t && s.tabOn]} activeOpacity={0.7}>
                  <Text style={[s.tabTxt, tab === t && s.tabTxtOn]}>
                    {t === 'oauth' ? 'Đăng nhập nhanh' : 'Tài khoản'}
                  </Text>
                </TouchableOpacity>
              ))}
            </View>

            {/* Mode */}
            <View style={s.modeRow}>
              {(['login', 'register'] as const).map(m => (
                <TouchableOpacity key={m} onPress={() => setMode(m)} style={[s.modeBtn, mode === m && s.modeBtnOn]}>
                  <Text style={[s.modeTxt, mode === m && s.modeTxtOn]}>
                    {m === 'login' ? 'Đăng nhập' : 'Đăng ký'}
                  </Text>
                </TouchableOpacity>
              ))}
            </View>

            {tab === 'oauth' ? (
              <View>
                {mode === 'register' && (
                  <>
                    <Field label="PIN bảo vệ E2EE (6 số)" value={passphrase} onChange={t => setPassphrase(t.replace(/\D/g,'').slice(0,6))}
                      placeholder="6 chữ số..." focused={focused} focusKey="pp"
                      onFocus={() => setFocused('pp')} onBlur={() => setFocused(null)} secure keyboardType="numeric" />
                    <Field label="Xác nhận PIN" value={confirmPassphrase} onChange={t => setConfirmPassphrase(t.replace(/\D/g,'').slice(0,6))}
                      placeholder="nhập lại 6 số..." focused={focused} focusKey="cpp"
                      onFocus={() => setFocused('cpp')} onBlur={() => setFocused(null)} secure keyboardType="numeric" />
                    <Text style={s.passphraseHint}>⚠️ Ghi nhớ PIN 6 số này — quên sẽ mất tin nhắn cũ khi đổi thiết bị.</Text>
                  </>
                )}
                <TouchableOpacity style={[s.oauthBtn, isLoading && { opacity: 0.6 }]} onPress={handleGoogle} disabled={isLoading} activeOpacity={0.85}>
                  {loading === 'google'
                    ? <ActivityIndicator color="#fff" />
                    : (
                      <View style={s.oauthInner}>
                        <View style={s.oauthIconWrap}><Text style={s.oauthIcon}>G</Text></View>
                        <Text style={s.oauthTxt}>Tiếp tục với Google</Text>
                      </View>
                    )}
                </TouchableOpacity>
                <Text style={s.hint}>🔒 Khóa mã hóa tạo ngay trên thiết bị.</Text>
              </View>
            ) : (
              <View>
                <Field label="Tên người dùng" value={username} onChange={setUsername}
                  placeholder="username..." focused={focused} focusKey="u"
                  onFocus={() => setFocused('u')} onBlur={() => setFocused(null)} />
                {mode === 'register' && (
                  <Field label="Email (để khôi phục mật khẩu)" value={email} onChange={setEmail}
                    placeholder="email@example.com" focused={focused} focusKey="em"
                    onFocus={() => setFocused('em')} onBlur={() => setFocused(null)} keyboardType="email-address" />
                )}
                <Field label="Mật khẩu" value={password} onChange={setPassword}
                  placeholder="mật khẩu..." focused={focused} focusKey="p"
                  onFocus={() => setFocused('p')} onBlur={() => setFocused(null)} secure />
                {mode === 'register' && (
                  <>
                    <Field label="PIN bảo vệ E2EE (6 số)" value={passphrase} onChange={t => setPassphrase(t.replace(/\D/g,'').slice(0,6))}
                      placeholder="6 chữ số..." focused={focused} focusKey="pp"
                      onFocus={() => setFocused('pp')} onBlur={() => setFocused(null)} secure keyboardType="numeric" />
                    <Field label="Xác nhận PIN" value={confirmPassphrase} onChange={t => setConfirmPassphrase(t.replace(/\D/g,'').slice(0,6))}
                      placeholder="nhập lại 6 số..." focused={focused} focusKey="cpp"
                      onFocus={() => setFocused('cpp')} onBlur={() => setFocused(null)} secure keyboardType="numeric" />
                    <Text style={s.passphraseHint}>⚠️ PIN bảo vệ khóa E2EE. Quên = mất tin nhắn cũ khi đổi thiết bị.</Text>
                  </>
                )}
                <TouchableOpacity style={[s.btn, isLoading && { opacity: 0.6 }]} onPress={handlePassword} disabled={isLoading} activeOpacity={0.85}>
                  {loading === 'password'
                    ? <ActivityIndicator color="#fff" />
                    : <Text style={s.btnTxt}>{mode === 'login' ? 'Đăng nhập →' : 'Tạo tài khoản →'}</Text>
                  }
                </TouchableOpacity>
                {mode === 'login' && (
                  <View style={{ marginTop: 16, alignItems: 'center', gap: 10 }}>
                    <TouchableOpacity onPress={() => setScreen('forgotPassword')}>
                      <Text style={{ color: '#6366F1', fontSize: 13 }}>Quên mật khẩu?</Text>
                    </TouchableOpacity>
                    <TouchableOpacity onPress={() => { setFpEmail(''); setScreen('forgotUsername') }}>
                      <Text style={{ color: '#4B5563', fontSize: 13 }}>Quên username?</Text>
                    </TouchableOpacity>
                  </View>
                )}
              </View>
            )}
          </View>
        </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  )
}

// ─── Shared components ────────────────────────────────────────────────────────
function Field({ label, value, onChange, placeholder, focused, focusKey, onFocus, onBlur, secure, keyboardType }: {
  label: string; value: string; onChange: (v: string) => void
  placeholder: string; focused: string | null; focusKey: string
  onFocus: () => void; onBlur: () => void; secure?: boolean
  keyboardType?: 'email-address' | 'numeric' | 'default'
}) {
  return (
    <View style={s.fieldWrap}>
      <Text style={s.label}>{label}</Text>
      <TextInput
        style={[s.input, focused === focusKey && s.inputOn]}
        placeholder={placeholder} placeholderTextColor="#2E2E45"
        value={value} onChangeText={onChange}
        onFocus={onFocus} onBlur={onBlur}
        secureTextEntry={secure} autoCapitalize="none" autoCorrect={false}
        keyboardType={keyboardType ?? 'default'}
      />
    </View>
  )
}

function Btn({ label, onPress, loading }: { label: string; onPress: () => void; loading: boolean }) {
  return (
    <TouchableOpacity style={[s.btn, loading && { opacity: 0.6 }]} onPress={onPress} disabled={loading} activeOpacity={0.85}>
      {loading ? <ActivityIndicator color="#fff" /> : <Text style={s.btnTxt}>{label}</Text>}
    </TouchableOpacity>
  )
}

const s = StyleSheet.create({
  root:       { flex: 1, backgroundColor: '#08080F' },
  scroll:     { flexGrow: 1, justifyContent: 'center', paddingHorizontal: 20, paddingVertical: 36 },
  hero:       { alignItems: 'center', marginBottom: 36 },
  moonWrap:   { width: 80, height: 80, alignItems: 'center', justifyContent: 'center', marginBottom: 20 },
  moonOuter:  { width: 60, height: 60, borderRadius: 30, backgroundColor: '#6366F1', alignItems: 'flex-end', justifyContent: 'flex-start', padding: 6, shadowColor: '#8B5CF6', shadowOffset: { width: 0, height: 0 }, shadowOpacity: 0.9, shadowRadius: 20 },
  moonInner:  { width: 40, height: 40, borderRadius: 20, backgroundColor: '#08080F' },
  orbitDot:   { position: 'absolute', width: 7, height: 7, borderRadius: 4, backgroundColor: '#8B5CF6' },
  appName:    { color: '#F1F5F9', fontSize: 30, fontWeight: '800', letterSpacing: 0.3, marginBottom: 6 },
  tagline:    { color: '#64748B', fontSize: 13, letterSpacing: 0.5 },
  card:       { backgroundColor: '#12121E', borderRadius: 24, padding: 20, borderWidth: 1, borderColor: '#1E1E30' },
  tabRow:     { flexDirection: 'row', backgroundColor: '#08080F', borderRadius: 12, padding: 3, marginBottom: 20 },
  tab:        { flex: 1, paddingVertical: 10, borderRadius: 10, alignItems: 'center' },
  tabOn:      { backgroundColor: '#1E1B4B' },
  tabTxt:     { color: '#4B5563', fontSize: 13, fontWeight: '500' },
  tabTxtOn:   { color: '#818CF8', fontWeight: '700' },
  modeRow:    { flexDirection: 'row', backgroundColor: '#08080F', borderRadius: 10, padding: 3, marginBottom: 16 },
  modeBtn:    { flex: 1, paddingVertical: 9, borderRadius: 8, alignItems: 'center' },
  modeBtnOn:  { backgroundColor: '#1E1B4B' },
  modeTxt:    { color: '#4B5563', fontSize: 13, fontWeight: '500' },
  modeTxtOn:  { color: '#818CF8', fontWeight: '700' },
  oauthBtn:   { backgroundColor: '#1E1E30', borderRadius: 14, paddingVertical: 15, paddingHorizontal: 16, marginBottom: 12, borderWidth: 1, borderColor: '#2E2E45' },
  oauthInner: { flexDirection: 'row', alignItems: 'center', justifyContent: 'center' },
  oauthIconWrap: { width: 28, height: 28, borderRadius: 14, backgroundColor: '#fff', alignItems: 'center', justifyContent: 'center', marginRight: 12 },
  oauthIcon:  { fontWeight: '800', fontSize: 15, color: '#1a1a1a' },
  oauthTxt:   { color: '#F1F5F9', fontSize: 15, fontWeight: '600' },
  fieldWrap:  { marginBottom: 14 },
  label:      { color: '#64748B', fontSize: 11, fontWeight: '600', letterSpacing: 0.5, marginBottom: 7, textTransform: 'uppercase' },
  input:      { backgroundColor: '#0D0D1A', borderWidth: 1.5, borderColor: '#1E1E30', borderRadius: 14, paddingHorizontal: 16, paddingVertical: 13, color: '#F1F5F9', fontSize: 15 },
  inputOn:    { borderColor: '#6366F1' },
  passphraseHint: { color: '#B45309', fontSize: 12, lineHeight: 17, marginBottom: 14, backgroundColor: '#1C1408', borderRadius: 10, padding: 12 },
  btn:        { backgroundColor: '#6366F1', borderRadius: 14, paddingVertical: 16, alignItems: 'center', marginTop: 4 },
  btnTxt:     { color: '#fff', fontSize: 16, fontWeight: '700' },
  hint:       { color: '#374151', fontSize: 12, textAlign: 'center', lineHeight: 18, marginTop: 8 },
})
