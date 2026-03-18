import 'expo-standard-web-crypto'
import { useEffect, useState } from 'react'
import {
  View, Text, TextInput, TouchableOpacity,
  ActivityIndicator, StyleSheet, Alert,
} from 'react-native'
import { useLocalSearchParams, router } from 'expo-router'
import * as SecureStore from 'expo-secure-store'
import {
  generateRsaKeyPair, exportRsaKeyPair, publicKeyFingerprint,
  encryptPrivateKeyWithPassphrase,
} from '../src/lib/crypto'

const API = process.env.EXPO_PUBLIC_API_URL ?? process.env.EXPO_PUBLIC_API_URL ?? 'http://localhost:8080'

export default function GoogleCallbackScreen() {
  const params = useLocalSearchParams<{ token?: string; userId?: string; username?: string; error?: string }>()

  // 'loading' | 'set-pin' | 'done'
  const [step, setStep]         = useState<'loading' | 'set-pin'>('loading')
  const [pin, setPin]           = useState('')
  const [confirmPin, setConfirm] = useState('')
  const [saving, setSaving]     = useState(false)

  // Stored for the set-pin step
  const [pendingKey, setPendingKey] = useState<{ token: string; userId: string; privateKey: string } | null>(null)

  useEffect(() => {
    const handle = async () => {
      const { token, userId, username, error } = params
      if (error || !token || !userId) {
        router.replace('/(auth)/login')
        return
      }
      try {
        await Promise.all([
          SecureStore.setItemAsync('amoon_userId', userId),
          SecureStore.setItemAsync('amoon_username', username ?? ''),
          SecureStore.setItemAsync('amoon_token', token),
        ])

        const existing = await SecureStore.getItemAsync(`privateKey_${userId}`)
        if (!existing) {
          // New account — create key then ask for PIN
          const kp = await generateRsaKeyPair()
          const { publicKey, privateKey } = await exportRsaKeyPair(kp)
          const fingerprint = await publicKeyFingerprint(publicKey)
          await SecureStore.setItemAsync(`privateKey_${userId}`, privateKey)
          await fetch(`${API}/api/auth/register-key`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
            body: JSON.stringify({ publicKey, fingerprint }),
          })
          setPendingKey({ token, userId, privateKey })
          setStep('set-pin')
        } else {
          router.replace('/(app)/(tabs)')
        }
      } catch {
        router.replace('/(auth)/login')
      }
    }
    handle()
  }, [])

  const handleSetPin = async () => {
    if (!/^\d{6}$/.test(pin)) {
      Alert.alert('PIN không hợp lệ', 'Nhập đúng 6 chữ số'); return
    }
    if (pin !== confirmPin) {
      Alert.alert('PIN không khớp', 'Nhập lại cho đúng'); return
    }
    if (!pendingKey) return
    setSaving(true)
    try {
      const { encryptedKey, keySalt } = await encryptPrivateKeyWithPassphrase(pendingKey.privateKey, pin)
      await fetch(`${API}/api/auth/store-encrypted-key`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${pendingKey.token}` },
        body: JSON.stringify({ encryptedKey, keySalt }),
      })
      router.replace('/(app)/(tabs)')
    } catch {
      Alert.alert('Lỗi', 'Không lưu được PIN, thử lại sau')
    } finally { setSaving(false) }
  }

  if (step === 'loading') {
    return (
      <View style={s.center}>
        <ActivityIndicator color="#6366F1" size="large" />
      </View>
    )
  }

  return (
    <View style={s.root}>
      <View style={s.moonRow}>
        <View style={s.moonOuter}><View style={s.moonInner} /></View>
      </View>
      <Text style={s.title}>Đặt PIN bảo vệ E2EE</Text>
      <Text style={s.sub}>PIN 6 số dùng để khôi phục tin nhắn khi đổi thiết bị. Ghi nhớ kỹ — quên sẽ mất tin nhắn cũ.</Text>

      <View style={s.box}>
        <Text style={s.label}>PIN (6 SỐ)</Text>
        <TextInput
          style={s.input}
          placeholder="6 chữ số..."
          placeholderTextColor="#2E2E45"
          value={pin}
          onChangeText={t => setPin(t.replace(/\D/g, '').slice(0, 6))}
          secureTextEntry keyboardType="numeric" maxLength={6}
        />
        <Text style={s.label}>XÁC NHẬN PIN</Text>
        <TextInput
          style={s.input}
          placeholder="nhập lại..."
          placeholderTextColor="#2E2E45"
          value={confirmPin}
          onChangeText={t => setConfirm(t.replace(/\D/g, '').slice(0, 6))}
          secureTextEntry keyboardType="numeric" maxLength={6}
        />
        <TouchableOpacity style={[s.btn, saving && { opacity: 0.6 }]} onPress={handleSetPin} disabled={saving}>
          {saving ? <ActivityIndicator color="#fff" /> : <Text style={s.btnTxt}>Xác nhận →</Text>}
        </TouchableOpacity>
        <TouchableOpacity style={{ marginTop: 14, alignItems: 'center' }} onPress={() => router.replace('/(app)/(tabs)')}>
          <Text style={{ color: '#374151', fontSize: 13 }}>Bỏ qua (không backup được key)</Text>
        </TouchableOpacity>
      </View>
    </View>
  )
}

const s = StyleSheet.create({
  center:    { flex: 1, backgroundColor: '#08080F', alignItems: 'center', justifyContent: 'center' },
  root:      { flex: 1, backgroundColor: '#08080F', justifyContent: 'center', padding: 24 },
  moonRow:   { alignItems: 'center', marginBottom: 28 },
  moonOuter: { width: 56, height: 56, borderRadius: 28, backgroundColor: '#6366F1', alignItems: 'flex-end', justifyContent: 'flex-start', padding: 6 },
  moonInner: { width: 36, height: 36, borderRadius: 18, backgroundColor: '#08080F' },
  title:     { color: '#F1F5F9', fontSize: 24, fontWeight: '800', textAlign: 'center', marginBottom: 10 },
  sub:       { color: '#64748B', fontSize: 13, textAlign: 'center', lineHeight: 20, marginBottom: 28 },
  box:       { backgroundColor: '#12121E', borderRadius: 20, padding: 20, borderWidth: 1, borderColor: '#1E1E30' },
  label:     { color: '#64748B', fontSize: 11, fontWeight: '600', letterSpacing: 0.5, marginBottom: 8 },
  input:     { backgroundColor: '#0D0D1A', borderWidth: 1.5, borderColor: '#1E1E30', borderRadius: 14, paddingHorizontal: 16, paddingVertical: 13, color: '#F1F5F9', fontSize: 15, marginBottom: 16 },
  btn:       { backgroundColor: '#6366F1', borderRadius: 14, paddingVertical: 15, alignItems: 'center', marginTop: 4 },
  btnTxt:    { color: '#fff', fontSize: 15, fontWeight: '700' },
})
