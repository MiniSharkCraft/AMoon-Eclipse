import 'expo-standard-web-crypto'
import { useState } from 'react'
import {
  View, Text, TextInput, TouchableOpacity, Alert,
  StyleSheet, SafeAreaView, KeyboardAvoidingView, Platform,
  ActivityIndicator, StatusBar,
} from 'react-native'
import { router } from 'expo-router'
import * as SecureStore from 'expo-secure-store'
import {
  decryptPrivateKeyWithPassphrase,
  generateRsaKeyPair, exportRsaKeyPair, publicKeyFingerprint,
} from '../../src/lib/crypto'

const API = process.env.EXPO_PUBLIC_API_URL ?? process.env.EXPO_PUBLIC_API_URL ?? 'http://localhost:8080'

export default function RecoverKeyScreen() {
  const [passphrase, setPassphrase] = useState('')
  const [loading, setLoading] = useState(false)

  const handleRecover = async () => {
    if (!passphrase.trim()) { Alert.alert('Nhập passphrase'); return }
    setLoading(true)
    try {
      const token  = await SecureStore.getItemAsync('amoon_token')
      const userId = await SecureStore.getItemAsync('amoon_userId')
      if (!token || !userId) throw new Error('Phiên đăng nhập hết hạn')

      const res = await fetch(`${API}/api/auth/encrypted-key`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!res.ok) throw new Error('Không lấy được key từ server')
      const { encryptedKey } = await res.json() as { encryptedKey: string }

      if (!encryptedKey) {
        Alert.alert('Không có backup', 'Tài khoản chưa có backup passphrase.',
          [{ text: 'Tạo key mới', onPress: createNewKey }])
        return
      }

      const privateKey = await decryptPrivateKeyWithPassphrase(encryptedKey, passphrase)
      await SecureStore.setItemAsync(`privateKey_${userId}`, privateKey)
      Alert.alert('Thành công', 'Đã khôi phục khóa E2EE!')
      router.replace('/(app)/(tabs)')
    } catch {
      Alert.alert('Sai passphrase', 'Passphrase không đúng hoặc key đã bị thay đổi.')
    } finally { setLoading(false) }
  }

  const createNewKey = async () => {
    try {
      const userId = await SecureStore.getItemAsync('amoon_userId')
      const token  = await SecureStore.getItemAsync('amoon_token')
      if (!userId || !token) return
      const kp = await generateRsaKeyPair()
      const { publicKey, privateKey } = await exportRsaKeyPair(kp)
      const fingerprint = await publicKeyFingerprint(publicKey)
      await SecureStore.setItemAsync(`privateKey_${userId}`, privateKey)
      await fetch(`${API}/api/auth/register-key`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ publicKey, fingerprint }),
      })
      router.replace('/(app)/(tabs)')
    } catch (e) {
      Alert.alert('Lỗi', 'Không thể tạo key mới: ' + (e instanceof Error ? e.message : String(e)))
    }
  }

  const handleLogout = async () => {
    await Promise.all([
      SecureStore.deleteItemAsync('amoon_token'),
      SecureStore.deleteItemAsync('amoon_userId'),
      SecureStore.deleteItemAsync('amoon_username'),
    ])
    router.replace('/(auth)/login')
  }

  return (
    <SafeAreaView style={s.root}>
      <StatusBar barStyle="light-content" backgroundColor="#08080F" />
      <KeyboardAvoidingView style={{ flex: 1, justifyContent: 'center', padding: 24 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
        <View style={s.moonRow}>
          <View style={s.moonOuter}><View style={s.moonInner} /></View>
        </View>
        <Text style={s.title}>Thiết bị mới</Text>
        <Text style={s.sub}>Nhập PIN 6 số để khôi phục khóa E2EE và đọc lại tin nhắn cũ.</Text>

        <View style={s.box}>
          <Text style={s.label}>PIN BẢO VỆ E2EE</Text>
          <TextInput
            style={s.input}
            placeholder="6 chữ số..."
            placeholderTextColor="#2E2E45"
            value={passphrase}
            onChangeText={t => setPassphrase(t.replace(/\D/g,'').slice(0,6))}
            secureTextEntry
            keyboardType="numeric"
            maxLength={6}
          />
          <TouchableOpacity style={[s.btn, loading && { opacity: 0.6 }]} onPress={handleRecover} disabled={loading}>
            {loading ? <ActivityIndicator color="#fff" /> : <Text style={s.btnTxt}>Khôi phục →</Text>}
          </TouchableOpacity>
          <TouchableOpacity onPress={createNewKey} style={{ marginTop: 16, alignItems: 'center' }}>
            <Text style={{ color: '#EF4444', fontSize: 13 }}>Quên passphrase (mất tin nhắn cũ)</Text>
          </TouchableOpacity>
        </View>

        <Text style={s.warn}>⚠️ Nếu quên passphrase, tin nhắn cũ sẽ không thể đọc lại.</Text>
        <TouchableOpacity onPress={handleLogout} style={{ marginTop: 20, alignItems: 'center' }}>
          <Text style={{ color: '#374151', fontSize: 13 }}>← Đăng xuất</Text>
        </TouchableOpacity>
      </KeyboardAvoidingView>
    </SafeAreaView>
  )
}

const s = StyleSheet.create({
  root:      { flex: 1, backgroundColor: '#08080F' },
  moonRow:   { alignItems: 'center', marginBottom: 28 },
  moonOuter: { width: 56, height: 56, borderRadius: 28, backgroundColor: '#6366F1', alignItems: 'flex-end', justifyContent: 'flex-start', padding: 6 },
  moonInner: { width: 36, height: 36, borderRadius: 18, backgroundColor: '#08080F' },
  title:     { color: '#F1F5F9', fontSize: 26, fontWeight: '800', textAlign: 'center', marginBottom: 10 },
  sub:       { color: '#64748B', fontSize: 13, textAlign: 'center', lineHeight: 20, marginBottom: 28 },
  box:       { backgroundColor: '#12121E', borderRadius: 20, padding: 20, borderWidth: 1, borderColor: '#1E1E30' },
  label:     { color: '#64748B', fontSize: 11, fontWeight: '600', letterSpacing: 0.5, marginBottom: 8 },
  input:     { backgroundColor: '#0D0D1A', borderWidth: 1.5, borderColor: '#1E1E30', borderRadius: 14, paddingHorizontal: 16, paddingVertical: 13, color: '#F1F5F9', fontSize: 15, marginBottom: 16 },
  btn:       { backgroundColor: '#6366F1', borderRadius: 14, paddingVertical: 15, alignItems: 'center' },
  btnTxt:    { color: '#fff', fontSize: 15, fontWeight: '700' },
  warn:      { color: '#78350F', fontSize: 12, textAlign: 'center', lineHeight: 18, marginTop: 20, paddingHorizontal: 10 },
})
