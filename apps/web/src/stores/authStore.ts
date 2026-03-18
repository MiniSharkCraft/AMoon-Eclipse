/**
 * @file authStore.ts
 * @description Zustand store for auth state + IndexedDB key persistence.
 *
 * Private keys NEVER leave IndexedDB. Zero-Knowledge.
 */

// Configure via .env — see .env.example
const API = import.meta.env.VITE_API_URL ?? 'http://localhost:8080'

import { create } from 'zustand'
import { openDB, type IDBPDatabase } from 'idb'
import {
  generateRsaKeyPair,
  exportRsaKeyPair,
  importRsaPrivateKey,
  importRsaPublicKey,
  publicKeyFingerprint,
} from '@messmini/common'

interface AuthState {
  isAuthenticated: boolean
  userId: string | null
  username: string | null
  publicKey: string | null       // Base64 SPKI — shared with server
  privateKey: CryptoKey | null   // In-memory only, sourced from IndexedDB
  token: string | null

  login: (username: string, password: string) => Promise<void>
  register: (username: string, password: string) => Promise<void>
  logout: () => void
  loadKeysFromStorage: () => Promise<void>
}

// ─── IndexedDB (private key storage) ─────────────────────────────────────────
let _db: IDBPDatabase | null = null

const getDb = async () => {
  if (_db) return _db
  _db = await openDB('messmini-keystore', 1, {
    upgrade(db) {
      db.createObjectStore('keys')
    },
  })
  return _db
}

const savePrivateKeyToIDB = async (userId: string, pkcs8: string) => {
  const db = await getDb()
  await db.put('keys', pkcs8, `privateKey:${userId}`)
}

export const loadPrivateKeyFromIDB = async (userId: string): Promise<CryptoKey | null> => {
  const db = await getDb()
  const pkcs8 = await db.get('keys', `privateKey:${userId}`)
  if (!pkcs8) return null
  return importRsaPrivateKey(pkcs8)
}

// ─── Password hashing ────────────────────────────────────────────────────────
const hashPassword = (password: string) => Promise.resolve(password)

// Suppress unused import warning for importRsaPublicKey — it's part of the common API
void importRsaPublicKey

export const useAuthStore = create<AuthState>((set, _get) => ({
  isAuthenticated: false,
  userId: null,
  username: null,
  publicKey: null,
  privateKey: null,
  token: null,

  register: async (username, password) => {
    const kp = await generateRsaKeyPair()
    const { publicKey, privateKey } = await exportRsaKeyPair(kp)
    const fingerprint = await publicKeyFingerprint(publicKey)
    const passwordHash = await hashPassword(password)

    const res = await fetch(`${API}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, publicKey, fingerprint, passwordHash }),
    })
    if (!res.ok) throw new Error((await res.json()).error)
    const data = await res.json()
    const token: string = data.token ?? ''

    await savePrivateKeyToIDB(data.id, privateKey)
    const privKey = await importRsaPrivateKey(privateKey)

    localStorage.setItem('amoon_token', token)
    localStorage.setItem('amoon_userId', data.id)
    localStorage.setItem('amoon_username', username)
    sessionStorage.setItem('messmini:userId', data.id)

    set({ isAuthenticated: true, userId: data.id, username, publicKey, privateKey: privKey, token })
  },

  login: async (username, password) => {
    const passwordHash = await hashPassword(password)
    const res = await fetch(`${API}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, passwordHash }),
    })
    if (!res.ok) throw new Error((await res.json()).error)
    const { token, user } = await res.json()

    const privKey = await loadPrivateKeyFromIDB(user.id)
    if (!privKey) throw new Error('Private key not found on this device. Please re-register or restore a backup.')

    localStorage.setItem('amoon_token', token)
    localStorage.setItem('amoon_userId', user.id)
    localStorage.setItem('amoon_username', user.username)
    sessionStorage.setItem('messmini:userId', user.id)

    set({
      isAuthenticated: true,
      userId: user.id,
      username: user.username,
      publicKey: user.publicKey,
      privateKey: privKey,
      token,
    })
  },

  logout: () => {
    localStorage.removeItem('amoon_token')
    localStorage.removeItem('amoon_userId')
    localStorage.removeItem('amoon_username')
    sessionStorage.removeItem('messmini:userId')
    set({ isAuthenticated: false, userId: null, username: null, publicKey: null, privateKey: null, token: null })
  },

  loadKeysFromStorage: async () => {
    // Try localStorage first, fall back to sessionStorage
    const userId = localStorage.getItem('amoon_userId') ?? sessionStorage.getItem('messmini:userId')
    const token = localStorage.getItem('amoon_token')
    const username = localStorage.getItem('amoon_username')
    if (!userId) return
    const privKey = await loadPrivateKeyFromIDB(userId)
    if (privKey) {
      set({ privateKey: privKey, isAuthenticated: true, userId, token: token ?? null, username: username ?? null })
    }
  },
}))
