/**
 * AMoon Eclipse — Global Secure Request Interceptor
 *
 * Attaches to every outgoing Axios request:
 *   X-App-Sum   — HMAC-SHA256(cert:device, SECRET_SALT) from native C++ module
 *   X-Nonce     — UUID v4 (anti-replay)
 *   X-Timestamp — Unix seconds
 *   X-Signature — HMAC-SHA256(method+path+timestamp+nonce+body, SECRET_SALT)
 *
 * The SECRET_SALT used for X-Signature is the JS-side shared secret
 * (same value as the server's env var HMAC_SIGNING_KEY).
 * It is NOT the same salt embedded in the C++ binary for X-App-Sum.
 */

import axios, { type AxiosInstance, type InternalAxiosRequestConfig } from 'axios'
import { NativeModules, Platform } from 'react-native'
import 'react-native-get-random-values' // polyfill for crypto.getRandomValues
import { v4 as uuidv4 } from 'uuid'
import CryptoJS from 'crypto-js'

const { IntegrityModule } = NativeModules

// ─── JS-side HMAC signing key (for X-Signature) ──────────────────────────────
// Must match server env var HMAC_SIGNING_KEY exactly.
// Obfuscated inline — not a plain string literal.
const _sigKeyParts = ['amoon', 'sig', 'key', 'v1', '2026']
const SIG_KEY = _sigKeyParts.join('-')

// ─── Cached App-Sum (computed once per app session) ──────────────────────────
let _appSumCache: string | null = null
let _appSumFetching: Promise<string> | null = null

async function getAppSum(): Promise<string> {
  if (_appSumCache) return _appSumCache

  if (_appSumFetching) return _appSumFetching

  _appSumFetching = (async () => {
    try {
      if (!IntegrityModule?.getAppSum) {
        // Dev mode / Expo Go — no native module available
        return 'dev-mode-no-native'
      }
      const sum: string = await IntegrityModule.getAppSum()
      _appSumCache = sum || 'integrity-failed'
      return _appSumCache
    } catch {
      _appSumCache = 'integrity-error'
      return _appSumCache
    } finally {
      _appSumFetching = null
    }
  })()

  return _appSumFetching
}

// ─── Body serialization ───────────────────────────────────────────────────────

function serializeBody(data: unknown): string {
  if (data == null) return ''
  if (typeof data === 'string') return data
  // FormData (multipart) — sign as empty string, server treats body as opaque
  if (typeof FormData !== 'undefined' && data instanceof FormData) return ''
  try {
    return JSON.stringify(data)
  } catch {
    return ''
  }
}

// ─── Path extraction ──────────────────────────────────────────────────────────

function extractPath(config: InternalAxiosRequestConfig): string {
  try {
    const base = config.baseURL ?? ''
    const url  = config.url  ?? ''
    // If url is absolute, extract just the path+query
    const full = url.startsWith('http') ? url : base + url
    const u = new URL(full)
    return u.pathname + (u.search || '')
  } catch {
    return config.url ?? '/'
  }
}

// ─── HMAC-SHA256 (JS — CryptoJS) ─────────────────────────────────────────────

function signRequest(
  method: string,
  path: string,
  timestamp: string,
  nonce: string,
  body: string,
  key: string
): string {
  const message = [method.toUpperCase(), path, timestamp, nonce, body].join('\n')
  return CryptoJS.HmacSHA256(message, key).toString(CryptoJS.enc.Hex)
}

// ─── Interceptor setup ────────────────────────────────────────────────────────

export function setupSecureInterceptor(instance: AxiosInstance): void {
  instance.interceptors.request.use(async (config) => {
    const method    = (config.method ?? 'get').toUpperCase()
    const path      = extractPath(config)
    const timestamp = String(Math.floor(Date.now() / 1000))
    const nonce     = uuidv4()
    const body      = serializeBody(config.data)

    const [appSum, signature] = await Promise.all([
      getAppSum(),
      Promise.resolve(signRequest(method, path, timestamp, nonce, body, SIG_KEY)),
    ])

    config.headers = config.headers ?? {}
    config.headers['X-App-Sum']   = appSum
    config.headers['X-Nonce']     = nonce
    config.headers['X-Timestamp'] = timestamp
    config.headers['X-Signature'] = signature
    config.headers['X-Platform']  = Platform.OS

    return config
  })
}

// ─── Pre-configured instance ──────────────────────────────────────────────────

const API_URL = process.env.EXPO_PUBLIC_API_URL ?? 'http://localhost:8080'

export const secureApi = axios.create({
  baseURL: API_URL,
  timeout: 30_000,
  headers: { 'Content-Type': 'application/json' },
})

setupSecureInterceptor(secureApi)

export default secureApi
