import { useEffect, useRef, useState, useCallback } from 'react'
import {
  RTCPeerConnection, RTCIceCandidate, RTCSessionDescription,
  mediaDevices,
} from 'react-native-webrtc'
import * as SecureStore from 'expo-secure-store'

const API = process.env.EXPO_PUBLIC_API_URL ?? 'http://localhost:8080'
const WS_URL = ((process.env.EXPO_PUBLIC_API_URL ?? 'http://localhost:8080').replace(/^http/, 'ws') + '/ws')

export type CallState = 'idle' | 'calling' | 'ringing' | 'active' | 'ended'

export type IncomingCall = {
  fromUserId: string
  fromUsername: string
  roomId: string
  offer: RTCSessionDescriptionInit
}

interface UseVoiceCallReturn {
  callState: CallState
  incomingCall: IncomingCall | null
  startCall: (toUserId: string, toUsername: string, roomId: string) => Promise<void>
  acceptCall: () => Promise<void>
  rejectCall: () => void
  endCall: () => void
  isMuted: boolean
  toggleMute: () => void
  isSpeaker: boolean
  toggleSpeaker: () => void
}

export function useVoiceCall(
  wsRef: React.MutableRefObject<WebSocket | null>
): UseVoiceCallReturn {
  const pcRef = useRef<RTCPeerConnection | null>(null)
  const [callState, setCallState] = useState<CallState>('idle')
  const [incomingCall, setIncomingCall] = useState<IncomingCall | null>(null)
  const [isMuted, setIsMuted] = useState(false)
  const [isSpeaker, setIsSpeaker] = useState(true)
  const callMetaRef = useRef<{ toUserId: string; roomId: string } | null>(null)
  const localStreamRef = useRef<any>(null)

  const getIceServers = useCallback(async () => {
    try {
      const token = await SecureStore.getItemAsync('amoon_token')
      const res = await fetch(`${API}/api/calls/turn-credentials`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      const data = await res.json()
      return data.iceServers ?? [{ urls: 'stun:stun.l.google.com:19302' }]
    } catch {
      return [{ urls: 'stun:stun.l.google.com:19302' }]
    }
  }, [])

  const cleanup = useCallback(() => {
    localStreamRef.current?.getTracks().forEach((t: any) => t.stop())
    localStreamRef.current = null
    pcRef.current?.close()
    pcRef.current = null
    setCallState('idle')
    setIncomingCall(null)
    callMetaRef.current = null
  }, [])

  const sendSignal = useCallback((type: string, toUserId: string, roomId: string, data: any) => {
    wsRef.current?.send(JSON.stringify({ type, toUserId, roomId, data }))
  }, [wsRef])

  const createPC = useCallback(async () => {
    const iceServers = await getIceServers()
    const pc = new RTCPeerConnection({ iceServers })

    // Get local audio stream
    const stream = await mediaDevices.getUserMedia({ audio: true, video: false })
    localStreamRef.current = stream
    stream.getTracks().forEach((track: any) => pc.addTrack(track, stream))

    ;(pc as any).addEventListener('icecandidate', (e: any) => {
      if (e.candidate && callMetaRef.current) {
        sendSignal('call-ice', callMetaRef.current.toUserId, callMetaRef.current.roomId, e.candidate)
      }
    })

    ;(pc as any).addEventListener('connectionstatechange', () => {
      if ((pc as any).connectionState === 'connected') setCallState('active')
      if ((pc as any).connectionState === 'disconnected' || (pc as any).connectionState === 'failed') cleanup()
    })

    return pc
  }, [getIceServers, sendSignal, cleanup])

  // Handle incoming WebRTC signals from WebSocket
  const handleSignal = useCallback(async (msg: any) => {
    if (msg.type === 'call-ring') {
      setIncomingCall({
        fromUserId: msg.fromUserId,
        fromUsername: msg.data?.fromUsername ?? msg.fromUserId,
        roomId: msg.roomId,
        offer: msg.data?.offer,
      })
      setCallState('ringing')
      callMetaRef.current = { toUserId: msg.fromUserId, roomId: msg.roomId }
    }

    if (msg.type === 'call-answer' && pcRef.current) {
      await pcRef.current.setRemoteDescription(new RTCSessionDescription(msg.data))
      setCallState('active')
    }

    if (msg.type === 'call-ice' && pcRef.current) {
      try { await pcRef.current.addIceCandidate(new RTCIceCandidate(msg.data)) } catch {}
    }

    if (msg.type === 'call-end') {
      cleanup()
    }
  }, [cleanup])

  // Expose handler to be called from WebSocket message handler
  useEffect(() => {
    ;(globalThis as any).__voiceCallHandler = handleSignal
    return () => { delete (globalThis as any).__voiceCallHandler }
  }, [handleSignal])

  const startCall = useCallback(async (toUserId: string, toUsername: string, roomId: string) => {
    callMetaRef.current = { toUserId, roomId }
    setCallState('calling')
    try {
      const pc = await createPC()
      pcRef.current = pc
      const offer = await pc.createOffer({})
      await pc.setLocalDescription(offer)
      const myUsername = await SecureStore.getItemAsync('amoon_username')
      sendSignal('call-ring', toUserId, roomId, { offer, fromUsername: myUsername })
    } catch {
      cleanup()
    }
  }, [createPC, sendSignal, cleanup])

  const acceptCall = useCallback(async () => {
    if (!incomingCall) return
    callMetaRef.current = { toUserId: incomingCall.fromUserId, roomId: incomingCall.roomId }
    try {
      const pc = await createPC()
      pcRef.current = pc
      await pc.setRemoteDescription(new RTCSessionDescription(incomingCall.offer as any))
      const answer = await pc.createAnswer()
      await pc.setLocalDescription(answer)
      sendSignal('call-answer', incomingCall.fromUserId, incomingCall.roomId, answer)
      setCallState('active')
      setIncomingCall(null)
    } catch {
      cleanup()
    }
  }, [incomingCall, createPC, sendSignal, cleanup])

  const rejectCall = useCallback(() => {
    if (incomingCall) {
      sendSignal('call-end', incomingCall.fromUserId, incomingCall.roomId, {})
    }
    cleanup()
  }, [incomingCall, sendSignal, cleanup])

  const endCall = useCallback(() => {
    if (callMetaRef.current) {
      sendSignal('call-end', callMetaRef.current.toUserId, callMetaRef.current.roomId, {})
    }
    cleanup()
  }, [sendSignal, cleanup])

  const toggleMute = useCallback(() => {
    localStreamRef.current?.getAudioTracks().forEach((t: any) => { t.enabled = !t.enabled })
    setIsMuted(m => !m)
  }, [])

  const toggleSpeaker = useCallback(() => {
    setIsSpeaker(s => !s)
  }, [])

  return { callState, incomingCall, startCall, acceptCall, rejectCall, endCall, isMuted, toggleMute, isSpeaker, toggleSpeaker }
}
