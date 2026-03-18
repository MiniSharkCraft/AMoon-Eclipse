import { useEffect, useRef, useState, useCallback } from 'react'

const API = process.env.EXPO_PUBLIC_API_URL ?? 'http://localhost:8080'

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
}

export function useVoiceCall(
  wsRef: React.MutableRefObject<WebSocket | null>
): UseVoiceCallReturn {
  const pcRef = useRef<RTCPeerConnection | null>(null)
  const [callState, setCallState] = useState<CallState>('idle')
  const [incomingCall, setIncomingCall] = useState<IncomingCall | null>(null)
  const [isMuted, setIsMuted] = useState(false)
  const callMetaRef = useRef<{ toUserId: string; roomId: string } | null>(null)
  const localStreamRef = useRef<MediaStream | null>(null)
  const remoteAudioRef = useRef<HTMLAudioElement | null>(null)

  const getIceServers = useCallback(async (): Promise<RTCIceServer[]> => {
    try {
      const token = localStorage.getItem('amoon_token')
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
    localStreamRef.current?.getTracks().forEach(t => t.stop())
    localStreamRef.current = null
    pcRef.current?.close()
    pcRef.current = null
    if (remoteAudioRef.current) {
      remoteAudioRef.current.srcObject = null
    }
    setCallState('idle')
    setIncomingCall(null)
    callMetaRef.current = null
  }, [])

  const sendSignal = useCallback((type: string, toUserId: string, roomId: string, data: unknown) => {
    wsRef.current?.send(JSON.stringify({ type, toUserId, roomId, data }))
  }, [wsRef])

  const createPC = useCallback(async (): Promise<RTCPeerConnection> => {
    const iceServers = await getIceServers()
    const pc = new RTCPeerConnection({ iceServers })

    const stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false })
    localStreamRef.current = stream
    stream.getTracks().forEach(track => pc.addTrack(track, stream))

    pc.onicecandidate = (e) => {
      if (e.candidate && callMetaRef.current) {
        sendSignal('call-ice', callMetaRef.current.toUserId, callMetaRef.current.roomId, e.candidate)
      }
    }

    pc.onconnectionstatechange = () => {
      if (pc.connectionState === 'connected') setCallState('active')
      if (pc.connectionState === 'disconnected' || pc.connectionState === 'failed') cleanup()
    }

    pc.ontrack = (e) => {
      if (!remoteAudioRef.current) {
        remoteAudioRef.current = new Audio()
        remoteAudioRef.current.autoplay = true
      }
      remoteAudioRef.current.srcObject = e.streams[0]
    }

    return pc
  }, [getIceServers, sendSignal, cleanup])

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

  useEffect(() => {
    ;(globalThis as any).__voiceCallHandler = handleSignal
    return () => { delete (globalThis as any).__voiceCallHandler }
  }, [handleSignal])

  const startCall = useCallback(async (toUserId: string, toUsername: string, roomId: string) => {
    void toUsername
    callMetaRef.current = { toUserId, roomId }
    setCallState('calling')
    try {
      const pc = await createPC()
      pcRef.current = pc
      const offer = await pc.createOffer()
      await pc.setLocalDescription(offer)
      const myUsername = localStorage.getItem('amoon_username')
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
      await pc.setRemoteDescription(new RTCSessionDescription(incomingCall.offer))
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
    localStreamRef.current?.getAudioTracks().forEach(t => { t.enabled = !t.enabled })
    setIsMuted(m => !m)
  }, [])

  return { callState, incomingCall, startCall, acceptCall, rejectCall, endCall, isMuted, toggleMute }
}
