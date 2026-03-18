import { useEffect, useRef, useState, useCallback } from 'react'
import {
  RTCPeerConnection, RTCIceCandidate, RTCSessionDescription,
  mediaDevices,
} from 'react-native-webrtc'
import * as SecureStore from 'expo-secure-store'

const API = process.env.EXPO_PUBLIC_API_URL ?? 'http://localhost:8080'

export type GroupCallState = 'idle' | 'inviting' | 'ringing' | 'active'

export interface GroupPeer {
  userId: string
  username: string
}

interface UseGroupCallReturn {
  groupCallState: GroupCallState
  peers: GroupPeer[]
  incomingGroupCall: { fromUserId: string; fromUsername: string; roomId: string } | null
  startGroupCall: (roomId: string, myUsername: string) => void
  joinGroupCall: (myUsername: string) => Promise<void>
  rejectGroupCall: () => void
  leaveGroupCall: () => void
  isGroupMuted: boolean
  toggleGroupMute: () => void
}

// PeerConnection registry
const peerMap = new Map<string, RTCPeerConnection>()

export function useGroupCall(
  wsRef: React.MutableRefObject<WebSocket | null>
): UseGroupCallReturn {
  const [groupCallState, setGroupCallState] = useState<GroupCallState>('idle')
  const [peers, setPeers] = useState<GroupPeer[]>([])
  const [incomingGroupCall, setIncomingGroupCall] = useState<{ fromUserId: string; fromUsername: string; roomId: string } | null>(null)
  const [isGroupMuted, setIsGroupMuted] = useState(false)
  const localStreamRef = useRef<any>(null)
  const roomIdRef = useRef<string | null>(null)

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

  const getLocalStream = useCallback(async () => {
    if (!localStreamRef.current) {
      localStreamRef.current = await mediaDevices.getUserMedia({ audio: true, video: false })
    }
    return localStreamRef.current
  }, [])

  const sendSignal = useCallback((type: string, toUserId: string, data: any) => {
    wsRef.current?.send(JSON.stringify({ type, toUserId, data }))
  }, [wsRef])

  const sendRoomSignal = useCallback((type: string, data: any) => {
    wsRef.current?.send(JSON.stringify({ type, data }))
  }, [wsRef])

  const createPCForPeer = useCallback(async (peerId: string, peerUsername: string) => {
    const iceServers = await getIceServers()
    const pc = new RTCPeerConnection({ iceServers })
    peerMap.set(peerId, pc)

    const stream = await getLocalStream()
    stream.getTracks().forEach((t: any) => pc.addTrack(t, stream))

    ;(pc as any).addEventListener('icecandidate', (e: any) => {
      if (e.candidate) {
        sendSignal('group-call-ice', peerId, e.candidate)
      }
    })

    ;(pc as any).addEventListener('connectionstatechange', () => {
      const state = (pc as any).connectionState
      if (state === 'connected') {
        setGroupCallState('active')
        setPeers(prev => prev.some(p => p.userId === peerId) ? prev : [...prev, { userId: peerId, username: peerUsername }])
      }
      if (state === 'disconnected' || state === 'failed') {
        removePeer(peerId)
      }
    })

    return pc
  }, [getIceServers, getLocalStream, sendSignal])

  const removePeer = useCallback((peerId: string) => {
    const pc = peerMap.get(peerId)
    if (pc) {
      pc.close()
      peerMap.delete(peerId)
    }
    setPeers(prev => {
      const next = prev.filter(p => p.userId !== peerId)
      if (next.length === 0) {
        setGroupCallState('idle')
      }
      return next
    })
  }, [])

  const cleanupAll = useCallback(() => {
    peerMap.forEach(pc => pc.close())
    peerMap.clear()
    localStreamRef.current?.getTracks().forEach((t: any) => t.stop())
    localStreamRef.current = null
    setPeers([])
    setGroupCallState('idle')
    setIncomingGroupCall(null)
    roomIdRef.current = null
  }, [])

  // Handle incoming group call signals
  const handleGroupSignal = useCallback(async (msg: any) => {
    if (msg.type === 'group-call-invite') {
      if (groupCallState !== 'idle') return // already in a call
      setIncomingGroupCall({
        fromUserId: msg.fromUserId,
        fromUsername: msg.data?.fromUsername ?? msg.fromUserId,
        roomId: msg.roomId ?? roomIdRef.current ?? '',
      })
      setGroupCallState('ringing')
    }

    if (msg.type === 'group-call-join') {
      // Someone joined → we need to create an offer to them
      if (groupCallState === 'active' || groupCallState === 'inviting') {
        const peerUserId = msg.fromUserId
        const peerUsername = msg.data?.username ?? peerUserId
        const pc = await createPCForPeer(peerUserId, peerUsername)
        const offer = await pc.createOffer({})
        await pc.setLocalDescription(offer)
        sendSignal('group-call-offer', peerUserId, { offer, username: msg.data?.myUsername })
      }
    }

    if (msg.type === 'group-call-offer') {
      const peerId = msg.fromUserId
      const peerUsername = msg.data?.username ?? peerId
      let pc = peerMap.get(peerId)
      if (!pc) {
        pc = await createPCForPeer(peerId, peerUsername)
      }
      await pc.setRemoteDescription(new RTCSessionDescription(msg.data.offer as any))
      const answer = await pc.createAnswer()
      await pc.setLocalDescription(answer)
      sendSignal('group-call-answer', peerId, { answer })
    }

    if (msg.type === 'group-call-answer') {
      const pc = peerMap.get(msg.fromUserId)
      if (pc) {
        await pc.setRemoteDescription(new RTCSessionDescription(msg.data.answer as any))
      }
    }

    if (msg.type === 'group-call-ice') {
      const pc = peerMap.get(msg.fromUserId)
      if (pc) {
        try { await pc.addIceCandidate(new RTCIceCandidate(msg.data)) } catch {}
      }
    }

    if (msg.type === 'group-call-end') {
      removePeer(msg.fromUserId)
    }
  }, [groupCallState, createPCForPeer, sendSignal, removePeer])

  useEffect(() => {
    ;(globalThis as any).__groupCallHandler = handleGroupSignal
    return () => { delete (globalThis as any).__groupCallHandler }
  }, [handleGroupSignal])

  const startGroupCall = useCallback((roomId: string, myUsername: string) => {
    roomIdRef.current = roomId
    setGroupCallState('inviting')
    sendRoomSignal('group-call-invite', { fromUsername: myUsername })
  }, [sendRoomSignal])

  const joinGroupCall = useCallback(async (myUsername: string) => {
    setGroupCallState('active')
    setIncomingGroupCall(null)
    // Let existing participants know we joined (they'll send us offers)
    sendRoomSignal('group-call-join', { username: myUsername, myUsername })
  }, [sendRoomSignal])

  const rejectGroupCall = useCallback(() => {
    setIncomingGroupCall(null)
    setGroupCallState('idle')
  }, [])

  const leaveGroupCall = useCallback(() => {
    // Notify all connected peers we're leaving
    peerMap.forEach((_, peerId) => {
      sendSignal('group-call-end', peerId, {})
    })
    cleanupAll()
  }, [sendSignal, cleanupAll])

  const toggleGroupMute = useCallback(() => {
    localStreamRef.current?.getAudioTracks().forEach((t: any) => { t.enabled = !t.enabled })
    setIsGroupMuted(m => !m)
  }, [])

  return {
    groupCallState,
    peers,
    incomingGroupCall,
    startGroupCall,
    joinGroupCall,
    rejectGroupCall,
    leaveGroupCall,
    isGroupMuted,
    toggleGroupMute,
  }
}
