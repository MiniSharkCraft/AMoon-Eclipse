// Configure via .env — see .env.example
const BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:8080'
export const WS_BASE = BASE.replace(/^https/, 'wss').replace(/^http/, 'ws')

class ApiError extends Error {
  constructor(public status: number, message: string) { super(message) }
}

function getToken(): string | null {
  return localStorage.getItem('amoon_token')
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(init.headers as Record<string, string>),
  }
  if (token) headers['Authorization'] = `Bearer ${token}`
  const res = await fetch(`${BASE}${path}`, { ...init, headers })
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }))
    throw new ApiError(res.status, body.error ?? res.statusText)
  }
  return res.json()
}

// ── Types ──────────────────────────────────────────────────────────────────

export type RoomType = {
  id: string
  name: string
  type: 'dm' | 'group'
  groupAdminId?: string
  memberCount?: number
  lastMessage?: string
  lastMessageAt?: number
  unreadCount?: number
}

export type BlockedUserType = {
  id: string
  username: string
  createdAt: number
}

export type MemberType = {
  id: string
  username: string
  displayName?: string
  publicKey: string
  fingerprint: string
}

export type MessageType = {
  id: string
  roomId: string
  senderId: string
  bundle: string
  createdAt: number
}

export type StoryType = {
  id: string
  userId: string
  content: string
  expiresAt: number
  createdAt: number
}

export type FriendType = {
  id: string
  username: string
  displayName?: string
  publicKey?: string
  friendId: string
}

export type FriendRequestType = {
  id: string
  fromId: string
  username: string
  publicKey?: string
  createdAt: number
}

export type SearchUserType = {
  id: string
  username: string
  displayName?: string
  publicKey?: string
}

export type PendingMessageType = {
  id: string
  fromUserId: string
  fromUsername: string
  bundle: string
  createdAt: number
}

export type ProfileType = {
  id: string
  username: string
  displayName?: string
  bio?: string
  publicKey?: string
  totpEnabled: boolean
  isAdmin: boolean
}

export type ReportType = {
  id: string
  reason: string
  detail?: string
  status: string
  adminNote?: string
  createdAt: number
  reporterUsername: string
  reporterId: string
  reportedUsername: string
  reportedId: string
}

// ── API Namespaces ─────────────────────────────────────────────────────────

export const roomsApi = {
  list: () => request<RoomType[]>('/api/rooms'),
  members: (roomId: string) => request<MemberType[]>(`/api/rooms/${roomId}/members`),
  startDm: (username: string) => request<{ id: string }>('/api/rooms/dm', {
    method: 'POST', body: JSON.stringify({ username }),
  }),
  createGroup: (name: string, members: string[]) => request<{ id: string }>('/api/rooms/group', {
    method: 'POST', body: JSON.stringify({ name, members }),
  }),
  addMember: (roomId: string, username: string) => request<{ status: string }>(`/api/rooms/${roomId}/members`, {
    method: 'POST', body: JSON.stringify({ username }),
  }),
  removeMember: (roomId: string, userId: string) => request<{ status: string }>(`/api/rooms/${roomId}/members/${userId}`, {
    method: 'DELETE',
  }),
  leaveGroup: (roomId: string) => request<{ status: string }>(`/api/rooms/${roomId}/leave`, { method: 'POST' }),
}

export const blocksApi = {
  list: () => request<BlockedUserType[]>('/api/blocks'),
  block: (userId: string) => request<{ status: string }>(`/api/blocks/${userId}`, { method: 'POST' }),
  unblock: (userId: string) => request<{ status: string }>(`/api/blocks/${userId}`, { method: 'DELETE' }),
}

export const messagesApi = {
  list: (roomId: string, before?: number) => {
    const q = before ? `?before=${before}&limit=50` : '?limit=50'
    return request<MessageType[]>(`/api/messages/${roomId}${q}`)
  },
  send: (roomId: string, bundle: string) => request<{ id: string }>(`/api/messages/${roomId}`, {
    method: 'POST', body: JSON.stringify({ bundle }),
  }),
}

export const storiesApi = {
  list: () => request<StoryType[]>('/api/notes'),
  create: (content: string) => request<{ id: string }>('/api/notes', {
    method: 'POST', body: JSON.stringify({ content }),
  }),
}

export const friendsApi = {
  list: () => request<FriendType[]>('/api/friends'),
  requests: () => request<FriendRequestType[]>('/api/friends/requests'),
  sendRequest: (username: string) => request<{ id: string; status: string }>('/api/friends/request', {
    method: 'POST', body: JSON.stringify({ username }),
  }),
  accept: (id: string) => request<{ status: string }>(`/api/friends/${id}/accept`, { method: 'POST' }),
  remove: (friendId: string) => request<{ status: string }>(`/api/friends/${friendId}`, { method: 'DELETE' }),
}

export const usersApi = {
  search: (q: string) => request<SearchUserType[]>(`/api/users/search?q=${encodeURIComponent(q)}`),
  me: () => request<ProfileType>('/api/users/me'),
  updateProfile: (data: { displayName?: string; bio?: string; username?: string }) =>
    request<{ status: string }>('/api/users/me', { method: 'PATCH', body: JSON.stringify(data) }),
  inviteLink: () => request<{ token: string; link: string }>('/api/users/invite-link'),
  resolveInvite: (token: string) => request<{ userId: string; username: string }>(`/api/users/invite/${token}`),
  totpSetup: () => request<{ secret: string; url: string }>('/api/users/totp/setup', { method: 'POST' }),
  totpVerify: (code: string) => request<{ status: string }>('/api/users/totp/verify', {
    method: 'POST', body: JSON.stringify({ code }),
  }),
  totpDisable: (code: string) => request<{ status: string }>('/api/users/totp/disable', {
    method: 'POST', body: JSON.stringify({ code }),
  }),
}

export const pendingApi = {
  list: () => request<PendingMessageType[]>('/api/pending'),
  send: (toUserId: string, bundle: string) => request<{ id: string; status: string }>(`/api/pending/send/${toUserId}`, {
    method: 'POST', body: JSON.stringify({ bundle }),
  }),
  accept: (id: string) => request<{ status: string; fromUserId: string }>(`/api/pending/${id}/accept`, { method: 'POST' }),
  dismiss: (id: string) => request<{ status: string }>(`/api/pending/${id}`, { method: 'DELETE' }),
}

export const moderationApi = {
  report: (reportedId: string, reason: string, detail?: string) =>
    request<{ status: string; id: string }>('/api/moderation/report', {
      method: 'POST', body: JSON.stringify({ reportedId, reason, detail }),
    }),
  banStatus: () => request<{ banned: boolean; bannedUntil: number; banCount: number }>('/api/moderation/ban/status'),
  adminReports: () => request<ReportType[]>('/api/moderation/admin/reports'),
  adminAction: (id: string, action: string, adminNote?: string) =>
    request<{ status: string }>(`/api/moderation/admin/reports/${id}/action`, {
      method: 'POST', body: JSON.stringify({ action, adminNote }),
    }),
}

export { ApiError }
