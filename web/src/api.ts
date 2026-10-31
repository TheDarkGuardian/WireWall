import type { Policy, Session, Snapshot, Scenario, EventHistory, AuditEntry } from './types';

let csrf = '';
export class ApiError extends Error {
  constructor(message: string, public status: number) { super(message); }
}
export function setCsrf(token: string) { csrf = token; }
export async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers);
  if (options.body) headers.set('Content-Type', 'application/json');
  if (options.method && options.method !== 'GET') headers.set('X-WireWall-CSRF', csrf);
  const response = await fetch(`/api/v1${path}`, { ...options, headers, credentials: 'same-origin' });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new ApiError(data.error || data.message || `İstek başarısız (${response.status})`, response.status);
  return data as T;
}
export const api = {
  session: () => request<Session>('/session'),
  login: (token: string) => request<Session>('/session', { method: 'POST', body: JSON.stringify({ token }) }),
  logout: () => request('/session', { method: 'DELETE' }),
  snapshot: () => request<Snapshot>('/snapshot'),
  validatePolicy: (policy: Policy) => request<{ valid: boolean; warnings?: string[] }>('/policy/validate', { method: 'POST', body: JSON.stringify({ policy }) }),
  applyPolicy: (policy: Policy, expectedVersion: number) => request<Policy>('/policy', { method: 'PUT', body: JSON.stringify({ policy, expectedVersion }) }),
  confirmPolicy: () => request('/policy/confirm', { method: 'POST', body: '{}' }),
  addBan: (address: string, reason: string, durationSeconds: number) => request('/bans', { method: 'POST', body: JSON.stringify({ address, reason, durationSeconds }) }),
  removeBan: (id: string) => request(`/bans/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  scenario: (scenario: Scenario) => request('/lab/scenarios', { method: 'POST', body: JSON.stringify({ scenario }) }),
  resetLab: () => request('/lab/reset', { method: 'POST' }),
  eventHistory: (query: string, signal?: AbortSignal) => request<EventHistory>(`/events?${query}`, { signal }),
  audit: (signal?: AbortSignal) => request<{ items: AuditEntry[] }>('/audit?limit=50', { signal }),
};
