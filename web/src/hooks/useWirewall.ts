import { useCallback, useEffect, useRef, useState } from 'react';
import { api, ApiError, setCsrf } from '../api';
import type { Snapshot } from '../types';

function normalize(data: Snapshot): Snapshot {
  return { ...data, rules: data.rules || [], bans: data.bans || [], events: data.events || [],
    history: data.history || [], connections: data.connections || [],
    system: { ...data.system, capabilities: data.system.capabilities || [], health: data.system.health || [] },
    metrics: { ...data.metrics, reasons: data.metrics.reasons || [], protocols: data.metrics.protocols || [], services: data.metrics.services || [] },
    policy: { ...data.policy, rules: data.policy.rules || [], managementCidrs: data.policy.managementCidrs || [] } };
}

export function useWirewall() {
  const [checking, setChecking] = useState(true);
  const [authenticated, setAuthenticated] = useState(false);
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [error, setError] = useState('');
  const [connected, setConnected] = useState(false);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<number | null>(null);
  const lastEvent = useRef(0);
  const lastObservation = useRef(0);
  const authGeneration = useRef(0);
  const observationGeneration = useRef(0);
  const refreshGeneration = useRef(0);
  const loadSession = useCallback(async () => {
    const generation = ++authGeneration.current;
    setChecking(true);
    try {
      const data = await api.session();
      if (generation !== authGeneration.current) return;
      setCsrf(data.csrfToken || '');
      setAuthenticated(data.authenticated);
      setError('');
    } catch (err) { if (generation === authGeneration.current) setError(err instanceof Error ? err.message : 'API bağlantısı kurulamadı.'); }
    finally { if (generation === authGeneration.current) setChecking(false); }
  }, []);
  useEffect(() => { void loadSession(); }, [loadSession]);
  const login = useCallback(async (token: string) => {
    const generation = ++authGeneration.current;
    const data = await api.login(token);
    if (generation !== authGeneration.current) return;
    setCsrf(data.csrfToken || '');
    setAuthenticated(data.authenticated);
    setError('');
  }, []);
  const refresh = useCallback(async () => {
    const auth = authGeneration.current;
    const observation = observationGeneration.current;
    const request = ++refreshGeneration.current;
    try {
      const data = await api.snapshot();
      // A delayed HTTP result must not rewind a newer stream observation or
      // replace data belonging to a later request/session.
      if (auth !== authGeneration.current || request !== refreshGeneration.current || observation !== observationGeneration.current) return;
      observationGeneration.current++;
      setSnapshot(normalize(data));
      const now = Date.now();
      lastObservation.current = now;
      setLastUpdatedAt(now);
      setConnected(true);
      setError('');
    } catch (err) {
      if (auth !== authGeneration.current || request !== refreshGeneration.current) return;
      if (err instanceof ApiError && err.status === 401) {
        authGeneration.current++;
        setCsrf(''); setAuthenticated(false); setSnapshot(null); setConnected(false);
        setError(err.message);
        return;
      }
      if (observation !== observationGeneration.current) return;
      setConnected(false);
      setError(err instanceof ApiError ? err.message : 'Sunucudan güncel veriler alınamadı. Bağlantıyı kontrol edip yeniden deneyin.');
    }
  }, []);
  useEffect(() => {
    if (!authenticated) return;
    const auth = authGeneration.current;
    void refresh();
    const stream = new EventSource('/api/v1/stream');
    const receive = (event: MessageEvent) => {
      if (auth !== authGeneration.current) return;
      try {
        const data = normalize(JSON.parse(event.data) as Snapshot);
        observationGeneration.current++;
        setSnapshot(data);
        const now = Date.now();
        lastEvent.current = now;
        lastObservation.current = now;
        setLastUpdatedAt(now);
        setConnected(true); setError('');
      } catch { setConnected(false); setError('Canlı akıştan geçersiz veri alındı.'); }
    };
    stream.addEventListener('snapshot', receive);
    stream.onerror = () => { if (auth === authGeneration.current) void refresh(); };
    const fallback = setInterval(() => {
      if (auth !== authGeneration.current) return;
      const now = Date.now();
      if (now - lastObservation.current > 10000) setConnected(false);
      if (now - lastEvent.current > 5000) void refresh();
    }, 5000);
    return () => { stream.removeEventListener('snapshot', receive); stream.close(); clearInterval(fallback); };
  }, [authenticated, refresh]);
  const logout = useCallback(async () => {
    const auth = authGeneration.current;
    await api.logout();
    if (auth !== authGeneration.current) return;
    authGeneration.current++;
    setCsrf(''); setAuthenticated(false); setSnapshot(null); setConnected(false); setLastUpdatedAt(null); lastEvent.current = 0; lastObservation.current = 0;
  }, []);
  return { checking, authenticated, snapshot, error, connected, lastUpdatedAt, stale: snapshot !== null && !connected, login, logout, refresh, loadSession };
}
