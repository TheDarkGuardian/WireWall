const integer = new Intl.NumberFormat('tr-TR');
const decimal = new Intl.NumberFormat('tr-TR', { maximumFractionDigits: 1 });
export const number = (value: number | undefined) => integer.format(value || 0);
export const shortNumber = (value: number | undefined) => {
  const amount = value || 0;
  if (amount >= 1_000_000_000) return `${decimal.format(amount / 1_000_000_000)} G`;
  if (amount >= 1_000_000) return `${decimal.format(amount / 1_000_000)} M`;
  if (amount >= 1_000) return `${decimal.format(amount / 1_000)} K`;
  return decimal.format(amount);
};
export function bytes(value: number | null | undefined) {
  if (value == null) return '—';
  if (value < 1024) return `${integer.format(value)} B`;
  const unit = Math.min(3, Math.floor(Math.log(value) / Math.log(1024)));
  return `${decimal.format(value / 1024 ** unit)} ${['B', 'KiB', 'MiB', 'GiB'][unit]}`;
}
export const time = (value: string) => new Date(value).toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
export function remaining(expiresAt: string) {
  const seconds = Math.max(0, Math.ceil((new Date(expiresAt).getTime() - Date.now()) / 1000));
  if (!seconds) return 'Süresi doldu';
  if (seconds < 60) return `${seconds} sn`;
  if (seconds < 3600) return `${Math.ceil(seconds / 60)} dk`;
  return `${Math.floor(seconds / 3600)} sa ${Math.ceil((seconds % 3600) / 60)} dk`;
}
export function duration(seconds: number) {
  if (seconds < 60) return `${Math.floor(seconds)} sn`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} dk`;
  return `${Math.floor(seconds / 3600)} sa ${Math.floor((seconds % 3600) / 60)} dk`;
}
const reasons: Record<string, string> = {
  pass: 'Sonraki katmana devret', default_pass: 'Varsayılan devretme', 'default-pass': 'Varsayılan devretme',
  rate_limit: 'Hız sınırı', 'rate-limit': 'Hız sınırı', rate_limited: 'Hız sınırı',
  source_rate_limit: 'Kaynak hız sınırı', service_rate_limit: 'Servis hız sınırı',
  banned: 'IP engeli', ban: 'IP engeli', ip_ban: 'IP engeli',
  rule_drop: 'Kural eşleşmesi', rule: 'Kural eşleşmesi', 'rule-drop': 'Kural eşleşmesi',
  rule_pass: 'Kural izni', 'rule-pass': 'Kural izni', management: 'Yönetim istisnası',
  management_bypass: 'Yönetim istisnası', invalid_packet: 'Geçersiz paket', malformed: 'Hatalı başlık',
  host_service_denied: 'Host servis izni yok', host_invalid: 'Geçersiz bağlantı durumu',
  host_ipv6_disabled: 'IPv6 servisi kapalı', host_tcp_syn_required: 'TCP başlangıcı gerekli',
  rule_match: 'Kural eşleşmesi', source_limit: 'Kaynak hız sınırı', aggregate_limit: 'Toplam hız sınırı',
  service_limit: 'Servis hız sınırı', complex_packet: 'Desteklenmeyen karmaşık paket',
  temporary_ban: 'Süreli IP engeli', management_exemption: 'Yönetim istisnası',
  rate_limit_pass: 'Hız bütçesi içinde', source_capacity_fallback: 'Kaynak tablosu kapasitesi',
  invalid_policy: 'Geçersiz politika', capacity_fallback: 'Tablo kapasitesi', event_lost: 'Olay kaybı',
  byte_limit: 'Servis byte sınırı', source_byte_limit: 'Kaynak byte sınırı',
};
export const reason = (value: string) => reasons[value] || value.replaceAll('_', ' ');
