/* SPDX-License-Identifier: (GPL-2.0-only OR MIT) */
/* Original WireWall early ingress filter. Stateful acceptance belongs to nftables.
 * Enforce mode rejects complex/unsupported IP packets because the downstream
 * service policy is not a full mirror of the early ordered ACL.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "wirewall.h"

/* Clang 14 may emit only a forward declaration for a nested map value type.
 * Use an explicit compile-time size for map creation, retain concrete ABI BTF
 * in a read-only sentinel for the loader's ELF/offset validation tests.
 * Active policy maps are created and published by Go; sentinel is never read.
 */
const struct ww_policy abi_policy SEC(".rodata") = {};
struct ww_policy_map {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __uint(value_size, sizeof(struct ww_policy));
} policy_template SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 1);
    __type(key, __u32);
    __array(values, struct ww_policy_map);
} policies SEC(".maps");

struct ww_bucket {
    struct bpf_spin_lock lock;
    __u32 padding;
    __u64 updated_ns;
    __u64 credits;
    __u64 byte_credits;
};
_Static_assert(sizeof(struct ww_bucket) == 32, "bucket ABI");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct ww_bucket_key);
    __type(value, struct ww_bucket);
} service_buckets SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, WW_MAX_SOURCES);
    __type(key, struct ww_source_key);
    __type(value, struct ww_bucket);
} source_buckets SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    /* Two generations can coexist while the next policy is staged. */
    __uint(max_entries, WW_MAX_BANS * 2);
    __type(key, struct ww_ban_key);
    __type(value, __u64);
} bans SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, WW_REASON_COUNT);
    __type(key, __u32);
    __type(value, struct ww_counter);
} counters SEC(".maps");
/* Unsampled ingress classification; bounded service cardinality cannot grow
 * with an adversary's destination-port scan. Overflow is explicit telemetry.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, struct ww_counter);
} protocol_counts SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct ww_counter);
} service_counts SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");
/* A reader announces itself before it can obtain a policy-map reference.
 * The loader may reclaim retired generations only after observing zero on
 * every CPU after publication. Active values are never reset by userspace.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} readers SEC(".maps");

struct ww_packet {
    __u32 family, protocol, length, syn;
    __u8 source[16], destination[16];
    __u16 source_port, destination_port;
};
struct ww_eth { __u8 destination[6], source[6]; __be16 protocol; } __attribute__((packed));
struct ww_vlan { __be16 tci, protocol; } __attribute__((packed));
struct ww_ipv4 {
    __u8 version_ihl, tos; __be16 length, identification, fragment;
    __u8 ttl, protocol; __be16 checksum; __u8 source[4], destination[4];
} __attribute__((packed));
struct ww_ipv6 {
    __u8 version_flow[4]; __be16 length; __u8 next, hops;
    __u8 source[16], destination[16];
} __attribute__((packed));
struct ww_tcp {
    __be16 source, destination; __be32 sequence, acknowledgement;
    __u8 offset, flags; __be16 window, checksum, urgent;
} __attribute__((packed));
struct ww_udp { __be16 source, destination, length, checksum; } __attribute__((packed));

static __always_inline void count(__u32 reason, __u32 length)
{
    struct ww_counter *value = bpf_map_lookup_elem(&counters, &reason);
    if (value) { value->packets++; value->bytes += length; }
}

static __always_inline __u32 packet_length(__be16 network_length)
{
    __u64 length = bpf_ntohs(network_length);
    /* Linux 5.15 can lose scalar bounds after the endian instruction emitted
     * for packed fields. Keep a real mask before packet-pointer arithmetic;
     * the compiler barrier prevents Clang from deleting it as redundant.
     */
    __asm__ __volatile__("" : "+r"(length));
    return length & 0xffff;
}

/* 0 = parsed, 1 = complex/unsupported, 2 = non-IP, -1 = malformed. */
static __always_inline int parse(struct xdp_md *ctx, struct ww_packet *out)
{
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    struct ww_eth *eth = data;
    if ((void *)(eth + 1) > end) return -1;
    __u16 protocol = bpf_ntohs(eth->protocol);
    __u32 offset = sizeof(*eth);
#pragma unroll
    for (int i = 0; i < 2; i++) {
        if (protocol == ETH_P_8021Q || protocol == ETH_P_8021AD) {
            struct ww_vlan *vlan = data + offset;
            if ((void *)(vlan + 1) > end) return -1;
            protocol = bpf_ntohs(vlan->protocol);
            offset += sizeof(*vlan);
        }
    }
    if (protocol == ETH_P_8021Q || protocol == ETH_P_8021AD) return 1;
    __u32 layer4_length = 0;
    if (protocol == ETH_P_IP) {
        struct ww_ipv4 *ip = data + offset;
        if ((void *)(ip + 1) > end || ip->version_ihl >> 4 != 4) return -1;
        __u32 ihl = (ip->version_ihl & 15) * 4;
        __u32 length = packet_length(ip->length);
        if (ihl < 20 || length < ihl || data + offset + length > end) return -1;
        if (bpf_ntohs(ip->fragment) & 0x8000) return -1;
        out->family = 4; out->protocol = ip->protocol; out->length = length;
        __builtin_memcpy(out->source, ip->source, 4);
        __builtin_memcpy(out->destination, ip->destination, 4);
        if (ihl != 20 || (bpf_ntohs(ip->fragment) & 0x3fff)) return 1;
        offset += ihl; layer4_length = length - ihl;
    } else if (protocol == ETH_P_IPV6) {
        struct ww_ipv6 *ip = data + offset;
        if ((void *)(ip + 1) > end || ip->version_flow[0] >> 4 != 6) return -1;
        __u32 length = packet_length(ip->length);
        out->family = 6; out->protocol = ip->next; out->length = length + 40;
        __builtin_memcpy(out->source, ip->source, 16);
        __builtin_memcpy(out->destination, ip->destination, 16);
        if (!length) return 1; /* IPv6 jumbograms require extension processing. */
        if (data + offset + 40 + length > end) return -1;
        offset += 40; layer4_length = length;
    } else if (protocol == ETH_P_ARP) {
        return 2; /* ARP is required for ordinary IPv4 neighbor resolution. */
    } else {
        return 1; /* Other L2 encapsulations are outside this strict profile. */
    }
    if (out->protocol == 6) {
        struct ww_tcp *tcp = data + offset;
        if (layer4_length < sizeof(*tcp) || (void *)(tcp + 1) > end) return -1;
        __u32 header_length = (tcp->offset >> 4) * 4;
        if (header_length < 20 || header_length > layer4_length || data + offset + header_length > end) return -1;
        /* SYN+FIN, SYN+RST and FIN+RST cannot describe a valid TCP segment.
         * SYN+ACK remains valid; ACK alone never establishes trusted state.
         */
        if (((tcp->flags & 0x02) && (tcp->flags & 0x05)) ||
            ((tcp->flags & 0x05) == 0x05)) return -1;
        out->source_port = bpf_ntohs(tcp->source);
        out->destination_port = bpf_ntohs(tcp->destination);
        out->syn = (tcp->flags & 0x12) == 0x02;
    } else if (out->protocol == 17) {
        struct ww_udp *udp = data + offset;
        if (layer4_length < sizeof(*udp) || (void *)(udp + 1) > end) return -1;
        __u32 length = packet_length(udp->length);
        if (length < 8 || length > layer4_length || data + offset + length > end) return -1;
        out->source_port = bpf_ntohs(udp->source);
        out->destination_port = bpf_ntohs(udp->destination);
    } else if (out->protocol == 1 || out->protocol == 58) {
        if (layer4_length < 8 || data + offset + 8 > end) return -1;
    } else {
        return 1; /* Includes IPv6 extension headers; never guess an L4 offset. */
    }
    return 0;
}

static __always_inline int prefix_matches(const struct ww_prefix *prefix, __u32 family, const __u8 *address)
{
    if (!prefix->family) return 1;
    if (prefix->family != family) return 0;
    __u32 remaining = prefix->bits;
#pragma unroll
    for (int i = 0; i < 16; i++) {
        if (remaining >= 8) {
            if (prefix->address[i] != address[i]) return 0;
            remaining -= 8;
        } else if (remaining) {
            __u8 mask = 0xff << (8 - remaining);
            if ((prefix->address[i] & mask) != (address[i] & mask)) return 0;
            remaining = 0;
        }
    }
    return 1;
}

/* Fractional packet credits avoid resetting sub-packet refill on each arrival.
 * Policy validation caps rate and burst at 1e9, keeping products in u64.
 * No BPF helper calls are made while the bucket's spin lock is held.
 */
static __always_inline __u64 refill_credits(__u64 credits, __u64 elapsed, __u64 rate, __u64 burst)
{
    if (!rate) return 0;
    __u64 capacity = burst * WW_NS_PER_PACKET;
    if (credits > capacity) credits = capacity;
    __u64 deficit = capacity - credits;
    if (elapsed >= deficit / rate + (deficit % rate != 0)) return capacity;
    return credits + elapsed * rate;
}

/* 1=allow, 0=packet limit, 2=byte limit, -1=missing/invalid bucket. Packet
 * and byte credits are checked and charged together under one shared lock.
 */
static __always_inline int consume(struct ww_bucket *bucket, __u64 now,
                                  __u64 rate, __u64 burst, __u64 byte_rate,
                                  __u64 byte_burst, __u32 length)
{
    if (!bucket || ((!rate) != (!burst)) || ((!byte_rate) != (!byte_burst)) ||
        (!rate && !byte_rate)) return -1;
    int allowed = 1;
    bpf_spin_lock(&bucket->lock);
    __u64 elapsed = now > bucket->updated_ns ? now - bucket->updated_ns : 0;
    bucket->credits = refill_credits(bucket->credits, elapsed, rate, burst);
    bucket->byte_credits = refill_credits(bucket->byte_credits, elapsed, byte_rate, byte_burst);
    /* A CPU may have captured now before another CPU acquired this lock.
     * Never move the shared refill timestamp backwards in that case.
     */
    if (now > bucket->updated_ns) bucket->updated_ns = now;
    __u64 byte_cost = ((__u64)length) * WW_NS_PER_PACKET;
    if (rate && bucket->credits < WW_NS_PER_PACKET) {
        allowed = 0;
    } else if (byte_rate && bucket->byte_credits < byte_cost) {
        allowed = 2;
    } else {
        if (rate) bucket->credits -= WW_NS_PER_PACKET;
        if (byte_rate) bucket->byte_credits -= byte_cost;
    }
    bpf_spin_unlock(&bucket->lock);
    return allowed;
}

static __always_inline int service_allow(__u64 version, __u32 slot, __u64 now,
                                        __u64 rate, __u64 burst, __u64 byte_rate,
                                        __u64 byte_burst, __u32 length)
{
    struct ww_bucket_key key = { .version = version, .slot = slot };
    struct ww_bucket *bucket = bpf_map_lookup_elem(&service_buckets, &key);
    if (!bucket) {
        struct ww_bucket initial = { .updated_ns = now, .credits = burst * WW_NS_PER_PACKET,
                                     .byte_credits = byte_burst * WW_NS_PER_PACKET };
        bpf_map_update_elem(&service_buckets, &key, &initial, BPF_NOEXIST);
        bucket = bpf_map_lookup_elem(&service_buckets, &key);
    }
    return consume(bucket, now, rate, burst, byte_rate, byte_burst, length);
}

static __always_inline int source_allow(__u64 version, __u32 slot, const struct ww_packet *packet,
                                       __u64 now, __u64 rate, __u64 burst,
                                       __u64 byte_rate, __u64 byte_burst)
{
    struct ww_source_key key = { .version = version, .slot = slot, .family = packet->family };
    __builtin_memcpy(key.address, packet->source, 16);
    struct ww_bucket *bucket = bpf_map_lookup_elem(&source_buckets, &key);
    if (!bucket) {
        struct ww_bucket initial = { .updated_ns = now, .credits = burst * WW_NS_PER_PACKET,
                                     .byte_credits = byte_burst * WW_NS_PER_PACKET };
        bpf_map_update_elem(&source_buckets, &key, &initial, BPF_NOEXIST);
        bucket = bpf_map_lookup_elem(&source_buckets, &key);
    }
    return consume(bucket, now, rate, burst, byte_rate, byte_burst, packet->length);
}

static __always_inline int verdict(const struct ww_policy *policy, const struct ww_packet *packet,
                                  __u32 reason, __u32 rule_index, int reject)
{
    int dropped = reject && policy->enforce;
    count(dropped ? WW_DROP : WW_PASS, packet->length);
    if (reason != WW_PASS) count(reason, packet->length);
    if (reject && !policy->enforce) count(WW_WOULD_DROP, packet->length);
    /* Events are sampled AND globally budgeted. Counters stay unsampled. */
    if ((bpf_get_prandom_u32() & 63) == 0) {
        __u64 now = bpf_ktime_get_ns();
        if (service_allow(policy->version, 0xfffffffe, now, 64, 64, 0, 0, 0) == 1) {
            struct ww_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
            if (event) {
                __builtin_memset(event, 0, sizeof(*event));
                event->monotonic_ns = now; event->version = policy->version;
                event->rule_index = rule_index; event->reason = reason;
                event->dropped = dropped; event->would_drop = reject && !policy->enforce;
                event->family = packet->family; event->protocol = packet->protocol;
                __builtin_memcpy(event->source, packet->source, 16);
                __builtin_memcpy(event->destination, packet->destination, 16);
                event->source_port = packet->source_port; event->destination_port = packet->destination_port;
                event->length = packet->length;
                bpf_ringbuf_submit(event, 0);
            } else count(WW_EVENT_LOST, 0);
        }
    }
    return dropped ? XDP_DROP : XDP_PASS;
}

__noinline int record_stats(struct xdp_md *ctx)
{
    struct ww_packet storage = {};
    storage.length = ctx->data_end - ctx->data;
    int parsed = parse(ctx, &storage);
    const struct ww_packet *packet = &storage;
    __u32 category = parsed < 0 ? 7 : parsed == 1 ? 6 : parsed == 2 ? 5 :
        packet->protocol == 6 ? 1 : packet->protocol == 17 ? 2 :
        packet->protocol == 1 ? 3 : packet->protocol == 58 ? 4 : 0;
    struct ww_counter *stat = bpf_map_lookup_elem(&protocol_counts, &category);
    if (stat) { stat->packets++; stat->bytes += packet->length; }
    if (!parsed && (packet->protocol == 6 || packet->protocol == 17)) {
        __u32 key = (packet->protocol << 16) | packet->destination_port;
        stat = bpf_map_lookup_elem(&service_counts, &key);
        if (!stat) {
            struct ww_counter empty = {};
            bpf_map_update_elem(&service_counts, &key, &empty, BPF_NOEXIST);
            stat = bpf_map_lookup_elem(&service_counts, &key);
        }
        if (stat) { stat->packets++; stat->bytes += packet->length; }
        else count(WW_SERVICE_STATS_OVERFLOW, packet->length);
    }
    return 0;
}

__noinline int process_packet(struct xdp_md *ctx)
{
    __u32 zero = 0;
    void *inner = bpf_map_lookup_elem(&policies, &zero);
    if (!inner) return XDP_ABORTED;
    struct ww_policy *policy = bpf_map_lookup_elem(inner, &zero);
    if (!policy) return XDP_ABORTED;
    struct ww_packet packet = {};
    packet.length = ctx->data_end - ctx->data;
    int parsed = parse(ctx, &packet);
    if (parsed < 0) return verdict(policy, &packet, WW_MALFORMED, 0xffffffff, 1);
    if (parsed == 2) return verdict(policy, &packet, WW_PASS, 0xffffffff, 0);
    __u64 now = bpf_ktime_get_ns();

    if (!parsed && packet.protocol == 6 && packet.destination_port == policy->management_port) {
#pragma clang loop unroll(disable)
        for (__u32 i = 0; i < WW_MAX_MANAGEMENT; i++) {
            if (i >= policy->management_count) break;
            if (prefix_matches(&policy->management[i], packet.family, packet.source))
                return verdict(policy, &packet, WW_MANAGEMENT, 0xffffffff, 0);
        }
    }
    struct ww_ban_key ban_key = { .version = policy->version, .family = packet.family };
    __builtin_memcpy(ban_key.address, packet.source, 16);
    __u64 *expiry = bpf_map_lookup_elem(&bans, &ban_key);
    if (expiry && *expiry > now) return verdict(policy, &packet, WW_BANNED, 0xffffffff, 1);

    if (parsed == 1) {
        /* Fail closed: passing to a service-only nftables policy would let an
         * IP/CIDR/port ACL be bypassed with fragments or extension headers.
         * Observe deliberately counts this as would-drop and forwards it.
         */
        return verdict(policy, &packet, WW_FALLBACK, 0xffffffff, 1);
    }
#pragma clang loop unroll(disable)
    for (__u32 i = 0; i < WW_MAX_RULES; i++) {
        if (i >= policy->rule_count) break;
        const struct ww_rule *rule = &policy->rules[i];
        if (rule->protocol && rule->protocol != packet.protocol) continue;
        if (!prefix_matches(&rule->source, packet.family, packet.source) ||
            !prefix_matches(&rule->destination, packet.family, packet.destination)) continue;
        if (packet.source_port < rule->source_lo || packet.source_port > rule->source_hi ||
            packet.destination_port < rule->destination_lo || packet.destination_port > rule->destination_hi) continue;
        if (rule->min_bytes && packet.length < rule->min_bytes) continue;
        if (rule->max_bytes && packet.length > rule->max_bytes) continue;
        if (rule->syn_only && !packet.syn) continue;
        if (rule->action == 1) return verdict(policy, &packet, WW_RULE_DROP, rule->index, 1);
        if (rule->action == 2) {
            int allowed = service_allow(policy->version, i, now, rule->pps, rule->burst,
                                        rule->bps, rule->byte_burst, packet.length);
            if (allowed == 2) return verdict(policy, &packet, WW_BYTE_LIMIT, rule->index, 1);
            if (allowed != 1) return verdict(policy, &packet, WW_SERVICE_LIMIT, rule->index, 1);
            if (rule->source_pps || rule->source_bps) {
                allowed = source_allow(policy->version, i, &packet, now, rule->source_pps, rule->source_burst,
                                       rule->source_bps, rule->source_byte_burst);
                if (allowed == 2) return verdict(policy, &packet, WW_SOURCE_BYTE_LIMIT, rule->index, 1);
                if (!allowed) return verdict(policy, &packet, WW_SOURCE_LIMIT, rule->index, 1);
                if (allowed < 0) count(WW_CAPACITY_FALLBACK, packet.length);
            }
        }
        return verdict(policy, &packet, WW_PASS, rule->index, 0);
    }
    return verdict(policy, &packet, WW_PASS, 0xffffffff, 0);
}

SEC("xdp") int wirewall_xdp(struct xdp_md *ctx)
{
    __u32 zero = 0;
    __u64 *active = bpf_map_lookup_elem(&readers, &zero);
    if (!active) return XDP_ABORTED;
    /* These full-barrier atomics also order the policy lookup and all reads
     * before the exit announcement. XDP execution remains on the same CPU.
     * Keeping the entry/exit wrapper outside process_packet covers every
     * malformed, unsupported, non-IP, map-missing, pass and drop path.
     */
    __sync_fetch_and_add(active, 1);
    int action = process_packet(ctx);
    record_stats(ctx);
    __sync_fetch_and_add(active, (__u64)-1);
    return action;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
