/* SPDX-License-Identifier: (GPL-2.0-only OR MIT) */
#ifndef WIREWALL_H
#define WIREWALL_H

#include <linux/types.h>

#define WW_MAX_RULES 64
#define WW_MAX_MANAGEMENT 16
#define WW_MAX_SOURCES 8192
#define WW_MAX_BANS 4096
#define WW_NS_PER_PACKET 1000000000ULL

enum ww_reason {
    WW_PASS, WW_DROP, WW_WOULD_DROP, WW_MALFORMED, WW_BANNED,
    WW_RULE_DROP, WW_SERVICE_LIMIT, WW_SOURCE_LIMIT, WW_FALLBACK,
    WW_CAPACITY_FALLBACK, WW_EVENT_LOST, WW_MANAGEMENT,
    WW_BYTE_LIMIT, WW_SOURCE_BYTE_LIMIT, WW_SERVICE_STATS_OVERFLOW, WW_REASON_COUNT
};

struct ww_prefix {
    __u8 family;
    __u8 bits;
    __u16 padding;
    __u8 address[16];
};

/* Layout is shared with internal/dataplane/compile.go. */
struct ww_rule {
    __u32 index;
    __u32 action;
    __u32 protocol;
    __u32 syn_only;
    struct ww_prefix source;
    struct ww_prefix destination;
    __u16 source_lo;
    __u16 source_hi;
    __u16 destination_lo;
    __u16 destination_hi;
    __u32 min_bytes;
    __u32 max_bytes;
    __u64 pps;
    __u64 burst;
    __u64 source_pps;
    __u64 source_burst;
    __u64 bps;
    __u64 byte_burst;
    __u64 source_bps;
    __u64 source_byte_burst;
};

struct ww_policy {
    __u64 version;
    __u32 enforce;
    __u32 rule_count;
    __u32 management_port;
    __u32 management_count;
    struct ww_prefix management[WW_MAX_MANAGEMENT];
    struct ww_rule rules[WW_MAX_RULES];
    /* Reserved ABI space. Complex packets fail closed in enforce mode. */
    __u64 reserved[2];
};

struct ww_counter { __u64 packets; __u64 bytes; };
struct ww_bucket_key { __u64 version; __u32 slot; __u32 padding; };
struct ww_source_key { __u64 version; __u32 slot; __u32 family; __u8 address[16]; };
struct ww_ban_key { __u64 version; __u32 family; __u32 padding; __u8 address[16]; };

struct ww_event {
    __u64 monotonic_ns;
    __u64 version;
    __u32 rule_index;
    __u32 reason;
    __u32 dropped;
    __u32 would_drop;
    __u32 family;
    __u32 protocol;
    __u8 source[16];
    __u8 destination[16];
    __u16 source_port;
    __u16 destination_port;
    __u32 length;
};

_Static_assert(sizeof(struct ww_prefix) == 20, "prefix ABI");
_Static_assert(sizeof(struct ww_rule) == 136, "rule ABI");
_Static_assert(sizeof(struct ww_policy) == 9064, "policy ABI");
_Static_assert(sizeof(struct ww_event) == 80, "event ABI");
#endif
