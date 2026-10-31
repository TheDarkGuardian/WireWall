# Observational port-scan warnings

This detector counts unique TCP destination ports per source/destination IP pair
using a trusted local clock. Default policy: 20 ports in a ten-second window,
30-second alert cooldown, 1,024 tracked pairs, 64 ports per pair and 100 retained
alerts. Source-table cleanup runs at most once per second by default. New pairs
at capacity are ignored and counted; active evidence is never LRU-evicted.

This is a **suspected scan warning**, not proof of an attack and not an automatic
ban. Distributed scans, scans slower than the window, scans spread over several
destinations and scans hidden by event sampling may not cross the threshold.
Port counts in sampled windows are observations, not complete traffic totals.
If any observation in the window was sampled, the alert's `sampled` field is true.
Packet-provided timestamps never control windows, expiry or cooldown.
