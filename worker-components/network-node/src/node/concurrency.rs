// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use crate::wlog;

pub(crate) fn resolve_max_concurrent(explicit: Option<usize>) -> usize {
    const DEFAULT_MAX_CONCURRENT: usize = 100;
    explicit.unwrap_or_else(|| match read_cgroup_memory_limit() {
        Some(limit) => {
            let mc = derive_max_concurrent(limit);
            wlog!(
                "network-node: cgroup memory limit {:.0} MiB → max_concurrent_requests={}",
                limit as f64 / (1024.0 * 1024.0),
                mc,
            );
            mc
        }
        None => {
            wlog!(
                "network-node: no cgroup memory limit detected, \
                 max_concurrent_requests={DEFAULT_MAX_CONCURRENT} (default)"
            );
            DEFAULT_MAX_CONCURRENT
        }
    })
}

fn read_cgroup_memory_limit() -> Option<usize> {
    if let Ok(s) = std::fs::read_to_string("/sys/fs/cgroup/memory.max") {
        return parse_cgroup_v2_limit(&s);
    }
    std::fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes")
        .ok()
        .and_then(|s| parse_cgroup_v1_limit(&s))
}

fn parse_cgroup_v2_limit(s: &str) -> Option<usize> {
    let s = s.trim();
    if s == "max" {
        None
    } else {
        s.parse::<usize>().ok()
    }
}

fn parse_cgroup_v1_limit(s: &str) -> Option<usize> {
    s.trim()
        .parse::<usize>()
        .ok()
        .filter(|n| *n < (1usize << 62))
}

fn derive_max_concurrent(memory_limit: usize) -> usize {
    const BASELINE: usize = 256 * 1024;
    const PER_REQUEST: usize = 100 * 1024;
    const MIN: usize = 10;
    (memory_limit.saturating_sub(BASELINE) / PER_REQUEST).max(MIN)
}
