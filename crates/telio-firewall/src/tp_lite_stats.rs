//! Code related to TP-Lite stats collection

use core::slice;
use std::{collections::HashMap, ffi::c_void, net::IpAddr};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::libfirewall::{LibfwBlockedDomain, LibfwDnsMetrics};

/// A callback for getting TP-Lite stats from libfirewall
pub trait TpLiteStatsCallback: Send + Sync + std::fmt::Debug {
    /// Get the blocked domains that have been buffered so far
    /// Blocking this callback can result in losing blocked domains from subsequent calls
    fn collect(&self, domains: Vec<BlockedDomain>, metrics: DnsMetrics);
}

#[derive(Debug)]
///
pub struct NoopCallback;
impl TpLiteStatsCallback for NoopCallback {
    fn collect(&self, _domains: Vec<BlockedDomain>, _metrics: DnsMetrics) {}
}

pub(crate) struct CallbackManager {
    pub(crate) callback: RwLock<Box<Box<dyn TpLiteStatsCallback>>>,
}

impl CallbackManager {
    pub(crate) fn new() -> Self {
        Self {
            callback: RwLock::new(Box::new(Box::new(NoopCallback))),
        }
    }

    pub(crate) fn as_raw_ptr(&self) -> *mut c_void {
        let cb = self.callback.read();
        let ptr = &**cb as *const Box<dyn TpLiteStatsCallback>;
        ptr as *mut c_void
    }
}

pub(crate) extern "C" fn collect_stats(
    data: *mut c_void,
    domains: *const LibfwBlockedDomain,
    num_blocked_domains: usize,
    metrics: LibfwDnsMetrics,
) {
    if data.is_null() {
        return;
    }

    let cb = unsafe { &*(data as *const Box<dyn TpLiteStatsCallback>) };
    let domains = unsafe { std::slice::from_raw_parts(domains, num_blocked_domains) }
        .iter()
        .map(BlockedDomain::from)
        .collect();
    cb.collect(domains, metrics.into());
}

/// LibfwDnsMetrics but with nicer types
#[derive(Debug)]
pub struct DnsMetrics {
    ///
    pub num_requests: u32,
    ///
    pub num_responses: u32,
    ///
    pub num_malformed_requests: u32,
    ///
    pub num_malformed_responses: u32,
    ///
    pub num_cache_hits: u32,
    ///
    pub record_type_distribution: HashMap<u16, u32>,
    ///
    pub response_type_distribution: HashMap<u8, u32>,
}

impl From<LibfwDnsMetrics> for DnsMetrics {
    fn from(metrics: LibfwDnsMetrics) -> Self {
        Self {
            num_requests: metrics.num_requests,
            num_responses: metrics.num_responses,
            num_malformed_requests: metrics.num_malformed_requests,
            num_malformed_responses: metrics.num_malformed_responses,
            num_cache_hits: metrics.num_cache_hits,
            record_type_distribution: unsafe {
                slice::from_raw_parts(metrics.record_type_distribution, metrics.num_record_types)
                    .iter()
                    .map(|count| (count.rr_type, count.count))
                    .collect::<HashMap<u16, u32>>()
            },
            response_type_distribution: unsafe {
                slice::from_raw_parts(
                    metrics.response_code_distribution,
                    metrics.num_response_codes,
                )
                .iter()
                .map(|count| (count.rr_type, count.count))
                .collect::<HashMap<u8, u32>>()
            },
        }
    }
}

/// LibfwBlockedDomain but with nicer types
#[derive(Debug)]
pub struct BlockedDomain {
    ///
    pub domain_name: String,
    ///
    pub record_type: u16,
    ///
    pub timestamp: u64,
    ///
    pub category: String,
}

impl From<&LibfwBlockedDomain> for BlockedDomain {
    fn from(domain: &LibfwBlockedDomain) -> Self {
        Self {
            domain_name: unsafe { std::ffi::CStr::from_ptr(domain.domain_name) }
                .to_string_lossy()
                .into_owned(),
            record_type: domain.record_type,
            timestamp: domain.timestamp,
            category: unsafe { std::ffi::CStr::from_ptr(domain.category) }
                .to_string_lossy()
                .into_owned(),
        }
    }
}

/// Config options for the TP-Lite stats collection
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpLiteStatsOptions {
    #[serde(default)]
    /// DNS servers from which responses are analyzed to collect TP-Lite stats
    /// At least one must be configured, otherwise stats collection will be considered disabled
    pub dns_server_ips: Vec<IpAddr>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// When a domain has been blocked it is added to a buffer to not invoke the stats callback for every response
    ///
    /// The  maximum number of blocked domains (not unique) that will be buffered
    /// If the buffer fills up the oldest entries will be overwritten
    ///
    /// Default value: 100
    pub blocked_domains_buffer_size: Option<u64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// After how long stats will be passed to the callback, in seconds
    /// The interval this controls starts when the collected stats goes from empty to not empty
    ///
    /// Default value: 5
    pub callback_interval_s: Option<u64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// libfirewall disables OS/client-level caching of blocked domains when stats collection is enabled
    /// To not make extra DNS requests libfirewall has it's own DNS cache for blocked domains
    ///
    /// How many entries the libfirewall-specific DNS cache can hold
    ///
    /// Default value: 512
    pub cache_size: Option<u64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// When TP-Lite stats collection is enabled libfirewall keeps track of open DNS requests
    ///
    /// How many requests libfirewall can keep track of
    ///
    /// Default value: same as blocked_domains_buffer_size
    pub max_open_requests: Option<u64>,
}
