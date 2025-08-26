use crate::utils::misc::{Typename, get_unix_secs_now};
use once_cell::sync::Lazy;
use scc::HashIndex;
use scc::ebr::Guard;
use serde_json::Value;
use std::collections::HashMap as StdHashMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tracing::warn;

pub static METRICS: Lazy<Metrics> = Lazy::new(Metrics::new);

pub struct Metrics {
    // Total packets counter
    incoming_bytes: AtomicU64,   // Total bytes received
    incoming_packets: AtomicU64, // Total UDP packets received

    // Handled protocol message counters by name (dynamic)
    handled_protos: HashIndex<String, Arc<AtomicU64>>,

    // Error counters by type name (dynamic)
    errors: HashIndex<String, Arc<AtomicU64>>,

    // Start time for uptime calculation
    start_time: u64,
}

impl Metrics {
    fn new() -> Self {
        let handled_protos = HashIndex::new();
        let errors = HashIndex::new();
        Self {
            incoming_bytes: AtomicU64::new(0),
            incoming_packets: AtomicU64::new(0),
            handled_protos,
            errors,
            start_time: get_unix_secs_now(),
        }
    }

    #[inline]
    pub fn add_handled_proto_by_name(&self, proto_name: &str) {
        // correct way of handling ownership in scc HashIndex
        let pn_owned = proto_name.to_string();
        if let Some(counter) = METRICS.handled_protos.get(&pn_owned) {
            counter.fetch_add(1, Ordering::Relaxed);
        } else {
            let _ = self.handled_protos.insert(pn_owned, Arc::new(AtomicU64::new(1)));
        }
    }

    /// Increment UDP packet count with size
    pub fn add_v2_udp_packet(&self, len: usize) {
        self.incoming_bytes.fetch_add(len as u64, Ordering::Relaxed);
        self.incoming_packets.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment V2 parsing errors
    pub fn add_error<E: Debug + Typename>(&self, error: &E) {
        warn!(target = "metrics", "v2 error: {error:?}");
        self.add_error_by_name(error.typename());
    }

    fn add_error_by_name(&self, error_type: &str) {
        // correct way of handling ownership in scc HashIndex
        let et_owned = error_type.to_string();
        if let Some(counter) = self.errors.get(&et_owned) {
            counter.fetch_add(1, Ordering::Relaxed);
        } else {
            let _ = METRICS.errors.insert(et_owned, Arc::new(AtomicU64::new(1)));
        }
    }

    /// Get JSON-formatted metrics
    pub fn get_json(&self) -> Value {
        let guard = Guard::new();

        let mut protos = StdHashMap::new();
        let mut iter = self.handled_protos.iter(&guard);
        while let Some((proto_name, counter)) = iter.next() {
            protos.insert(proto_name.clone(), counter.load(Ordering::Relaxed));
        }

        let mut errors = StdHashMap::new();
        let mut iter = self.errors.iter(&guard);
        while let Some((error_type, counter)) = iter.next() {
            errors.insert(error_type.clone(), counter.load(Ordering::Relaxed));
        }

        let uptime_seconds = get_unix_secs_now() - self.start_time;

        serde_json::json!({
            "handled_protos": protos,
            "errors": errors,
            "packets": self.get_packets_json(uptime_seconds),
            "uptime": uptime_seconds
        })
    }

    fn get_packets_json(&self, uptime_seconds: u64) -> serde_json::Value {
        static LAST_INCOMING_BYTES: AtomicU64 = AtomicU64::new(0);
        static LAST_INCOMING_PACKETS: AtomicU64 = AtomicU64::new(0);
        static LAST_UPTIME_SECONDS: AtomicU64 = AtomicU64::new(0);

        let incoming_packets = self.incoming_packets.load(Ordering::Relaxed);
        let incoming_bytes = self.incoming_bytes.load(Ordering::Relaxed);

        let lus = LAST_UPTIME_SECONDS.swap(uptime_seconds, Ordering::Relaxed);
        let lip = LAST_INCOMING_PACKETS.swap(incoming_packets, Ordering::Relaxed);
        let lib = LAST_INCOMING_BYTES.swap(incoming_bytes, Ordering::Relaxed);

        if lus == 0 {
            return serde_json::json!({
                "total_incoming_packets": incoming_packets,
                "total_incoming_bytes": incoming_bytes
            });
        }

        let seconds = uptime_seconds - lus;
        let packets = incoming_packets - lip;
        let bytes = incoming_bytes - lib;

        serde_json::json!({
            "total_incoming_packets": incoming_packets,
            "total_incoming_bytes": incoming_bytes,
            "packets_per_second": packets / seconds,
            "bytes_per_second": bytes / seconds,
        })
    }

    /// Prometheus-formatted metrics string
    pub fn get_prometheus(&self) -> String {
        let packets = format!(
            r#"
# HELP amadeus_packets_total Total number of UDP packets received
# TYPE amadeus_packets_total counter
amadeus_udp_packets_total {}
amadeus_bytes_total {}

# HELP amadeus_uptime_seconds Process uptime in seconds
# TYPE amadeus_uptime_seconds gauge
amadeus_uptime_seconds {}"#,
            self.incoming_packets.load(Ordering::Relaxed),
            self.incoming_bytes.load(Ordering::Relaxed),
            get_unix_secs_now() - self.start_time
        );

        let mut protos = Vec::new();
        protos.push("\n\n# HELP amadeus_protocol_messages_total Total number of proto messages handled by type".into());
        protos.push("# TYPE amadeus_protocol_messages_total counter".into());
        let guard = Guard::new();
        let mut iter = self.handled_protos.iter(&guard);
        while let Some((proto_name, counter)) = iter.next() {
            let count = counter.load(Ordering::Relaxed);
            protos.push(format!("amadeus_protocol_messages_total{{type=\"{}\"}} {}", proto_name, count));
        }

        let mut errors = Vec::new();
        errors.push("\n\n# HELP amadeus_packet_errors_total Total number of packet processing errors by type".into());
        errors.push("# TYPE amadeus_packet_errors_total counter".into());
        let mut iter = self.errors.iter(&guard);
        while let Some((error_type, counter)) = iter.next() {
            let count = counter.load(Ordering::Relaxed);
            errors.push(format!("amadeus_packet_errors_total{{type=\"{}\"}} {}", error_type, count));
        }

        format!("{}{}{}", packets, protos.join("\n"), errors.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_prometheus_format() {
        let metrics_str = METRICS.get_prometheus();
        assert!(metrics_str.contains("# HELP amadeus_protocol_messages_total"));
        assert!(metrics_str.contains("# TYPE amadeus_protocol_messages_total counter"));
    }
}
