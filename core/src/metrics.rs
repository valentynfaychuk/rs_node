use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicU64, Ordering};

static METRICS: Lazy<Metrics> = Lazy::new(|| Metrics::new());

pub struct Metrics {
    // Core protocol messages
    ping_count: AtomicU64,
    pong_count: AtomicU64,
    who_are_you_count: AtomicU64,

    // Transaction and peer management
    txpool_count: AtomicU64,
    peers_count: AtomicU64,

    // Blockchain operations
    sol_count: AtomicU64,
    entry_count: AtomicU64,
    attestation_bulk_count: AtomicU64,
    consensus_bulk_count: AtomicU64,

    // Catchup operations
    catchup_entry_count: AtomicU64,
    catchup_tri_count: AtomicU64,
    catchup_bi_count: AtomicU64,
    catchup_attestation_count: AtomicU64,

    // Special business operations
    special_business_count: AtomicU64,
    special_business_reply_count: AtomicU64,

    // Entry solicitation
    solicit_entry_count: AtomicU64,
    solicit_entry2_count: AtomicU64,

    // Error counters
    v2_error_count: AtomicU64,                     // Failed to parse MessageV2
    reassembly_error_count: AtomicU64,             // Reed-Solomon shard assembly
    etf_parsing_validation_error_count: AtomicU64, // ETF decoding and validation
    proto_handling_error_count: AtomicU64,         // Protocol message handling
    unknown_proto_error_count: AtomicU64,          // Unknown Protocol messages

    // Total packets counter
    total_v2udp_packets_count: AtomicU64, // Total UDP packets received
}

impl Metrics {
    fn new() -> Self {
        Self {
            ping_count: AtomicU64::new(0),
            pong_count: AtomicU64::new(0),
            who_are_you_count: AtomicU64::new(0),
            txpool_count: AtomicU64::new(0),
            peers_count: AtomicU64::new(0),
            sol_count: AtomicU64::new(0),
            entry_count: AtomicU64::new(0),
            attestation_bulk_count: AtomicU64::new(0),
            consensus_bulk_count: AtomicU64::new(0),
            catchup_entry_count: AtomicU64::new(0),
            catchup_tri_count: AtomicU64::new(0),
            catchup_bi_count: AtomicU64::new(0),
            catchup_attestation_count: AtomicU64::new(0),
            special_business_count: AtomicU64::new(0),
            special_business_reply_count: AtomicU64::new(0),
            solicit_entry_count: AtomicU64::new(0),
            solicit_entry2_count: AtomicU64::new(0),

            // Initialize error counters
            v2_error_count: AtomicU64::new(0),
            reassembly_error_count: AtomicU64::new(0),
            etf_parsing_validation_error_count: AtomicU64::new(0),
            proto_handling_error_count: AtomicU64::new(0),
            unknown_proto_error_count: AtomicU64::new(0),

            // Initialize total packets counter
            total_v2udp_packets_count: AtomicU64::new(0),
        }
    }
}

pub fn inc_ping() {
    METRICS.ping_count.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_pong() {
    METRICS.pong_count.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_who_are_you() {
    METRICS.who_are_you_count.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_txpool() {
    METRICS.txpool_count.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_peers() {
    METRICS.peers_count.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_sol() {
    METRICS.sol_count.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_entry() {
    METRICS.entry_count.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_attestation_bulk() {
    METRICS.attestation_bulk_count.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_consensus_bulk() {
    METRICS.consensus_bulk_count.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_catchup_entry() {
    METRICS.catchup_entry_count.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_catchup_tri() {
    METRICS.catchup_tri_count.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_catchup_bi() {
    METRICS.catchup_bi_count.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_catchup_attestation() {
    METRICS.catchup_attestation_count.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_special_business() {
    METRICS.special_business_count.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_special_business_reply() {
    METRICS.special_business_reply_count.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_solicit_entry() {
    METRICS.solicit_entry_count.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_solicit_entry2() {
    METRICS.solicit_entry2_count.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_v2udp_packets() {
    METRICS.total_v2udp_packets_count.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_v2_parsing_errors() {
    METRICS.v2_error_count.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_reassembly_errors() {
    METRICS.reassembly_error_count.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_parsing_and_validation_errors() {
    METRICS.etf_parsing_validation_error_count.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_handling_errors() {
    METRICS.proto_handling_error_count.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_unknown_proto() {
    METRICS.unknown_proto_error_count.fetch_add(1, Ordering::Relaxed);
}

/// Prometheus-formatted metrics string
pub fn get_metrics() -> String {
    let metrics = &*METRICS;

    let protocol_metrics = format!(
        r#"# HELP amadeus_protocol_messages_total Total number of protocol messages handled by type
# TYPE amadeus_protocol_messages_total counter
amadeus_protocol_messages_total{{type="ping"}} {}
amadeus_protocol_messages_total{{type="pong"}} {}
amadeus_protocol_messages_total{{type="who_are_you"}} {}
amadeus_protocol_messages_total{{type="txpool"}} {}
amadeus_protocol_messages_total{{type="peers"}} {}
amadeus_protocol_messages_total{{type="sol"}} {}
amadeus_protocol_messages_total{{type="entry"}} {}
amadeus_protocol_messages_total{{type="attestation_bulk"}} {}
amadeus_protocol_messages_total{{type="consensus_bulk"}} {}
amadeus_protocol_messages_total{{type="catchup_entry"}} {}
amadeus_protocol_messages_total{{type="catchup_tri"}} {}
amadeus_protocol_messages_total{{type="catchup_bi"}} {}
amadeus_protocol_messages_total{{type="catchup_attestation"}} {}
amadeus_protocol_messages_total{{type="special_business"}} {}
amadeus_protocol_messages_total{{type="special_business_reply"}} {}
amadeus_protocol_messages_total{{type="solicit_entry"}} {}
amadeus_protocol_messages_total{{type="solicit_entry2"}} {}

# HELP amadeus_packets_total Total number of UDP packets received
# TYPE amadeus_packets_total counter
amadeus_udp_packets_total {}
"#,
        metrics.ping_count.load(Ordering::Relaxed),
        metrics.pong_count.load(Ordering::Relaxed),
        metrics.who_are_you_count.load(Ordering::Relaxed),
        metrics.txpool_count.load(Ordering::Relaxed),
        metrics.peers_count.load(Ordering::Relaxed),
        metrics.sol_count.load(Ordering::Relaxed),
        metrics.entry_count.load(Ordering::Relaxed),
        metrics.attestation_bulk_count.load(Ordering::Relaxed),
        metrics.consensus_bulk_count.load(Ordering::Relaxed),
        metrics.catchup_entry_count.load(Ordering::Relaxed),
        metrics.catchup_tri_count.load(Ordering::Relaxed),
        metrics.catchup_bi_count.load(Ordering::Relaxed),
        metrics.catchup_attestation_count.load(Ordering::Relaxed),
        metrics.special_business_count.load(Ordering::Relaxed),
        metrics.special_business_reply_count.load(Ordering::Relaxed),
        metrics.solicit_entry_count.load(Ordering::Relaxed),
        metrics.solicit_entry2_count.load(Ordering::Relaxed),
        metrics.total_v2udp_packets_count.load(Ordering::Relaxed),
    );

    // Add error metrics
    let error_metrics = format!(
        r#"
# HELP amadeus_packet_errors_total Total number of packet processing errors by type
# TYPE amadeus_packet_errors_total counter
amadeus_packet_errors_total{{type="v2_parsing"}} {}
amadeus_packet_errors_total{{type="reassembly"}} {}
amadeus_packet_errors_total{{type="etf_decode_and_validation"}} {}
amadeus_packet_errors_total{{type="handling"}} {}
amadeus_packet_errors_total{{type="unknown_proto"}} {}
"#,
        metrics.v2_error_count.load(Ordering::Relaxed),
        metrics.reassembly_error_count.load(Ordering::Relaxed),
        metrics.etf_parsing_validation_error_count.load(Ordering::Relaxed),
        metrics.proto_handling_error_count.load(Ordering::Relaxed),
        metrics.unknown_proto_error_count.load(Ordering::Relaxed),
    );

    format!("{}{}", protocol_metrics, error_metrics)
}

/// Increment counter for a specific protocol message type
pub fn inc_handled_counter_by_name(proto_name: &str) {
    match proto_name {
        "ping" => inc_ping(),
        "pong" => inc_pong(),
        "who_are_you" => inc_who_are_you(),
        "txpool" => inc_txpool(),
        "peers" => inc_peers(),
        "sol" => inc_sol(),
        "entry" => inc_entry(),
        "attestation_bulk" => inc_attestation_bulk(),
        "consensus_bulk" => inc_consensus_bulk(),
        "catchup_entry" => inc_catchup_entry(),
        "catchup_tri" => inc_catchup_tri(),
        "catchup_bi" => inc_catchup_bi(),
        "catchup_attestation" => inc_catchup_attestation(),
        "special_business" => inc_special_business(),
        "special_business_reply" => inc_special_business_reply(),
        "solicit_entry" => inc_solicit_entry(),
        "solicit_entry2" => inc_solicit_entry2(),
        _ => {} // Unknown message type, ignore
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_increment_functions() {
        inc_ping();
        inc_pong();
        inc_entry();

        let metrics_str = get_metrics();
        assert!(metrics_str.contains("amadeus_protocol_messages_total{type=\"ping\"}"));
        assert!(metrics_str.contains("amadeus_protocol_messages_total{type=\"pong\"}"));
        assert!(metrics_str.contains("amadeus_protocol_messages_total{type=\"entry\"}"));
    }

    #[test]
    fn test_prometheus_format() {
        let metrics_str = get_metrics();
        assert!(metrics_str.contains("# HELP amadeus_protocol_messages_total"));
        assert!(metrics_str.contains("# TYPE amadeus_protocol_messages_total counter"));
    }

    #[test]
    fn test_inc_proto_message() {
        inc_handled_counter_by_name("ping");
        inc_handled_counter_by_name("entry");
        inc_handled_counter_by_name("unknown_type"); // Should be ignored

        let metrics_str = get_metrics();
        assert!(metrics_str.contains("amadeus_protocol_messages_total{type=\"ping\"}"));
        assert!(metrics_str.contains("amadeus_protocol_messages_total{type=\"entry\"}"));
    }

    #[test]
    fn test_error_counters() {
        inc_v2_parsing_errors();
        inc_reassembly_errors();
        inc_v2udp_packets();

        let metrics_str = get_metrics();
        assert!(metrics_str.contains("amadeus_packet_errors_total{type=\"parse_error\"}"));
        assert!(metrics_str.contains("amadeus_packet_errors_total{type=\"shard_error\"}"));
        assert!(metrics_str.contains("amadeus_packets_total"));
    }
}
