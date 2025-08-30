//pub mod etf_ser;
pub mod anr;
pub mod msg_v2;
pub mod node_gen;
pub mod peers;
/// The network protocol of the Amadeus node
pub mod protocol;
pub mod reassembler;
pub mod socket_gen;
pub mod state;

// Broadcaster trait defines a minimal sending capability for UDP broadcast mechanisms.
pub trait Broadcaster: Send + Sync {
    /// fire-and-forget send to a set of IPv4 addresses with a pre-serialized payload
    fn send_to(&self, ips: Vec<String>, payload: Vec<u8>);
}

pub use node_gen::NodeGen;
pub use peers::NodePeers;
pub use reassembler::ReedSolomonReassembler;
pub use socket_gen::NodeGenSocketGen;
pub use state::{NodeState, StateMessage};
