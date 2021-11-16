use std::collections::HashMap;

use once_cell::sync::Lazy;
use strum::VariantNames;

use near_metrics::{
    inc_counter_by_opt, inc_counter_opt, try_create_histogram, try_create_int_counter,
    try_create_int_gauge, Histogram, IntCounter, IntGauge,
};

use crate::types::{PeerMessage, RoutedMessageBody};

pub static PEER_CONNECTIONS_TOTAL: Lazy<near_metrics::Result<IntGauge>> =
    Lazy::new(|| try_create_int_gauge("near_peer_connections_total", "Number of connected peers"));
pub static PEER_DATA_RECEIVED_BYTES: Lazy<near_metrics::Result<IntCounter>> = Lazy::new(|| {
    try_create_int_counter("near_peer_data_received_bytes", "Total data received from peers")
});
pub static PEER_MESSAGE_RECEIVED_TOTAL: Lazy<near_metrics::Result<IntCounter>> = Lazy::new(|| {
    try_create_int_counter(
        "near_peer_message_received_total",
        "Number of messages received from peers",
    )
});
pub static PEER_CLIENT_MESSAGE_RECEIVED_TOTAL: Lazy<near_metrics::Result<IntCounter>> =
    Lazy::new(|| {
        try_create_int_counter(
            "near_peer_client_message_received_total",
            "Number of messages for client received from peers",
        )
    });
pub static PEER_BLOCK_RECEIVED_TOTAL: Lazy<near_metrics::Result<IntCounter>> = Lazy::new(|| {
    try_create_int_counter("near_peer_block_received_total", "Number of blocks received by peers")
});
pub static PEER_TRANSACTION_RECEIVED_TOTAL: Lazy<near_metrics::Result<IntCounter>> =
    Lazy::new(|| {
        try_create_int_counter(
            "near_peer_transaction_received_total",
            "Number of transactions received by peers",
        )
    });

// Routing table metrics
pub static ROUTING_TABLE_RECALCULATIONS: Lazy<near_metrics::Result<IntCounter>> = Lazy::new(|| {
    try_create_int_counter(
        "near_routing_table_recalculations_total",
        "Number of times routing table have been recalculated from scratch",
    )
});
pub static ROUTING_TABLE_RECALCULATION_HISTOGRAM: Lazy<near_metrics::Result<Histogram>> =
    Lazy::new(|| {
        try_create_histogram(
            "near_routing_table_recalculation_seconds",
            "Time spent recalculating routing table",
        )
    });
pub static EDGE_UPDATES: Lazy<near_metrics::Result<IntCounter>> =
    Lazy::new(|| try_create_int_counter("near_edge_updates", "Unique edge updates"));
pub static EDGE_ACTIVE: Lazy<near_metrics::Result<IntGauge>> =
    Lazy::new(|| try_create_int_gauge("near_edge_active", "Total edges active between peers"));
pub static PEER_REACHABLE: Lazy<near_metrics::Result<IntGauge>> = Lazy::new(|| {
    try_create_int_gauge(
        "near_peer_reachable",
        "Total peers such that there is a path potentially through other peers",
    )
});
pub static DROP_MESSAGE_UNKNOWN_ACCOUNT: Lazy<near_metrics::Result<IntCounter>> = Lazy::new(|| {
    try_create_int_counter(
        "near_drop_message_unknown_account",
        "Total messages dropped because target account is not known",
    )
});
pub static RECEIVED_INFO_ABOUT_ITSELF: Lazy<near_metrics::Result<IntCounter>> = Lazy::new(|| {
    try_create_int_counter(
        "received_info_about_itself",
        "Number of times a peer tried to connect to itself",
    )
});
pub static DROPPED_MESSAGES_COUNT: Lazy<near_metrics::Result<IntCounter>> = Lazy::new(|| {
    near_metrics::try_create_int_counter(
        "near_dropped_messages_count",
        "Total count of messages which were dropped, because write buffer was full",
    )
});

#[derive(Clone)]
pub struct NetworkMetrics {
    pub peer_messages: HashMap<String, Option<IntCounter>>,
}

impl NetworkMetrics {
    pub fn new() -> Self {
        let mut peer_messages = HashMap::new();

        let variants = PeerMessage::VARIANTS
            .into_iter()
            .filter(|&name| *name != "Routed")
            .chain(RoutedMessageBody::VARIANTS.into_iter());

        for name in variants {
            let counter_name = NetworkMetrics::peer_message_total_rx(name.as_ref());
            peer_messages.insert(
                counter_name.clone(),
                try_create_int_counter(counter_name.as_ref(), counter_name.as_ref()).ok(),
            );

            let counter_name = NetworkMetrics::peer_message_bytes_rx(name.as_ref());
            peer_messages.insert(
                counter_name.clone(),
                try_create_int_counter(counter_name.as_ref(), counter_name.as_ref()).ok(),
            );

            let counter_name = NetworkMetrics::peer_message_dropped(name.as_ref());
            peer_messages.insert(
                counter_name.clone(),
                try_create_int_counter(counter_name.as_ref(), counter_name.as_ref()).ok(),
            );
        }

        Self { peer_messages }
    }

    pub fn peer_message_total_rx(message_name: &str) -> String {
        format!("near_{}_total", message_name.to_lowercase())
    }

    pub fn peer_message_bytes_rx(message_name: &str) -> String {
        format!("near_{}_bytes", message_name.to_lowercase())
    }

    pub fn peer_message_dropped(message_name: &str) -> String {
        format!("near_{}_dropped", message_name.to_lowercase())
    }

    pub fn inc(&self, message_name: &str) {
        if let Some(counter) = self.peer_messages.get(message_name) {
            inc_counter_opt(counter.as_ref());
        }
    }

    pub fn inc_by(&self, message_name: &str, value: u64) {
        if let Some(counter) = self.peer_messages.get(message_name) {
            inc_counter_by_opt(counter.as_ref(), value);
        }
    }
}
