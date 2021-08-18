//  Copyright 2021, The Tari Project
//
//  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
//  following conditions are met:
//
//  1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
//  disclaimer.
//
//  2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
//  following disclaimer in the documentation and/or other materials provided with the distribution.
//
//  3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
//  products derived from this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
//  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
//  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
//  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use crate::{
    base_node_service::{
        handle::{BaseNodeEvent, BaseNodeEventSender},
        service::BaseNodeState,
    },
    connectivity_service::WalletConnectivityHandle,
    error::WalletStorageError,
    storage::database::{WalletBackend, WalletDatabase},
};
use chrono::Utc;
use log::*;
use std::{convert::TryFrom, sync::Arc, time::Duration};
use tari_common_types::chain_metadata::ChainMetadata;
use tari_comms::protocol::rpc::RpcError;
use tokio::{sync::RwLock, time};

const LOG_TARGET: &str = "wallet::base_node_service::chain_metadata_monitor";

pub struct BaseNodeMonitor<T> {
    interval: Duration,
    state: Arc<RwLock<BaseNodeState>>,
    db: WalletDatabase<T>,
    wallet_connectivity: WalletConnectivityHandle,
    event_publisher: BaseNodeEventSender,
}

impl<T: WalletBackend + 'static> BaseNodeMonitor<T> {
    pub fn new(
        interval: Duration,
        state: Arc<RwLock<BaseNodeState>>,
        db: WalletDatabase<T>,
        wallet_connectivity: WalletConnectivityHandle,
        event_publisher: BaseNodeEventSender,
    ) -> Self {
        Self {
            interval,
            state,
            db,
            wallet_connectivity,
            event_publisher,
        }
    }

    pub async fn run(mut self) {
        loop {
            trace!(target: LOG_TARGET, "Beginning new base node monitoring round");
            match self.monitor_node().await {
                Ok(_) => continue,
                Err(BaseNodeMonitorError::NodeShuttingDown) => {
                    debug!(
                        target: LOG_TARGET,
                        "Wallet Base Node Service chain metadata task shutting down because the shutdown signal was \
                         received"
                    );
                    break;
                },
                Err(e @ BaseNodeMonitorError::RpcFailed(_)) => {
                    warn!(target: LOG_TARGET, "Connectivity failure to base node: {}", e);
                    // debug!(target: LOG_TARGET, "Reconnect current base node peer...");
                    // Disconnecting and re-setting the base node peer would revive a stale peer connection - most
                    // the client can do. As the wallet's base node monitor service runs in a slow loop, it will
                    // assist other services that are dependent on the same base node peer connection; if one service
                    // suffers due to a bad/stale peer connection all services suffer.
                    // self.reconnect_current_base_node_peer().await;
                    // time::sleep(self.interval).await;
                    continue;
                },
                Err(e @ BaseNodeMonitorError::InvalidBaseNodeResponse(_)) |
                Err(e @ BaseNodeMonitorError::WalletStorageError(_)) => {
                    error!(target: LOG_TARGET, "{}", e);
                    continue;
                },
            }
        }
        debug!(
            target: LOG_TARGET,
            "Base Node Service Monitor shutting down because it received the shutdown signal"
        );
    }

    // async fn reconnect_current_base_node_peer(&mut self) {
    //     if let Some(peer) = self.wallet_connectivity.get_current_base_node_peer() {
    //         self.wallet_connectivity.disconnect_base_node(peer.clone()).await;
    //         let _ = self.wallet_connectivity.set_base_node(peer).await;
    //     };
    // }

    async fn monitor_node(&mut self) -> Result<(), BaseNodeMonitorError> {
        loop {
            let mut client = self
                .wallet_connectivity
                .obtain_base_node_wallet_rpc_client()
                .await
                .ok_or(BaseNodeMonitorError::NodeShuttingDown)?;

            let base_node_id = match self.wallet_connectivity.get_current_base_node_id() {
                Some(n) => n,
                None => continue,
            };

            let tip_info = client.get_tip_info().await?;

            let chain_metadata = tip_info
                .metadata
                .ok_or_else(|| BaseNodeMonitorError::InvalidBaseNodeResponse("Tip info no metadata".to_string()))
                .and_then(|metadata| {
                    ChainMetadata::try_from(metadata).map_err(BaseNodeMonitorError::InvalidBaseNodeResponse)
                })?;

            let latency = client.ping().await?;
            let is_synced = tip_info.is_synced;
            debug!(
                target: LOG_TARGET,
                "Base node {} Tip: {} ({}) Latency: {} ms",
                base_node_id,
                chain_metadata.height_of_longest_chain(),
                if is_synced { "Synced" } else { "Syncing..." },
                latency.as_millis()
            );

            self.db.set_chain_metadata(chain_metadata.clone()).await?;

            self.map_state(move |_| BaseNodeState {
                chain_metadata: Some(chain_metadata),
                is_synced: Some(is_synced),
                updated: Some(Utc::now().naive_utc()),
                latency: Some(latency),
            })
            .await;

            time::sleep(self.interval).await
        }

        // loop only exits on shutdown/error
        #[allow(unreachable_code)]
        Ok(())
    }

    async fn map_state<F>(&self, transform: F)
    where F: FnOnce(&BaseNodeState) -> BaseNodeState {
        let new_state = {
            let mut lock = self.state.write().await;
            let new_state = transform(&*lock);
            *lock = new_state.clone();
            new_state
        };
        self.publish_event(BaseNodeEvent::BaseNodeStateChanged(new_state));
    }

    fn publish_event(&self, event: BaseNodeEvent) {
        let _ = self.event_publisher.send(Arc::new(event));
    }
}

#[derive(thiserror::Error, Debug)]
enum BaseNodeMonitorError {
    #[error("Node is shutting down")]
    NodeShuttingDown,
    #[error("Rpc error: {0}")]
    RpcFailed(#[from] RpcError),
    #[error("Invalid base node response: {0}")]
    InvalidBaseNodeResponse(String),
    #[error("Wallet storage error: {0}")]
    WalletStorageError(#[from] WalletStorageError),
}
