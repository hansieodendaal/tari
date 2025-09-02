//  Copyright 2022, The Tari Project
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

use std::{
    collections::{BTreeMap, HashMap},
    fs,
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    process,
    time::Duration,
};

use anyhow::Error;
use async_trait::async_trait;
use clap::Parser;
use futures::StreamExt;
use minotari_app_utilities::utilities::UniPublicKey;
use tari_common_types::types::CompressedPublicKey;
use tari_comms::{
    peer_manager::{NodeId, Peer},
    protocol::rpc::RpcClient,
    CommsNode,
};
use tari_core::{base_node::sync::rpc, blocks::BlockHeaderAccumulatedData, proto::base_node::AccumulatedDataRequest};
use tari_p2p::services::liveness::LivenessEvent;
use tari_utilities::hex::Hex;
use tokio::time::timeout;

use super::{CommandContext, HandleCommand};

const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const PING_TIMEOUT: Duration = Duration::from_secs(5);
const LAST_HEADER_HEIGHT_DEFAULT: u64 = 250;

/// Adds a peer
#[derive(Debug, Parser)]
pub struct ArgsCheckChainConsistency {
    /// The optional public keys of the peers to be tested; if none seed peers will be used
    public_keys: Vec<UniPublicKey>,
    /// Auto exit the base node after test
    exit: Option<bool>,
    /// Write the responsiveness result to file - results will be written to
    /// 'peer_liveness_test.log'
    output_to_file: Option<bool>,
    /// Start with a new log file
    refresh_file: Option<bool>,
    /// Optional output directory (otherwise current directory will be used)
    output_directory: Option<PathBuf>,
    /// Optional last header height to query; default is 250 headers from the tip
    last_header_height: Option<u64>,
}

#[async_trait]
impl HandleCommand<ArgsCheckChainConsistency> for CommandContext {
    async fn handle_command(&mut self, args: ArgsCheckChainConsistency) -> Result<(), Error> {
        println!("\nChecking chain consistency...\n");
        let peers = get_peer_info(&self.comms, &args).await?;
        if peers.is_empty() {
            println!("No peers provided, and no seed peers found in the peer manager, stopping test");
            return Ok(());
        }

        let blockchain_db = &self.blockchain_db;

        // Collect local chain headers corresponding to remote accumulated data to be requested
        let metadata = blockchain_db.get_chain_metadata().await?;
        let last_header_height = args.last_header_height.unwrap_or(LAST_HEADER_HEIGHT_DEFAULT);
        let header_heights = collect_header_heights(metadata.best_block_height(), last_header_height);
        let mut local_chain_headers = Vec::with_capacity(header_heights.len());
        for h in header_heights.clone() {
            let header = blockchain_db.fetch_chain_headers(h..=h).await?;
            local_chain_headers.push(header[0].clone());
        }

        // Use comms RPC to retrieve accumulated data from peers
        let mut peer_response_map: HashMap<NodeId, Vec<(u64, BlockHeaderAccumulatedData)>> = HashMap::new();
        let connectivity = self.comms.connectivity();
        for peer in peers {
            match timeout(DIAL_TIMEOUT, connectivity.dial_peer(peer.node_id.clone())).await {
                Ok(Ok(mut conn)) => {
                    let mut liveness = self.liveness.clone();
                    let mut liveness_events = liveness.get_event_stream();
                    let mut peer_available = false;
                    let mut ping_error = false;
                    match timeout(PING_TIMEOUT, liveness.send_ping(peer.node_id.clone())).await {
                        Ok(Ok(nonce)) => {
                            for _ in 0..5 {
                                match timeout(PING_TIMEOUT, liveness_events.recv()).await {
                                    Ok(Ok(event)) => {
                                        if let LivenessEvent::ReceivedPong(pong) = &*event {
                                            if pong.node_id == peer.node_id && pong.nonce == nonce {
                                                println!(
                                                    "🏓️ Pong: peer {} responded with nonce {}, round-trip-time {:.2?}!",
                                                    pong.node_id,
                                                    pong.nonce,
                                                    pong.latency.unwrap_or_default()
                                                );
                                                peer_available = true;
                                                break;
                                            }
                                        }
                                    },
                                    Ok(Err(e)) => {
                                        println!(
                                            "🏓 Ping peer ({}, {}) liveness events error: {}",
                                            peer.node_id, peer.public_key, e
                                        );
                                        ping_error = true;
                                        break;
                                    },
                                    Err(_) => {
                                        println!(
                                            "🏓 Ping peer ({}, {}) did not respond with liveness events in time",
                                            peer.node_id, peer.public_key
                                        );
                                        break;
                                    },
                                }
                            }
                            if ping_error {
                                continue;
                            }
                            if peer_available {
                                let config = RpcClient::builder()
                                    .with_deadline(Duration::from_secs(10))
                                    .with_deadline_grace_period(Duration::from_secs(5));
                                let mut client = match conn
                                    .connect_rpc_using_builder::<rpc::BaseNodeSyncRpcClient>(config)
                                    .await
                                {
                                    Ok(val) => val,
                                    Err(e) => {
                                        println!(
                                            "🏓 RPC peer ({}, {}) connection error: {}",
                                            peer.node_id, peer.public_key, e
                                        );
                                        continue;
                                    },
                                };
                                let request = AccumulatedDataRequest {
                                    header_heights: header_heights.clone(),
                                };
                                let mut accumulated_data_stream = match client.get_accumulated_data(request).await {
                                    Ok(val) => val,
                                    Err(e) => {
                                        println!(
                                            "🏓 RPC peer ({}, {}) get stream error: {}",
                                            peer.node_id, peer.public_key, e
                                        );
                                        continue;
                                    },
                                };
                                let mut peer_responses = Vec::with_capacity(header_heights.len());
                                let mut header_heights_iter = header_heights.iter();
                                while let Some(rpc_message) = accumulated_data_stream.next().await {
                                    match rpc_message {
                                        Ok(proto_accum_data) => {
                                            match BlockHeaderAccumulatedData::try_from(proto_accum_data) {
                                                Ok(accum_data) => {
                                                    if let Some(height) = header_heights_iter.next() {
                                                        peer_responses.push((*height, accum_data))
                                                    } else {
                                                        println!(
                                                            "🏓 Out of bounds value streamed from ({}, {})",
                                                            peer.node_id, peer.public_key
                                                        );
                                                        continue;
                                                    };
                                                },
                                                Err(e) => {
                                                    println!(
                                                        "🏓 Accumulated data conversion error for ({}, {}): {}",
                                                        peer.node_id, peer.public_key, e
                                                    );
                                                    continue;
                                                },
                                            }
                                        },
                                        Err(e) => {
                                            println!(
                                                "🏓 RPC peer ({}, {}) stream message error: {}",
                                                peer.node_id, peer.public_key, e
                                            );
                                            continue;
                                        },
                                    }
                                }
                                if header_heights.len() != peer_responses.len() {
                                    println!(
                                        "❌ Peer ({}, {}) did not provide all the requested accumulated data sets, \
                                         ignoring their responses",
                                        peer.node_id, peer.public_key
                                    );
                                    continue;
                                }
                                peer_response_map.insert(peer.node_id.clone(), peer_responses);
                            }
                        },
                        Ok(Err(e)) => {
                            println!(
                                "🏓 Ping peer ({}, {}) has an error: {}",
                                peer.node_id, peer.public_key, e
                            );
                            continue;
                        },
                        Err(_) => {
                            println!(
                                "🏓 Ping peer ({}, {}) did not respond in time",
                                peer.node_id, peer.public_key
                            );
                            continue;
                        },
                    }
                },
                Ok(Err(e)) => {
                    println!(
                        "🏓 Dial peer ({}, {}) has an error: {}",
                        peer.node_id, peer.public_key, e
                    );
                    continue;
                },
                Err(_) => {
                    println!(
                        "🏓 Dial peer ({}, {}) did not respond in time",
                        peer.node_id, peer.public_key
                    );
                    continue;
                },
            }
        }

        // Process results
        let local_accumulated_data = header_heights
            .iter()
            .zip(local_chain_headers.iter())
            .map(|(height, header)| (*height, header.accumulated_data().clone()))
            .collect::<Vec<_>>();
        let conformity_table = calculate_conformity_by_height(&local_accumulated_data, &peer_response_map);

        print_results_to_console_by_height(&conformity_table);

        if let Some(true) = args.output_to_file {
            print_by_height_to_file(args.output_directory, args.refresh_file, &conformity_table).await;
        }

        if let Some(true) = args.exit {
            println!("The liveness test is complete and base node will now exit\n");
            self.shutdown.trigger();
            tokio::time::sleep(Duration::from_secs(1)).await;
            process::exit(0)
        }

        Ok(())
    }
}

async fn get_peer_info(comms: &CommsNode, args: &ArgsCheckChainConsistency) -> Result<Vec<Peer>, Error> {
    let peer_manager = comms.peer_manager();

    let mut peer_public_keys = args
        .public_keys
        .iter()
        .map(|pk| CompressedPublicKey::from(pk.clone()))
        .collect::<Vec<_>>();
    if peer_public_keys
        .iter()
        .any(|pk| comms.node_identity().public_key() == pk)
    {
        println!("Local node detected in the list, will be removed as a peer");
        peer_public_keys = peer_public_keys
            .iter()
            .filter(|&pk| comms.node_identity().public_key() != pk)
            .cloned()
            .collect::<Vec<_>>();
    }
    // If no public keys are provided, use the seed peers
    let peers = if peer_public_keys.is_empty() {
        let mut seed_peers = peer_manager.get_seed_peers().await?;
        seed_peers = seed_peers
            .iter()
            .filter(|&pk| comms.node_identity().public_key() != &pk.public_key)
            .cloned()
            .collect::<Vec<_>>();
        if seed_peers.is_empty() {
            return Ok(Vec::new());
        }
        peer_public_keys = seed_peers.iter().map(|p| p.public_key.clone()).collect();
        println!("No peers provided, using {} seed peers", peer_public_keys.len());
        seed_peers
    } else {
        let node_ids = peer_public_keys.iter().map(NodeId::from_public_key).collect::<Vec<_>>();
        peer_manager.get_peers_by_node_ids(&node_ids).await?
    };

    Ok(peers)
}

// Return header heights: every 10_000th header, then every 1000th header, then every 100th header, and lastly the
// header that is 'last_header_height' deep
fn collect_header_heights(best_block_height: u64, last_header_height: u64) -> Vec<u64> {
    let mut heights = Vec::new();
    let mut last_added = 0;

    // Every 10,000th header
    for h in (10_000..=best_block_height).step_by(10_000) {
        if best_block_height - h > last_header_height {
            heights.push(h);
        }
    }
    if let Some(&last) = heights.last() {
        last_added = last;
    }
    // Thereafter, every 1,000th header
    for h in (last_added + 1000..=best_block_height).step_by(1_000) {
        if best_block_height - h > last_header_height {
            heights.push(h);
        }
    }
    if let Some(&last) = heights.last() {
        last_added = last;
    }
    // Thereafter, every 100th header
    for h in (last_added + 100..=best_block_height).step_by(100) {
        if best_block_height - h > last_header_height {
            heights.push(h);
        }
    }
    if let Some(&last) = heights.last() {
        last_added = last;
    }
    // Always add the header 'last_header_height' below the tip, if possible
    if best_block_height > last_header_height {
        let last_height = best_block_height - last_header_height;
        if last_added != last_height {
            heights.push(last_height);
        }
    }

    heights
}

// Helper to extract all entities from BlockHeaderAccumulatedData
fn extract_entities(accum: &BlockHeaderAccumulatedData) -> HashMap<&'static str, String> {
    let mut map = HashMap::new();
    map.insert("hash", accum.hash.to_hex());
    map.insert("total_kernel_offset", format!("{}", accum.total_kernel_offset.reveal()));
    map.insert("achieved_difficulty", format!("{}", accum.achieved_difficulty));
    map.insert(
        "total_accumulated_difficulty",
        format!("{}", accum.total_accumulated_difficulty),
    );
    map.insert(
        "accumulated_monero_randomx_difficulty",
        format!("{}", accum.accumulated_monero_randomx_difficulty),
    );
    map.insert(
        "accumulated_tari_randomx_difficulty",
        format!("{}", accum.accumulated_tari_randomx_difficulty),
    );
    map.insert(
        "accumulated_sha3x_difficulty",
        format!("{}", accum.accumulated_sha3x_difficulty),
    );
    map.insert(
        "accumulated_cuckaroo_difficulty",
        format!("{}", accum.accumulated_cuckaroo_difficulty),
    );
    map.insert("target_difficulty", format!("{}", accum.target_difficulty));
    map
}

fn calculate_conformity_by_height(
    local_accumulated_data: &[(u64, BlockHeaderAccumulatedData)],
    peer_response_map: &HashMap<NodeId, Vec<(u64, BlockHeaderAccumulatedData)>>,
) -> BTreeMap<u64, BTreeMap<&'static str, BTreeMap<String, f64>>> {
    // Stable column order: local first, then peers by NodeId string
    let mut nodes: Vec<(String, Vec<&BlockHeaderAccumulatedData>)> = Vec::new();
    let heights: Vec<u64> = local_accumulated_data.iter().map(|(h, _)| *h).collect();

    nodes.push((
        "local".to_string(),
        local_accumulated_data.iter().map(|(_, d)| d).collect(),
    ));
    let mut peers: Vec<(String, Vec<&BlockHeaderAccumulatedData>)> = peer_response_map
        .iter()
        .map(|(id, v)| (id.to_string(), v.iter().map(|(_, d)| d).collect()))
        .collect();
    peers.sort_by(|a, b| a.0.cmp(&b.0));
    for p in peers {
        nodes.push(p);
    }

    let total_nodes = nodes.len() as f64;

    const ENTITIES: [&str; 9] = [
        "hash",
        "total_kernel_offset",
        "achieved_difficulty",
        "total_accumulated_difficulty",
        "accumulated_monero_randomx_difficulty",
        "accumulated_tari_randomx_difficulty",
        "accumulated_sha3x_difficulty",
        "accumulated_cuckaroo_difficulty",
        "target_difficulty",
    ];

    let mut by_height: BTreeMap<u64, BTreeMap<&'static str, BTreeMap<String, f64>>> = BTreeMap::new();

    for (idx, h) in heights.iter().enumerate() {
        let mut entity_row_map: BTreeMap<&'static str, BTreeMap<String, f64>> = BTreeMap::new();

        for entity in ENTITIES {
            // Count clusters at this height
            let mut value_counts: HashMap<String, usize> = HashMap::new();
            let mut node_vals: Vec<(String, String)> = Vec::with_capacity(nodes.len());
            for (name, vec_ref) in &nodes {
                let v = extract_entities(vec_ref[idx]).get(entity).cloned().unwrap_or_default();
                *value_counts.entry(v.clone()).or_insert(0) += 1;
                node_vals.push((name.clone(), v));
            }

            // Build row: node -> percent
            let mut row: BTreeMap<String, f64> = BTreeMap::new();
            for (name, vkey) in node_vals {
                let cluster = *value_counts.get(&vkey).unwrap_or(&1) as f64;
                row.insert(name, (cluster / total_nodes) * 100.0);
            }
            entity_row_map.insert(entity, row);
        }

        by_height.insert(*h, entity_row_map);
    }

    by_height
}

fn print_results_to_console_by_height(by_height: &BTreeMap<u64, BTreeMap<&'static str, BTreeMap<String, f64>>>) {
    println!();
    for (height, entity_map) in by_height {
        // Header (use the first entity row to get stable column order)
        if let Some(first_row) = entity_map.values().next() {
            println!("Entities(height_{})", height);
            println!("Entity,{}", first_row.keys().cloned().collect::<Vec<_>>().join(","));
            for (entity, peer_map) in entity_map {
                print!("{entity}");
                for key in first_row.keys() {
                    let v = peer_map.get(key).copied().unwrap_or(0.0);
                    print!(",{:.1}%", v);
                }
                println!();
            }
            println!();
        }
    }
}

async fn print_by_height_to_file(
    output_directory: Option<PathBuf>,
    refresh_file: Option<bool>,
    by_height: &BTreeMap<u64, BTreeMap<&'static str, BTreeMap<String, f64>>>,
) {
    use chrono::Local;

    let date_time = Local::now().format("%Y_%m_%d_%H_%M_%S").to_string();
    let file_name = format!("chain_consistency_check_by_height_{}.csv", date_time);
    let file_path = if let Some(path) = output_directory.clone() {
        if let Ok(true) = fs::exists(&path) {
            path.join(&file_name)
        } else if fs::create_dir_all(&path).is_ok() {
            path.join(&file_name)
        } else {
            PathBuf::from(&file_name)
        }
    } else {
        PathBuf::from(&file_name)
    };

    if let Some(true) = refresh_file {
        let _ = fs::remove_file(&file_path);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&file_path)
    {
        let mut out = String::new();

        for (height, entity_map) in by_height {
            if let Some(first_row) = entity_map.values().next() {
                out.push_str(&format!("Entities(height_{})\n", height));
                out.push_str("Entity,");
                out.push_str(&first_row.keys().cloned().collect::<Vec<_>>().join(","));
                out.push('\n');

                for (entity, peer_map) in entity_map {
                    out.push_str(entity);
                    for key in first_row.keys() {
                        let v = peer_map.get(key).copied().unwrap_or(0.0);
                        out.push_str(&format!(",{:.1}%", v));
                    }
                    out.push('\n');
                }
                out.push('\n');
            }
        }

        let _ = file.write_all(out.as_bytes());
        println!("📝 Per-height results written to file: {}", file_path.display());
    } else {
        println!("❌ Could not open per-height output file: {}", file_path.display());
    }
}
