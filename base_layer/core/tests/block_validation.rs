// Copyright 2019. The Tari Project
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
// following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
// disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
// following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
// products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
// USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use tari_core::{
    chain_storage::{BlockAddResult, BlockchainDatabase, BlockchainDatabaseConfig, Validators},
    consensus::{ConsensusManagerBuilder, Network},
    test_helpers::blockchain::create_test_db,
    transactions::types::CryptoFactories,
    validation::block_validators::{FullConsensusValidator, StatelessBlockValidator},
};

mod helpers;

#[test]
fn test_genesis_block() {
    let factories = CryptoFactories::default();
    let network = Network::Ridcully;
    let rules = ConsensusManagerBuilder::new(network).build();
    let backend = create_test_db();
    let validators = Validators::new(
        FullConsensusValidator::new(rules.clone()),
        StatelessBlockValidator::new(rules.clone(), factories),
    );
    let db = BlockchainDatabase::new(backend, &rules, validators, BlockchainDatabaseConfig::default(), false).unwrap();
    let block = rules.get_genesis_block();
    let result = db.add_block(block.into()).unwrap();
    assert_eq!(result, BlockAddResult::BlockExists);
}
