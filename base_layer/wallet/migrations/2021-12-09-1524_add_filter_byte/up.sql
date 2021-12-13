--  Copyright 2021. The Tari Project
--
--  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
--  following conditions are met:
--
--  1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
--  disclaimer.
--
--  2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
--  following disclaimer in the documentation and/or other materials provided with the distribution.
--
--  3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
--  products derived from this software without specific prior written permission.
--
--  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
--  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
--  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
--  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
--  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
--  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
--  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

-- This migration is part of a testnet reset and should not be used on db's with existing old data in them
-- thus this migration does not accommodate db's with existing rows.

PRAGMA foreign_keys=OFF;
DROP TABLE outputs;
CREATE TABLE outputs (
  id                                         INTEGER           NOT NULL PRIMARY KEY, --auto inc,
  commitment                                 BLOB              NULL,
  spending_key                               BLOB              NOT NULL,
  value                                      BIGINT            NOT NULL,
  flags                                      INTEGER           NOT NULL,
  maturity                                   BIGINT            NOT NULL,
  filter_byte                                INTEGER           NOT NULL,
  status                                     INTEGER           NOT NULL,
  hash                                       BLOB              NULL,
  script                                     BLOB              NOT NULL,
  input_data                                 BLOB              NOT NULL,
  script_private_key                         BLOB              NOT NULL,
  script_lock_height                         UNSIGNED BIGINT   NOT NULL DEFAULT 0,
  sender_offset_public_key                   BLOB              NOT NULL,
  metadata_signature_nonce                   BLOB              NOT NULL,
  metadata_signature_u_key                   BLOB              NOT NULL,
  metadata_signature_v_key                   BLOB              NOT NULL,
  mined_height                               UNSIGNED BIGINT   NULL,
  mined_in_block                             BLOB              NULL,
  mined_mmr_position                         BIGINT            NULL,
  marked_deleted_at_height                   BIGINT,
  marked_deleted_in_block                    BLOB,
  received_in_tx_id                          BIGINT,
  spent_in_tx_id                             BIGINT,
  coinbase_block_height                      UNSIGNED BIGINT   NULL,
  metadata                                   BLOB,
  features_mint_asset_public_key             BLOB,
  features_sidechain_checkpoint_merkle_root  BLOB,
  features_parent_public_key                 BLOB,
  features_unique_id                         BLOB,
  features_sidechain_committee               TEXT,
  features_asset_json                        TEXT NULL,
  spending_priority                          UNSIGNED INTEGER  NOT NULL DEFAULT 500,
  CONSTRAINT unique_commitment UNIQUE (commitment)
);
PRAGMA foreign_keys=ON;
