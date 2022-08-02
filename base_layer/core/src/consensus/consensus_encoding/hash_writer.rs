//  Copyright 2022. The Tari Project
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

use std::io::Write;

use digest::{consts::U32, Digest, FixedOutput, Update};
use tari_crypto::hash::blake2::Blake256;

use crate::consensus::ConsensusEncoding;

#[derive(Clone)]
pub struct ConsensusHashWriter<H> {
    digest: H,
}

impl<H: Digest> ConsensusHashWriter<H> {
    pub fn new(digest: H) -> Self {
        Self { digest }
    }
}

impl<H> ConsensusHashWriter<H>
where H: FixedOutput<OutputSize = U32> + Update
{
    pub fn finalize(self) -> [u8; 32] {
        self.digest.finalize_fixed().into()
    }

    pub fn update_consensus_encode<T: ConsensusEncoding>(&mut self, data: &T) {
        // UNWRAP: ConsensusEncode MUST only error if the writer errors, HashWriter::write is infallible
        data.consensus_encode(self)
            .expect("Incorrect implementation of ConsensusEncoding encountered. Implementations MUST be infallible.");
    }

    pub fn chain<T: ConsensusEncoding>(mut self, data: &T) -> Self {
        self.update_consensus_encode(data);
        self
    }

    pub fn into_digest(self) -> H {
        self.digest
    }
}

impl<H: Update> Write for ConsensusHashWriter<H> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.digest.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Default for ConsensusHashWriter<Blake256> {
    fn default() -> Self {
        // Note: Do not use 'DomainSeparatedHasher' here as 'H.chain(a).chain(b).finalize() != H.chain(a||b).finalize()'
        // A custom implementation with heap allocation will be inefficient.
        ConsensusHashWriter::new(
            Blake256::with_params(&[], b"tari.base_layer", b"core.consensus")
                .expect("Correct assignment will not fail"),
        )
    }
}

#[cfg(test)]
mod test {
    use rand::{rngs::OsRng, RngCore};
    use tari_crypto::hash::blake2::Blake256;

    use super::*;

    #[test]
    fn it_updates_the_digest_state() {
        let mut writer = ConsensusHashWriter::default();
        let mut data = [0u8; 1024];
        OsRng.fill_bytes(&mut data);

        // Even if data is streamed in chunks, the preimage and therefore the resulting hash are the same
        writer.write_all(&data[0..256]).unwrap();
        writer.write_all(&data[256..500]).unwrap();
        writer.write_all(&data[500..1024]).unwrap();
        let hash_of_chunks = writer.finalize();
        let hasher = Blake256::with_params(&[], b"tari.base_layer", b"core.consensus")
            .expect("Correct assignment will not fail");
        let hash_of_zeros: [u8; 32] = Update::chain(hasher, [0u8; 1024]).finalize_fixed().into();
        assert_ne!(hash_of_chunks, hash_of_zeros);

        let mut writer = ConsensusHashWriter::default();
        writer.write_all(&data).unwrap();
        assert_eq!(writer.finalize(), hash_of_chunks);

        // Testing no data in the buffer
        let mut writer = ConsensusHashWriter::default();
        writer.write_all(&[]).unwrap();
        writer.write_all(&[]).unwrap();
        writer.write_all(&[]).unwrap();
        let hasher = Blake256::with_params(&[], b"tari.base_layer", b"core.consensus")
            .expect("Correct assignment will not fail");
        let hash_of_empty: [u8; 32] = Update::chain(hasher, &[]).finalize_fixed().into();
        assert_eq!(writer.finalize(), hash_of_empty);
    }

    #[test]
    fn it_returns_the_correct_size() {
        let mut writer = ConsensusHashWriter::default();
        let data = [0u8; 1024];
        let size = writer.write(&data).unwrap();
        assert_eq!(size, data.len());
    }
}
