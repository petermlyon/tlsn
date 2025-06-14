//! Computation of HMAC-SHA256.
//!
//! HMAC-SHA256 is defined as
//!
//! HMAC(m) = H((key' xor opad) || H((key' xor ipad) || m))
//!
//! * H     - SHA256 hash function
//! * key'  - key padded with zero bytes to 64 bytes (we do not support longer
//!   keys)
//! * opad  - 64 bytes of 0x5c
//! * ipad  - 64 bytes of 0x36
//! * m     - message
//!
//! This implementation computes HMAC-SHA256 using intermediate results
//! `outer_partial` and `inner_local`. Then HMAC(m) = H(outer_partial ||
//! inner_local)
//!
//! * `outer_partial`   - key' xor opad
//! * `inner_local`     - H((key' xor ipad) || m)

use mpz_hash::sha256::Sha256;
use mpz_vm_core::{
    memory::{
        binary::{Binary, U8},
        Array,
    },
    Vm,
};

use crate::PrfError;

pub(crate) const IPAD: [u8; 64] = [0x36; 64];
pub(crate) const OPAD: [u8; 64] = [0x5c; 64];

/// Computes HMAC-SHA256
///
/// # Arguments
///
/// * `vm` - The virtual machine.
/// * `outer_partial` - (key' xor opad)
/// * `inner_local` - H((key' xor ipad) || m)
pub(crate) fn hmac_sha256(
    vm: &mut dyn Vm<Binary>,
    mut outer_partial: Sha256,
    inner_local: Array<U8, 32>,
) -> Result<Array<U8, 32>, PrfError> {
    outer_partial.update(&inner_local.into());
    outer_partial.compress(vm)?;
    outer_partial.finalize(vm).map_err(PrfError::from)
}

#[cfg(test)]
mod tests {
    use crate::{
        hmac::hmac_sha256,
        sha256, state_to_bytes,
        test_utils::{compute_inner_local, compute_outer_partial, mock_vm},
    };
    use mpz_common::context::test_st_context;
    use mpz_hash::sha256::Sha256;
    use mpz_vm_core::{
        memory::{
            binary::{U32, U8},
            Array, MemoryExt, ViewExt,
        },
        Execute,
    };

    #[test]
    fn test_hmac_reference() {
        let (inputs, references) = test_fixtures();

        for (input, &reference) in inputs.iter().zip(references.iter()) {
            let outer_partial = compute_outer_partial(input.0.clone());
            let inner_local = compute_inner_local(input.0.clone(), &input.1);

            let hmac = sha256(outer_partial, 64, &state_to_bytes(inner_local));

            assert_eq!(state_to_bytes(hmac), reference);
        }
    }

    #[tokio::test]
    async fn test_hmac_circuit() {
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut leader, mut follower) = mock_vm();

        let (inputs, references) = test_fixtures();
        for (input, &reference) in inputs.iter().zip(references.iter()) {
            let outer_partial = compute_outer_partial(input.0.clone());
            let inner_local = compute_inner_local(input.0.clone(), &input.1);

            let outer_partial_leader: Array<U32, 8> = leader.alloc().unwrap();
            leader.mark_public(outer_partial_leader).unwrap();
            leader.assign(outer_partial_leader, outer_partial).unwrap();
            leader.commit(outer_partial_leader).unwrap();

            let inner_local_leader: Array<U8, 32> = leader.alloc().unwrap();
            leader.mark_public(inner_local_leader).unwrap();
            leader
                .assign(inner_local_leader, state_to_bytes(inner_local))
                .unwrap();
            leader.commit(inner_local_leader).unwrap();

            let hmac_leader = hmac_sha256(
                &mut leader,
                Sha256::new_from_state(outer_partial_leader, 1),
                inner_local_leader,
            )
            .unwrap();
            let hmac_leader = leader.decode(hmac_leader).unwrap();

            let outer_partial_follower: Array<U32, 8> = follower.alloc().unwrap();
            follower.mark_public(outer_partial_follower).unwrap();
            follower
                .assign(outer_partial_follower, outer_partial)
                .unwrap();
            follower.commit(outer_partial_follower).unwrap();

            let inner_local_follower: Array<U8, 32> = follower.alloc().unwrap();
            follower.mark_public(inner_local_follower).unwrap();
            follower
                .assign(inner_local_follower, state_to_bytes(inner_local))
                .unwrap();
            follower.commit(inner_local_follower).unwrap();

            let hmac_follower = hmac_sha256(
                &mut follower,
                Sha256::new_from_state(outer_partial_follower, 1),
                inner_local_follower,
            )
            .unwrap();
            let hmac_follower = follower.decode(hmac_follower).unwrap();

            let (hmac_leader, hmac_follower) = tokio::try_join!(
                async {
                    leader.execute_all(&mut ctx_a).await.unwrap();
                    hmac_leader.await
                },
                async {
                    follower.execute_all(&mut ctx_b).await.unwrap();
                    hmac_follower.await
                }
            )
            .unwrap();

            assert_eq!(hmac_leader, hmac_follower);
            assert_eq!(hmac_leader, reference);
        }
    }

    #[allow(clippy::type_complexity)]
    fn test_fixtures() -> (Vec<(Vec<u8>, Vec<u8>)>, Vec<[u8; 32]>) {
        let test_vectors: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (
                hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
                hex::decode("4869205468657265").unwrap(),
            ),
            (
                hex::decode("4a656665").unwrap(),
                hex::decode("7768617420646f2079612077616e7420666f72206e6f7468696e673f").unwrap(),
            ),
        ];
        let expected: Vec<[u8; 32]> = vec![
            hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
                .unwrap()
                .try_into()
                .unwrap(),
        ];

        (test_vectors, expected)
    }
}
