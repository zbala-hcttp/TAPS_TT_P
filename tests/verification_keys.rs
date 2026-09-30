//! The aggregated-commitment computation of the tracers' verification keys
//! must give exactly the keys of the original per-dealer formula
//! `vk_k = prod_{w in QUAL} prod_l A_{wl}^{k^l}`, and the tracers' own
//! `vk_k = g^{sk_{e_k}}`.

use std::collections::BTreeMap;
use taps_tt_p::protocol::dkg::{self, DkgBroadcast, DkgParticipant, TracerKeyShare};
use taps_tt_p::protocol::field::Fq;
use taps_tt_p::protocol::group::Gt;

/// In-memory DKG that keeps the round-1 broadcasts.
fn dkg_with_broadcasts(
    te: usize,
    n3: usize,
) -> (Vec<TracerKeyShare>, BTreeMap<usize, DkgBroadcast>, Vec<usize>) {
    let participants: Vec<DkgParticipant> = (1..=n3)
        .map(|index| DkgParticipant::new(index, te, n3).expect("valid parameters"))
        .collect();
    let broadcasts: BTreeMap<usize, DkgBroadcast> = participants
        .iter()
        .map(|p| (p.index, p.broadcast.clone()))
        .collect();
    let qual: Vec<usize> = (1..=n3).collect();
    let shares: Vec<TracerKeyShare> = participants
        .iter()
        .map(|receiver| {
            let received: BTreeMap<usize, Fq> = participants
                .iter()
                .map(|dealer| (dealer.index, dealer.share_for(receiver.index)))
                .collect();
            receiver.finalize(&qual, &broadcasts, &received).expect("finalize")
        })
        .collect();
    (shares, broadcasts, qual)
}

/// The original formula: evaluate every dealer's polynomial separately.
fn per_dealer_verification_key(
    qual: &[usize],
    broadcasts: &BTreeMap<usize, DkgBroadcast>,
    k: usize,
) -> Gt {
    qual.iter().fold(Gt::identity(), |acc: Gt, w: &usize| {
        acc.add(&dkg::feldman_evaluate(&broadcasts[w].commitments, k))
    })
}

#[test]
fn aggregated_keys_equal_the_per_dealer_formula_and_the_real_keys() {
    for &n3 in &[1usize, 2, 3, 5, 8, 13] {
        let te: usize = (2 * n3) / 3 + 1;
        let (shares, broadcasts, qual) = dkg_with_broadcasts(te, n3);
        let indices: Vec<usize> = (1..=n3).collect();

        let batch: Vec<Gt> = dkg::verification_keys(&qual, &broadcasts, &indices).expect("keys");
        for (position, &k) in indices.iter().enumerate() {
            let reference: Gt = per_dealer_verification_key(&qual, &broadcasts, k);
            assert_eq!(batch[position], reference, "n3={} k={}", n3, k);
            assert_eq!(
                dkg::verification_key(&qual, &broadcasts, k).expect("key"),
                reference,
                "n3={} k={}",
                n3,
                k
            );
            assert_eq!(batch[position], shares[k - 1].vk, "vk_k != g^sk_e_k for n3={} k={}", n3, k);
        }
    }
}

#[test]
fn keys_follow_the_requested_order_and_repeats() {
    let (shares, broadcasts, qual) = dkg_with_broadcasts(3, 4);
    let indices: Vec<usize> = vec![4, 1, 3, 1];
    let keys: Vec<Gt> = dkg::verification_keys(&qual, &broadcasts, &indices).expect("keys");
    let expected: Vec<Gt> = indices.iter().map(|&k| shares[k - 1].vk).collect();
    assert_eq!(keys, expected);
}

#[test]
fn a_subset_qual_uses_only_its_dealers() {
    let (_, broadcasts, _) = dkg_with_broadcasts(3, 5);
    let qual: Vec<usize> = vec![1, 3, 4];
    for k in 1..=5 {
        assert_eq!(
            dkg::verification_key(&qual, &broadcasts, k).expect("key"),
            per_dealer_verification_key(&qual, &broadcasts, k)
        );
    }
}

#[test]
fn missing_or_inconsistent_broadcasts_are_rejected() {
    let (_, mut broadcasts, qual) = dkg_with_broadcasts(2, 3);
    let mut short: DkgBroadcast = broadcasts[&2].clone();
    short.commitments.pop();
    broadcasts.insert(2, short);
    assert!(dkg::aggregate_commitments(&qual, &broadcasts).is_err());

    broadcasts.remove(&2);
    assert!(dkg::verification_keys(&qual, &broadcasts, &[1]).is_err());
}
