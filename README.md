# TAPS_TT_P — Parallel TAPS_TT

A copy of `TAPS_TT` (threshold signatures with distributed tracers) in which
the **tracing step** and the tracer's **accountability-proof verification**
are parallelized with [rayon](https://crates.io/crates/rayon). The protocol,
the proof statements, the Fiat–Shamir transcripts and the existing public API
are unchanged. The original `TAPS_TT` stays the sequential baseline.

## What runs in parallel

| Step | Function | Strategy |
|---|---|---|
| ShareDec (`v0_i^{sk_e}` + Chaum–Pedersen proof per signer) | `dkg::partial_decrypt` | ordered `par_iter().map().unzip()` over the signers |
| Share verification (all partials × all proofs) | `dkg::verify_partial_decryptions` (new batch API) | the (tracer, proof) pairs are **flattened** into one work list and checked in parallel |
| Rec (`g^{b_i} = v1_i / Π_k v'_{ki}^{λ_k}`) | `dkg::combine_partial_decryptions` | Lagrange coefficients sequential; bits in parallel (ordered collect) |
| `g^z` check `R · Π pk_i^c` | `schnorr_signature` | parallel map + parallel reduction |
| VerifyProof: S1, S4c | `Proofs::verify_s1`, `Proofs::verify_s4c` | α powers precomputed sequentially, parallel map + `try_reduce` |
| VerifyProof: S4ai, S4bi | `Proofs::verify_s4ai`, `Proofs::verify_s4bi` | parallel per-bit checks; the first failure is reported in index order, like the sequential loop |

## Algorithmic improvement: verification keys

To check a partial decryption, a tracer first recomputes the sender's
verification key `vk_k` from the DKG commitments. The original formula
evaluates every qualified dealer's polynomial separately:

  `vk_k = Π_{w∈QUAL} Π_l A_{wl}^{k^l}`

That costs `|QUAL|·t_e` scalar multiplications per key, or 85,000 per tracer
for j = 50. TAPS_TT_P first aggregates the commitments once,
`C_l = Π_{w∈QUAL} A_{wl}`, which needs only point additions
(`dkg::aggregate_commitments`). It then evaluates

  `vk_k = Π_l C_l^{k^l}`

with `t_e` multiplications per key (`dkg::verification_keys`). The keys are
identical, and `tests/verification_keys.rs` checks them against the
per-dealer formula and against `g^{sk_{e_k}}`. The protocol is unchanged.

This improvement is independent of the thread count, so it also speeds up the
multi-process benchmark, where the co-located tracers already use every core.
When comparing against TAPS_TT, remember that the gain comes from this
algorithm *plus* parallelism.

## What stays sequential

Fiat–Shamir hashes (`c`, `alpha`, `beta`, Chaum–Pedersen
challenges), Lagrange coefficients, signer operations, the distributed key
generation, the combiner, and cheap scalar arithmetic.

Group products are reduced in parallel through `group::Gt`, which can
represent the identity. Because the group is commutative, the result does not
depend on the reduction order.

`verify_partial_decryption` (for a single partial) keeps its signature and
behaviour; it now delegates to the batch function.

## Thread count

rayon uses one thread per logical core by default. Set `RAYON_NUM_THREADS` to
override this, e.g. in PowerShell:

```powershell
$env:RAYON_NUM_THREADS = 4
```

## Tests

```powershell
cargo test --release
```

`tests/parallel_tracing.rs` signs end to end for several `(n, j)` pairs
(`t = ⌊n/2⌋+1`, `t_e = ⌊2j/3⌋+1`) and checks the following:

- the traced quorum is exactly the signing quorum `C`;
- verification still accepts valid signatures;
- the results are identical with 1, 2, 4 and 8 threads;
- the batched verifier agrees with a sequential reference, including on
  tampered shares;
- tampered proofs are still rejected.
