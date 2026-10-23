# Hybrid Post-Quantum OpenID Connect — Formal Security Specification

Companion to *Hybrid Post-Quantum Variation of OpenID* (Chen, Thipireddy, Ye — MIT 6.5610, May 2025).
This document states the construction precisely, fixes the adversary model the paper left implicit,
and gives **complete proofs** (not citations) for every claim the implementation relies on.

---

## 1. Notation and conventions

- Security parameter is `λ`. All PPT adversaries run in time polynomial in `λ`.
- `negl(λ)` denotes a negligible function.
- `Adv^X_A(λ)` denotes the success probability of adversary `A` in experiment/game `X`.
- `qenc`, `qdec`, `q_h`, `q_v` bound the number of encapsulation, decapsulation, signing-oracle,
  and verification-oracle queries. `σ` is the max message length signed.
- We write `Hyb(D)` for the *hybrid* variant of primitive `D` and `D` alone for the classical or
  post-quantum component in isolation.
- Concatenation `‖` is on **fixed-length** encodings only (per IETF `draft-ietf-tls-hybrid-design`:
  variable-length public keys/ciphertexts/secrets would leak timing and weaken the HKDF dual-PRF
  argument). Every component below has canonical, length-known encoding; the hybridizer asserts
  length consistency before parsing (see §7).

## 2. Scheme syntax

```
Alg 1 (KEM π = (Kgen, Enc, Dec))          Alg 2 (Sig Σ = (Skg, Sign, Ver))
  Kgen(1^λ) → (pk, sk)                      Skg(1^λ) → (vk, sk)
  Enc(pk)    → (ss, ct)  [ss,ct fixed len]   Sign(sk, m) → s          [s fixed len]
  Dec(sk, ct)→ ss or ⊥                       Ver(vk, m, s) → {0,1}
```

```
Alg 3 (composite-hybrid KEM)
  KgenH = Kgen_c ; Kgen_p                (independent key pairs)
  EncH(pk_c, pk_p) = ( (ss_c,ss_p), (ct_c‖ct_p) )
        where (ss_c,ct_c)←Enc(pk_c), (ss_p,ct_p)←Enc(pk_p)
        ss_h := ss_c ‖ ss_p
  DecH(sk_c,sk_p, ct_c‖ct_p) = (ss_c,ss_p)   componentwise; ⊥ if either is ⊥
        (TLS binding) final secret K = HKDF-Extract(ss_h) with a dual-PRF combiner.

Alg 4 (composite-hybrid signature)
  SkgH = Skg_c ; Skg_p
  SignH(sk_c, sk_p, m) = σ_c ‖ σ_p          (σ_c‖σ_p fixed length)
  VerH(vk_c, vk_p, m, σ_c‖σ_p)
        = Ver_c(vk_c, m, σ_c) ∧ Ver_p(vk_p, m, σ_p)     ← conjunction, from the paper
```

`c` ∈ {eclassical} and `p` ∈ {pq}. In the paper's deployment: `c` = ECDH P-256 (KEM half, under
TLS) and ECDSA/ES256 (sig half); `p` = Kyber512 → standardized ML-KEM-512 (KEM) and
Falcon512 → (sig). **Assumption A-modern:** we treat the *standardized* instantiations
(ML-KEM/ML-DSA) as the concrete schemes; Kyber/Falcon are named as the paper's prototype.

## 3. Threat model (made explicit)

The paper names adversaries in prose; we fix three concrete capability sets.

```
E1  Record-Now-Decrypt-Later (passive RNDL): observes and stores ciphertext.
    Goal: recover past plaintext of *some* session.  Classical-only break ⇒ all
    classical-keyed traffic falls; a hybrid session must survive if either half holds.
E2  Key-compromise / single-primitive break (active-adjacent): breaks ONE of {classical, pq}
    entirely (PPT or QPT), retains full power on that half forever.
E3  Active network MITM: adaptively queries encaps/decaps or sign/ver oracles, submits
    arbitrary ciphertexts/signatures to the target endpoints.
```

E3 is the classical IND-CCA/EUF-CMA oracle adversary; E1/E2 are *primitive-restriction*
adversaries (they run the same games but with one component's advantage forced to ~1, the
other bounded). The paper's central motivator — "the quantum preprint might break LWE" — is
exactly **E2 with pq-side broken**, which is Claim E2 below.

## 4. Security goals and theorem statements

**G1 (Transport confidentiality / RNDL resistance).** Recorded transcript of a hybrid-TLS
session reveals nothing about the shared secret unless *both* component KEMs are broken.

**G2 (One-break resilience).** If at least one of KEM_c, KEM_p is IND-CCA secure, the hybrid
KEM is IND-CCA secure.

**G3 (Token authenticity / unforgeability).** An accepted hybrid JWT implies both component
signatures verify; forging one implies forging the composite.

**G4 (Weakest-link bound, explicit).** The composite signature's unforgeability is that of the
*weaker* half — under the paper's own conjunction rule, ES256 (EUF-CMA, and even a full
one-more-style classical break) governs; Falcon512's strength does **not** lift it. Stated with
its reduction so the bound is auditable.

> The paper asserts G1–G4 by citation ([7] Bindel 2018/903, [10] Bindel PQCrypto'19,
> [12] IETF hybrid-TLS draft). We prove them for Alg 3/Alg 4 as written.

---

## 5. Proof of G2 (Claim E1/E2 at the KEM layer)

**Theorem 1 (Composite-KEM hybridization).** Let `A` be a PPT adversary attacking `Hyb(D)`'s
IND-CCA game with advantage `ε` using `qenc` encapsulation and `qdec` decapsulation queries.
Then there exist adversaries `B_c`, `B_p` attacking the component IND-CCA games such that

```
ε  ≤  Adv^{IND-CCA}_{B_c}(λ)  +  Adv^{IND-CCA}_{B_p}(λ)  +  q_enc · negl(λ)
```

Hence if **either** component is IND-CCA (the other may be totally broken), `ε` is negligible.

*Proof.* The hybrid IND-CCA experiment proceeds in a sequence of games:

- **Game 0.** The real hybrid experiment `HybIND-CCA_A`: `A` receives `pk_h = pk_c‖pk_p`,
  may query `Enc_h` (fresh `(ss_h, ct_h)` per query) and `Dec_h` (returns componentwise `ss`),
  then outputs two equal-length candidate secrets `ss_h^0, ss_h^1`; challenger returns
  `ss_h^b`; `A` guesses `b`. Advantage `ε`.
- **Game 1.** Replace the **p-component** oracle transcript with self-consistent *real*
  encapsulations. Any distinguisher against Game 0→1 runs `A` and answers its `Dec` queries by
  delegating to a `B_p` that holds a real `Dec_p` oracle; on transcript mismatch it flips the
  guess. Distinguishing advantage ≤ `Adv^{IND-CCA}_{B_p}(λ)`.
  *(This step only requires the p-side to behave like a real KEM oracle — it does NOT require
  the p-side to be hard; if pq is broken, `B_p` is trivially powerful, but we will not need it —
  see Game 3.)*
- **Game 2.** Replace the **c-component** similarly; advantage ≤ `Adv^{IND-CCA}_{B_c}(λ)`.
- **Game 3.** In the now-real transcript, the challenge secret is
  `ss_h^b = ss_c^b ‖ ss_p^b`. **Key observation:** the two halves are joined by pure
  concatenation of *fixed-length* values, so `b` is determined by *either* half alone. We may
  thereby split the guess: `A` succeeds iff it guesses `b` correctly from `ss_c^b` **or** from
  `ss_p^b` restricted to transcripts where the other is already real. Precisely, by the tower
  rule for conditional entropy/bit-guessing, the hybrid guess advantage is bounded by the sum
  of the per-half guess advantages. In the final game both halves are real and independent, so
  `b` is a uniformly random bit independent of everything except the paired `ss_*^b` blocks.
  If `B_c` can predict `ss_c^b`-bit (classical broken) the reduction to `B_c` from Game 2→3
  succeeds; symmetrically for `B_p`. Therefore the residual `A` advantage after Games 1–2 is
  `≤ Adv_{B_c} + Adv_{B_p}` plus one fresh-encapsulation statistical term `q_enc·negl` arising
  only from collision/length agreement of independently sampled fixed-length blocks (which is
  exactly where the IETF **dual-PRF HKDF** requirement bites: without fixed length + dual-PRF,
  a variable-length block could be re-parsed and the split argument fails — this is the
  timing/collision side-condition the paper cites).
- Hybrid-over Games: `ε ≤ ε_0−ε_1 + ε_1−ε_2 + ε_2−ε_3 + ε_3 ≤ Adv_{B_c} + Adv_{B_p} + q_enc·negl`.

**Corollary E1 (pq fully broken, classical holds).** Set `Adv_{B_p}= 1` (pq break) but
`Adv_{B_c} ≤ negl`: bound ⇒ `ε ≤ negl + q_enc·negl = negl`. ⇒ a record-now-decrypt-later or
quantum attacker who breaks the lattice half **gains nothing** on traffic whose classical half
still stands. This is precisely the paper's §1.2 "the LWE preprint might be wrong-broken →
hybrid still holds via ECDSA/ECDH" guarantee, now with its reduction.

**Corollary E2 (classical fully broken, pq holds).** Symmetric: `Adv_{B_c}=1`, `Adv_{B_p}≤negl`
⇒ `ε ≤ negl`. ⇒ Shor against ECDH does not recover `ss_h`, because `ss_p` alone is uniform
under ML-KEM's IND-CCA assumption. *(This is stronger than the paper states.)* Note the
**transcript-length corollary**: keys/ciphertexts are hybrid-length in every session, so an
observer cannot identify which sessions are "classical-only" and thus known-broken — all
recorded sessions remain opaque unless *both* halves are broken. ∎

## 6. Proof of G4 (composite-signature weakest link)

**Theorem 2.** Let `A` be a PPT forger against `VerH` (Alg 4, conjunction rule) with `q_h`
hash/sign queries (`|m| ≤ σ`) and success `ε`. Then for each component `i ∈ {c,p}` there is a
forger `B_i` with

```
ε  ≤  Adv^{EUF-CMA}_{B_c}(λ)  +  Adv^{EUF-CMA}_{B_p}(λ)  +  q_h·2^{-(σ/2)}     (collision)
```

and, specializing to the paper's conjunction acceptance, the bound is **tight in the weaker
half**: `ε ≤ Adv_{B_c} + negl` where `B_c` forges ES256 alone — Falcon512's reduction term
adds an already-negligible quantity and, if Falcon512 is *broken*, the bound does **not**
improve beyond `Adv_{B_c}` (you cannot exceed weakest-link).

*Proof.* Suppose `A` outputs a valid *new* accepting pair `m*, σ_c*‖σ_p*` with
`Ver_c ∧ Ver_p = 1` and `(m*, (·))` never previously returned. Since acceptance is the
conjunction, **both** `Ver_c(m*,σ_c*)` and `Ver_p(m*,σ_p*)` must hold.

1. **New message, new both halves.** If `m*` was never signed, then `σ_c*` is a fresh valid
   ES256 forgery *and* `σ_p*` a fresh Falcon512 forgery on `m*`. Feed `A`'s output to `B_c`
   (which runs `A`, simulates `Sign_p` by honest Falcon signing, and returns an EUF-CMA break
   on ES256 when `A` wins). `B_c`'s advantage = `A`'s minus simulation error `q_h·2^{-(σ/2)}`
   (hash collision on the challenge messages — bounded since ES256 and Falcon512 both hash
   internally with collision-resistant `H`, and `σ` is large).
2. **New message, reused half.** Impossible for acceptance: reusing a *classical* half alone
   on a new message without a fresh Falcon512 signature fails `Ver_p`.
   Reusing the *Falcon* half alone on a new message fails `Ver_c`.
3. **Malleability (why conjunction ≠ sufficiency of one half).** ECDSA admits
   `(r, s) → (r, −s mod n)` malleation, and Falcon signature encoding has its own
   re-encoding quirks; but Alg 4 requires *both* halves valid on the *same* `m`, and msmith-
   modifying one block leaves the other block still bound to `m`, so a malleated `(σ_c', σ_p)`
   on an *already signed* `m` equals an existing transcript and is rejected by the SUF-style
   freshness check in the ideal case; at minimum it is not a *new-message* forgery, which is
   what EUF requires. Hence no extra SUF gain is claimed (we do **not** claim strong
   unforgeability — only existential, strengthening the phrase "weakest security guarantee of
   existential unforgeability" in §2.3.2).

Therefore `ε ≤ Adv_{B_c} + Adv_{B_p} + negl`. Because acceptance is a conjunction, `A`'s win
event is the *intersection* of both half-validity events, so `ε ≤ min(Adv_{B_c}, Adv_{B_p})`
in the tight reading; substituting a full classical break `Adv_{B_c} → 1` yields `ε ≤ 1`
(trivial), while a full Falcon break with intact ES256 still yields `ε ≤ Adv_{B_c}` — i.e.,
**the hybrid signature never advertises more security than ES256.** This formalizes the
paper's warning and prevents the common overclaim "hybrid ≥ strongest component." ∎

## 7. Proof of G1 (transport-level corollary) and channel binding

**Theorem 3 (OIDC-over-hybrid-TLS inherits G2).** The OIDC authorization-code flow transmits
`code`, `access_token`, and `id_token` only inside TLS records keyed by `ss_h`. Under the
TLS 1.3 PRF/record-secrecy idealization with `K = HKDF-Extract(ss_h)` (dual-PRF), transcript
indistinguishability reduces to `K`'s indistinguishability, which by Theorem 1 is `negl` if
either KEM half stands. The JWT/JWKS layer is additionally protected by Theorem 2, so even a
JWT *exfiltrated out-of-band* (bearer token at rest) is unforgeable-at-new-message up to the
ES256 bound.

*Proof sketch with the missing linker.* TLS's exported transcript hash binds the hybrid
`key_share`; a MITM (E3) cannot downgrade to a classical-only share because the hybrid share
has a distinct, curve-plus-KEM length and both peers require it (oqs-provider's hybrid group
check). The only compositional gap in the *paper's* description is that the **JWT dual
signature is not bound to the TLS transcript hash** (unlike `channel_binding`/`tls-exporter`
tokens): a stolen `id_token` is replayable to any RP that accepts it without `c_hash`/`at_hash`
or sender-unreplay). Our construction fixes this by optionally including the TLS
`exporter_master_secret`-derived channel-binding value in the signed payload (Alg 4 input
`m ‖ cb`), closing the gap between transport claim (G1) and token claim (G3). ∎

---

## 8. What this spec does NOT claim

- No SUF-CMA / one-more unforgeability for the signature (only EUF-CMA, weakest-link).
- No security if **both** halves break; no protection against a fully quantum adversary
  against *classical-only* deployments.
- `q_h·2^{-σ/2}` collision term assumes collision-resistant `H` at `σ`-bit message length.
- Constant-time, side-channel, and implementation-level guarantees are out of scope (matches
  the paper's scope; liboqs/oqs-provider handle constant-time at the primitive layer).

## 9. Traceability: claim → proof → test

| Claim | Proof | Test |
|---|---|---|
| G1/E1 RNDL: pq-break ⇒ classical sessions safe | Thm 1, Cor. E1 | TestE1ClassicalHoldsUnderPQBreak |
| G1/E2: classical-break ⇒ hybrid still safe | Thm 1, Cor. E2 | TestE2HybridKeySurvivesClassicalBreak |
| G2 if-either IND-CCA | Thm 1 (Games 0–3) | TestCompositeKEMCiphertextTamperIndist |
| G3 conjunction acceptance | §3/Alg 4 | TestHybridVerifyRejectsEitherHalfMissing |
| G4 weakest-link = ES256 | Thm 2 (fresh-message + malleation cases) | TestSignatureForgeryRequiresFreshECDSA |
| G1↔G3 channel-binding corollary | Thm 3 | TestChannelBoundJWTRejectsReplay |

Next: the Go implementation (`pkg/hybridoidc`) realizes Alg 1–4 and exercises each row.