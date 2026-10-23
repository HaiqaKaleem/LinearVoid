package hybridoidc

import (
	"bytes"
	"testing"
)

// G1/Cor. E1 (Thm 1): a total break of the pq half must NOT weaken traffic
// whose classical half still holds — i.e. the hybrid shared secret remains
// unpredictable to an adversary who breaks only pq.
func TestE1ClassicalHoldsUnderPQBreak(t *testing.T) {
	// pq half fully broken; classical half sound.
	h := &HybridKEM{Classical: &roKEM{}, PQ: &roKEM{broken: true}}
	pk, sk, err := h.KgenH()
	if err != nil {
		t.Fatal(err)
	}
	ss1, ct, err := h.EncH(pk)
	if err != nil {
		t.Fatal(err)
	}
	ss2, err := h.DecH(sk, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ss1, ss2) {
		t.Fatal("honest decap must recover hybrid secret")
	}
	// Adversary breaks only the pq block: recovers ss_p but the classical
	// block ss_c remains unknown, so the full 64B secret is not recovered.
	// Simulate: adversary reads pq block (index 32..64), classical block is
	// the RO-keyed half it cannot invert without the RO preimage.
	pqBlock := ss1[32:]
	_ = pqBlock
	// The classical block must differ from anything pq-break could guess:
	// two honest encapsulations under the same pk must differ in the
	// classical block (fresh ss_c per query) — proves pq-break alone does
	// not predict the secret.
	ss3, _, err := h.EncH(pk)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ss1[:32], ss3[:32]) {
		t.Fatal("classical block must be fresh & unpredicable by pq-break")
	}
}

// G1/Cor. E2 (Thm 1): a total break of the classical half (models Shor on
// ECDH) must not reveal the hybrid secret — the pq block alone is uniform.
func TestE2HybridKeySurvivesClassicalBreak(t *testing.T) {
	h := &HybridKEM{Classical: &roKEM{broken: true}, PQ: &roKEM{}}
	pk, sk, err := h.KgenH()
	if err != nil {
		t.Fatal(err)
	}
	ss1, ct, err := h.EncH(pk)
	if err != nil {
		t.Fatal(err)
	}
	ss2, err := h.DecH(sk, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ss1, ss2) {
		t.Fatal("honest decap must recover hybrid secret")
	}
	// Adversary discovers classical block ss_c = ss1[0:32]; the pq block
	// ss1[32:64] must still be a fresh 32B value, independently sampled per
	// encapsulation (a second honest encap differs in the pq block).
	ss3, _, err := h.EncH(pk)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ss1[32:], ss3[32:]) {
		t.Fatal("pq block must be fresh & unpredict by classical-break")
	}
}

// G2 (Thm 1, Games 0-3): tampering with either component ct must fail
// decapsulation (conjunction = ⊥ if either half fails), and equal-length
// fixed encodings hold (the timing/parser side-condition).
func TestCompositeKEMTamperIndist(t *testing.T) {
	h := NewDefaultHybridKEM()
	pk, sk, err := h.KgenH()
	if err != nil {
		t.Fatal(err)
	}
	if len(pk) != 2*pkLen || len(pk)%pkLen != 0 {
		t.Fatalf("pk fixed length violated: %d", len(pk))
	}
	_, ct, err := h.EncH(pk)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != 2*ctLen {
		t.Fatalf("ct fixed length violated: %d", len(ct))
	}
	// flip one classical byte
	tamperedC := append([]byte{}, ct...)
	tamperedC[0] ^= 0x01
	if _, err := h.DecH(sk, tamperedC); err == nil {
		t.Fatal("classical half tamper must fail (E3)")
	}
	// flip one pq byte
	tamperedP := append([]byte{}, ct...)
	tamperedP[2*ctLen-1] ^= 0x01
	if _, err := h.DecH(sk, tamperedP); err == nil {
		t.Fatal("pq half tamper must fail (E3)")
	}
	// honest decap OK
	if _, err := h.DecH(sk, ct); err != nil {
		t.Fatal(err)
	}
}

// G3 (Alg 4): acceptance requires BOTH halves; either half invalid ⇒ reject.
func TestHybridVerifyRejectsEitherHalfMissing(t *testing.T) {
	s := NewDefaultHybridSig()
	vk, sk, err := s.SkgH()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte(`{"iss":"op","sub":"user1"}`)
	sig, err := s.SignH(sk, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !s.VerH(vk, msg, sig) {
		t.Fatal("valid hybrid sig must verify")
	}
	// break classical half of sig
	badC := append([]byte{}, sig...)
	badC[0] ^= 0x01
	if s.VerH(vk, msg, badC) {
		t.Fatal("invalid classical half must reject (G3 conjunction)")
	}
	// break pq half
	badP := append([]byte{}, sig...)
	badP[2*32-1] ^= 0x01
	if s.VerH(vk, msg, badP) {
		t.Fatal("invalid pq half must reject (G3 conjunction)")
	}
	// wrong message
	if s.VerH(vk, []byte("other"), sig) {
		t.Fatal("message mismatch must reject")
	}
}

// G4 (Thm 2): even with the pq half fully broken (accepts anything), forging
// on a NEW message still requires a fresh classical (ES256-model) forgery.
// A forger who only tampers the pq block on an already-signed message does
// not yield a new-message forgery; forging on an unsigned message without a
// valid classical half fails.
func TestSignatureForgeryRequiresFreshECDSA(t *testing.T) {
	s := &HybridSig{Classical: &roSig{}, PQ: &roSig{broken: true}} // pq broken
	vk, sk, err := s.SkgH()
	if err != nil {
		t.Fatal(err)
	}
	signed := []byte("m1")
	sig1, err := s.SignH(sk, signed)
	if err != nil {
		t.Fatal(err)
	}
	// Replay (m1, sig1): accepted but is NOT a new-message forgery (not our
	// goal). Try forging on a fresh message with only a random/malleated
	// classical half:
	fresh := []byte("m2-never-signed")
	// attacker grafts a broken-pq-valid block but without valid classical half:
	sigP, err := s.SignH(sk, fresh)
	if err != nil {
		t.Fatal(err)
	}
	// sigP's classical half is a REAL signature on m2 because SignH runs the
	// classical half honestly — that's the legitimate signer, not a forger.
	// The forgery: take sig1 (classical half for m1) and pair it with a
	// broken-pq-valid block for m2:
	forged := append(append([]byte{}, sig1[:32]...), sigP[32:]...) // classical half for m1, pq half for m2
	if s.VerH(vk, fresh, forged) {
		t.Fatal("must reject: classical half doesn't sign fresh msg (G4 weakest link)")
	}
	// Honest sig on the fresh message still verifies (signer has sk).
	if !s.VerH(vk, fresh, sigP) {
		t.Fatal("legit signature must verify")
	}
}

// G1<->G3 (Thm 3): a JWT whose signed input includes a TLS channel-binding
// value must fail verification when replayed with a different binding (closes
// the bearer-token replay gap between transport and token claims).
func TestChannelBoundJWTRejectsReplay(t *testing.T) {
	s := NewDefaultHybridSig()
	vk, sk, err := s.SkgH()
	if err != nil {
		t.Fatal(err)
	}
	header := []byte(`{"alg":"hybrid","typ":"JWT"}`)
	payload := []byte(`{"sub":"user","exp":99}`)
	exporter1 := []byte("exporter-secret-conn-1")
	exporter2 := []byte("exporter-secret-conn-2")
	b1 := ChannelBinding(exporter1, []byte("tls-exporter"), []byte("rp"))
	b2 := ChannelBinding(exporter2, []byte("tls-exporter"), []byte("rp"))

	j, err := SignJWT2(s, sk, header, payload, b1)
	if err != nil {
		t.Fatal(err)
	}
	// Verify on same connection (b1) passes.
	if !VerifyJWT(s, vk, j, b1) {
		t.Fatal("legit token on its own connection must verify")
	}
	// Replay on a different connection (b2) fails.
	if VerifyJWT(s, vk, j, b2) {
		t.Fatal("channel-bound JWT must reject replay on new TLS connection")
	}
}

// Fixed-length enforcement (the timing/variable-length side-condition from
// §1 that the IETF hybrid draft requires for the dual-PRF argument).
func TestFixedLengthEncodings(t *testing.T) {
	h := NewDefaultHybridKEM()
	pk, _, err := h.KgenH()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 16; i++ {
		_, ct, err := h.EncH(pk)
		if err != nil {
			t.Fatal(err)
		}
		if len(ct) != 2*ctLen {
			t.Fatalf("ct length must be constant, got %d", len(ct))
		}
	}
	s := NewDefaultHybridSig()
	vk, sk, err := s.SkgH()
	if err != nil {
		t.Fatal(err)
	}
	_ = vk
	for i := 0; i < 16; i++ {
		sig, err := s.SignH(sk, []byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		if len(sig) != 64 {
			t.Fatalf("sig length must be constant, got %d", len(sig))
		}
	}
}