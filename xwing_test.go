package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/hkdf"
)

// X-Wing, in Go, as an ORACLE for web/static/mlkem.js — the same relationship
// chunkformat_test.go has with the container format. Nothing in the shipped
// binary encapsulates, decapsulates or generates a key: a drop's keypair is
// born in the owner's browser and the server never sees either half. This lives
// in test scope so the two implementations can be held against each other, and
// TestServerHasNoAsymmetricCryptography is what keeps it there.
//
// The primitive is draft-connolly-cfrg-xwing-kem: ML-KEM-768 + X25519 under a
// fixed combiner, with the whole private key expressed as a 32-byte seed. That
// seed size is why a drop's private link looks like every other Pyxis link.
//
// Go needs no new dependency for any of it: crypto/mlkem, crypto/sha3 and
// crypto/ecdh are all standard library.

// XWingLabel: the 6-byte ASCII string the combiner ends with, `\./` then `/^\`.
var xwingLabel = []byte{0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c}

const (
	xwingSeedLen    = 32
	xwingPubLen     = 1216 // 1184-byte ML-KEM-768 key || 32-byte X25519 key
	xwingCipherLen  = 1120 // 1088-byte ML-KEM-768 ciphertext || 32-byte X25519 key
	xwingMLKEMPub   = 1184
	xwingMLKEMCiphe = 1088
)

// xwingExpand derives the whole keypair from the 32-byte seed, exactly as the
// draft's expandDecapsulationKey does: SHAKE256 the seed to 96 bytes, the first
// 64 of which seed ML-KEM and the last 32 are the X25519 scalar.
func xwingExpand(t *testing.T, seed []byte) (*mlkem.DecapsulationKey768, *ecdh.PrivateKey, []byte) {
	t.Helper()
	if len(seed) != xwingSeedLen {
		t.Fatalf("seed is %d bytes, want %d", len(seed), xwingSeedLen)
	}
	expanded := make([]byte, 96)
	sh := sha3.NewSHAKE256()
	if _, err := sh.Write(seed); err != nil {
		t.Fatalf("shake write: %v", err)
	}
	if _, err := sh.Read(expanded); err != nil {
		t.Fatalf("shake read: %v", err)
	}
	dk, err := mlkem.NewDecapsulationKey768(expanded[0:64])
	if err != nil {
		t.Fatalf("ml-kem key from seed: %v", err)
	}
	xk, err := ecdh.X25519().NewPrivateKey(expanded[64:96])
	if err != nil {
		t.Fatalf("x25519 key from scalar: %v", err)
	}
	pub := append(append([]byte{}, dk.EncapsulationKey().Bytes()...), xk.PublicKey().Bytes()...)
	return dk, xk, pub
}

// xwingCombiner is the draft's Combiner: one SHA3-256 over the two shared
// secrets, the X25519 ciphertext, the recipient's X25519 key and the label.
// Binding ct_X and pk_X in is what gives X-Wing the binding properties raw
// ML-KEM does not have.
func xwingCombiner(ssM, ssX, ctX, pkX []byte) []byte {
	h := sha3.New256()
	h.Write(ssM)
	h.Write(ssX)
	h.Write(ctX)
	h.Write(pkX)
	h.Write(xwingLabel)
	return h.Sum(nil)
}

func xwingDecapsulate(t *testing.T, seed, ct []byte) []byte {
	t.Helper()
	if len(ct) != xwingCipherLen {
		t.Fatalf("ciphertext is %d bytes, want %d", len(ct), xwingCipherLen)
	}
	dk, xk, pub := xwingExpand(t, seed)
	ssM, err := dk.Decapsulate(ct[:xwingMLKEMCiphe])
	if err != nil {
		t.Fatalf("ml-kem decapsulate: %v", err)
	}
	peer, err := ecdh.X25519().NewPublicKey(ct[xwingMLKEMCiphe:])
	if err != nil {
		t.Fatalf("x25519 peer key: %v", err)
	}
	ssX, err := xk.ECDH(peer)
	if err != nil {
		t.Fatalf("x25519: %v", err)
	}
	return xwingCombiner(ssM, ssX, ct[xwingMLKEMCiphe:], pub[xwingMLKEMPub:])
}

type xwingVector struct {
	Seed  string `json:"seed"`
	SK    string `json:"sk"`
	PK    string `json:"pk"`
	ESeed string `json:"eseed"`
	CT    string `json:"ct"`
	SS    string `json:"ss"`
}

// TestXWingDraftVectors pins this implementation to the specification rather
// than to itself. Both directions Go can express are checked: a keypair grown
// from the seed must equal the published public key, and decapsulating the
// published ciphertext must yield the published shared secret.
//
// The ENCAPSULATION direction is deliberately absent. Reproducing a vector's
// ciphertext needs derandomised ML-KEM encapsulation, which the standard
// library does not expose; that half is checked against the same vectors in
// JavaScript, where the implementation that actually runs in a browser can be
// driven with the vector's own encapsulation seed.
func TestXWingDraftVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/xwing-draft10-vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var file struct {
		Vectors []xwingVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(file.Vectors) != 3 {
		t.Fatalf("got %d vectors, want the draft's 3", len(file.Vectors))
	}
	for i, v := range file.Vectors {
		seed := mustHex(t, v.Seed)
		wantPK := mustHex(t, v.PK)
		wantSS := mustHex(t, v.SS)
		ct := mustHex(t, v.CT)

		if v.Seed != v.SK {
			t.Errorf("vector %d: the private key is not the seed, which is the whole reason a drop link fits in a fragment", i+1)
		}
		if _, _, pub := xwingExpand(t, seed); !bytes.Equal(pub, wantPK) {
			t.Errorf("vector %d: public key mismatch", i+1)
		}
		if got := xwingDecapsulate(t, seed, ct); !bytes.Equal(got, wantSS) {
			t.Errorf("vector %d: shared secret mismatch\n got %x\nwant %x", i+1, got, wantSS)
		}
	}
}

// TestXWingSizesMatchTheProtocolConstants guards the numbers the wire format
// and the database columns are built on: a drop row stores a sealed public key
// of one fixed length, a submission row a ciphertext of another.
func TestXWingSizesMatchTheProtocolConstants(t *testing.T) {
	seed := make([]byte, xwingSeedLen)
	for i := range seed {
		seed[i] = byte(i)
	}
	_, _, pub := xwingExpand(t, seed)
	if len(pub) != xwingPubLen {
		t.Errorf("public key is %d bytes, the protocol says %d", len(pub), xwingPubLen)
	}
	if dropPublicKeyLen != xwingPubLen {
		t.Errorf("dropPublicKeyLen is %d, the protocol says %d", dropPublicKeyLen, xwingPubLen)
	}
	if dropSealedPKLen != dropNonceLen+dropPublicKeyLen+gcmOverhead {
		t.Errorf("dropSealedPKLen %d does not match a sealed %d-byte key", dropSealedPKLen, dropPublicKeyLen)
	}
	if dropCiphertextLen != xwingCipherLen {
		t.Errorf("dropCiphertextLen is %d, want %d", dropCiphertextLen, xwingCipherLen)
	}
}

// --- the drop key schedule, browser against Go -----------------------------
//
// Vectors produced by web/static/e2e.js and web/static/mlkem.js running on
// Node, from the fixed owner secret below. They pin the whole schedule: if a
// label moves, a salt changes or the KEM is swapped, these stop matching — and
// so would every live drop.
//
// Regenerate by loading both modules in Node (globalThis.window = globalThis)
// and driving PYXIS_E2E from jsDropOwnerSecretHex.
const (
	jsDropOwnerSecretHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	jsDropPublicID       = "11111111-2222-3333-4444-555555555555"
	jsDropBatchID        = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

	// The two branches off the owner's secret.
	jsDropKemSeedHex   = "2f685cba12525a78045bcbb2823c78f9c46cb8eb492c33160783732e1fb7470c"
	jsDropShareSecHex  = "9df2eebea23bd56a30476bff484b33fea285c3cda503790c3e0ed392cf11052b"
	jsDropPublicKeySHA = "c8df9d8a632cf159328483898d459afb7b7777e5ec3f8b875772b4193c9ae5ed"

	// The two branches off the share secret: one seals the public key, one is
	// handed to the server as SHA-256(token) and gates uploads.
	jsDropPkKeyHex = "a0cb39450784230acab2e49d3751488db68c579bf423b5547261895d4a58b418"
	jsDropTokenHex = "0250ec617415e63a35ebbe728e6435da7f0cc2643d414fba44c752959c14817f"

	// The submission root and the four branches under it. The first three are
	// the SAME branches a batch link derives — which is what makes a submission
	// a batch and lets the inbox reuse the download page unchanged.
	jsDropRootHex   = "c5ad12c838a219fc0e3c800090ed64d5fd3bad670b8f811d4542654954488f97"
	jsDropBatchKey  = "2e02329280e9add9ac23169fef61719fdbfc1ba7747af184c83f9f28753ed974"
	jsDropRosterKey = "06f2431310927a67a98f0ec782c8dd2f814759d5d5dd6dc475c16f1be417255b"
	jsDropNameKey   = "da29bcc93a22449049c2d612556ed225b5827c7d321c4fd3b0e570bca0a34c5e"
	jsDropNoteKey   = "7df3c3904816d8801624b20ffa4548f8e7862eadeb7e5083c02d80f6a2ac4bc1"

	// The public key as the server stores it, and one submission's
	// encapsulation. The nonce and the encapsulation are random, so these are
	// captured blobs rather than values Go can recompute — which is the point:
	// the server stores exactly this and can do nothing with either.
	jsDropSealedPK = "IInuJSUDHxzSM8vTM9LTl9gWOJ5akqgWOBnpii-UP94VtZSoBRMLFY6vjs0M8eMDISTLuu_9G4k3VDd57MjD1uxk2x5JOFNBhXtfeBe1ScHP8ErZCbnNOasxC5HNeNRinYRHO68HIfDfkocVJ-MLX5jojRCJTTQ9IjuxR2KB1To2T8TJ1eLCnualnJlsBtioiodtnBWf5iu7A3ta-wD-TGm8KxZsrsIdjPlPDHNnNtYe6hPK50RZD4bYqwhDMfMTLknWMtUsvg7iVQibA64i-qtsyNfOo71K5xMLbQv-E3OzrTBd2KqRfb1s3sLkqMvkoVffznS3BwOqUCYga6sm4W3rYD3-riHw8S5_iGX8nB1-HfpFRhv6knxYoXifo3edVTX2SB-Ha7ijDDJDqWu6ZSGo1E4l_pCwNyZSitTkCcRrpRrAoSrx3I5td8L7xDM4MmN0E85LB2UZaGoPO-tqJb-vosRaUoYSkSXi4ePkx0k5A0AfAg2qen35iZZGeT2B9wzQFwJToC56-lO_yJrJSKdahfcbwfsuHCJHSMuB0MDT2wlCZGfeoppx6jYT1VarJZ9kEcIuOyUvYVUnqqS8f-tHwDTPwuNbH_cSs6C5yJWGbxRGdNxNBVe2-Ip4tDVK51gD_T9Gz2NRqeLM33B2gUg5jYTNK5Vbntw20fafbwmjB6Bt9IJv_2P2SytYtz07h7LxLpb_kgASb35TEl3P_PoVCGhB8A837njXoSPTYHs7oOSbswS3Xr5ugsY6UY0AoRzwmw2Gtw3X_INzTk6CccE6kdFXc7myNiySuZzsdxXWTkS7_TuwvVaPcPe9aUXOD7VrnP4S-nyjra-WXB26_na6JChWh2DrQNDlw4bQSHK2InUNU0GgVt2yBBsTOPohE3z8k_fmLcw1M-bKknhki9fFOMHOBLDnNro-ni1mLA2FhntJc959FxUDOc2WniNajjyjh9gysVxX4JL-mtjcRmwo-karpk0X5FSezXSHv1Xge0JcUnVqiy5tl9WskI8aVgpw0oj_P7mrmdLw298F8oQLZQzDyyNFxL3HtDHEb9laeAc1TFsCk3LQE8XkVvKO3-IqoGkwB723ic_LEja8q3RcMBvXEYJqmO8_EdJxOTP8ajPij-MpQum1vs3JZrblzqzkeIGGHvkDTG6tJj5fBs8zU1LXCpsfX-AqbOx-krhwBIoy_L814Sl0hvTLyNZRHk1u-2OGZxgcLeIK20FAcm6Xqppk0UCCZuJV0A2ct9o4xpSAOgrImehvycwWMKYUh5zrS8k70Lq4B_9KZbtpfeP4SbveOfvQ9ikkWxjiQXwr4MTyIWVbLdhv6xvhmkEVkdnkD0rMXvEDfV4qv_RodWq1ZOaPxFCMn1jS6JRET9OtFiJpfhoL28rcqZschyCCVvAFwv3oOcrBDXWmX0nPV9Ndd7P1_rDtffGl1f41o-oQw9bZ__7Qfw5mW7YEGtPAf482CUiHcD2_XAq9yKdYQNc9dMgxgh5OnFnTtQp4oEa-pbN5sHALMkLHi3Kh6IFUEat_rKye9mc3oZAgWjv6OrliRA98QyXpKzSXDdbD_Jge4WzXHkvZaVhbwInx2m9u0BwsubfQnql04Yo2R5cuTXZLfUPQ2P2BMwakfDJPZJMPrPYVoBYYvVtp2cE"
	jsDropCT       = "ZqnFU5_vGJ3PH3dV7BEIW2dti7rzWQNR7VROhQM-jwSpwTEeUMMtDL6FsbcGceQYJSk4gmzJDAcfnUKBUwV5ds5q7AYUw8hRYeZCS7Ao5buWLkShAOJX6BWthcy9hq4fOcD5zo3gk7AWHhtgd4mYXZsF0ak1ng5ut9pRc7qBJMPlgDYJHoebe1dVkwZnWZX6S3254dNITAcDqEryRmqnp8FL0gsnGLms-R9vHMAcTMdmQnQ4E4yVmm9gUtumlLD1JXOfm-4A1jTTXob5Sfv412G1Hx-4-6-OD0a1oLwGo5ZTZbBKHdqotE3gQfd2inJM9VuG14aihkxILpIOGMqqGRY-tfXGh9VWyrNEbO1CsEkiQzsr30IcaPLP9q75V7GwqK4FlqRO_04hWgpDBHWRP6o_i4ZcMtQBiW9Ho69K_Tz7hxCM-hW05FpPHtMt93Tu3l0w1wr95INRIJfi_kghydUR5SqK50rug_YXDt7VC0klQhKmG64MaBup_Dz-feDidxwRbj_8imtEPPNh7g6RFc_ZQdOMHeyWyNhCt-8nsM2Pu0A5xLINhpAD0gdzBPegmdrLrGire6OgglpyvG_DmVr3WIZlRJEGFWF6XaYf6ksmLqh9rrb2yqkcMgQLFQCl8NO3C6APU1ouTi--z2nFdT0FFsxvZwGyHKXMO4PSW_YCVx0I3ZJ2sMd1GjxQkzXiFpf2p2fJfjdtaHpVzAAZFPGBFMSfoLtvtvXXkiL_M7-xYdfb7wdrJ8OGx6mQnLMQ6orU1XPVPVdv53LM3_fmOIva5LitXGCI_MVxm6IVeBVn7VVeQS3tuDZbzV7Sx5LcjUFtHN06u3tbHggmmj7scmsIPv03KMJi9Q8Bbz7T5gza40nI7mZACNbM4878gBMFh2GvWq3wbgEZ3HGz1MTxNzQ1HBackvKVKKAQUrklaqgyF5-ylX-lLG5HRq-KttIywLquTfElNRqsPhEHgVHwgeyaTNhgAxmICjM6JI77qcy0XD6Kl8Vv-EZqxGMamcfEf2zaj-ii4Mb7nyRyPA7iyqincEsqcP_zf_gMy3UjULTcVOB3zWxO9ey-ffLjo2srePx5dnnP9CDLKNG5qxxxZyaAvFXItYLFNlNp_pWqv8deBnQkos6hbvPLHy2gOgyH1pTXz7AfcneVRydRrYLU_AMRg4pyjUXXM954l-MOipnq5lKeK8K_qDDGJwal8XlxDGJ0EquNxb66YXA-jkp2vfYG_hy_UVKrvDuNqN6S9_aqkrN8j7g7SBY3XvPF1lmJmjkg1Bi916TUzeOPwqC4RjUBBN3NYT5PYb8vQ1OKEIOeW3MwFpUHpFeRP0VtVMRzcmLnvd5apxGo6bmMNVVQPXOz5J8hFxdglAnM0dUJmvzSf_mIrttnumXAZLwfjXrpsZiRlc_wJrsY_3p5jLqjIewHlVtF-SdTWMSdwUHI9J26XLjnr8f389ICADMJJ74sxvckCyD66YNiRP6p-0V4RQ"

	jsDropSealedNote = "PVDYUcehCk_6ySR4jCsALpqE_aVt-8j0Z5uUEU0Vxk6QPfipWSYijdpfO9QwqN_aFdyZOjGXRG7MlnWGG8s1CiIp6DXqQ0ClGiLJcgnx9tMHE3QA-JXR3Kfo_bCufkjKRS7yvvpQ2s6IV5J0DCcn-PVxoOgE2nT-s3Wzkf-HQEYplHLBrty8o-XeVUpoxgufiX19ayoAVHrLQe4ftJEgF1gRuKx--uQ6U6TXgPj9uFiBisZBB_2TgM6Kzns7CoGPW-XFfLP5yyEPUrqYANPuZVGAD-T1BhJUCvEGwqapVMwC9dbfAKoSKJ5J0M5W6gHSJds7Pq5pyhDpY4gykR7FA7-TNkMUFCC667XrQd8rUWQGoygJhC80SQuRzc6cY70hj7B8lm921I9ERdHDuGVl-sHTP2XsGK_BdLx_iUxGuxDJTG5Extsi3VPZK9z3Xc5azMBk3ukQk-d5AsxBU-dbEn3sRgMpG0Le0SaVqDuJxr1mSDZDXfPXXnlqUm0bpNdfZLaxNoz_2nyrI9WlU36phZq05JYUFEeZGnk0Rrt-V1U3R6RuHVSn5RfWyPh6HYmFpQ-K96qoQAbfapX49ptEaMtKIhLCYvx6BmJUgZkM60v8yo7DAqrwaAIqQbh8D5yEK1xo1a2yWmyLRZ1FxBs6s2UpOAwn42GpOZeBIPIG-qEMmeLbpjV52cVhyblQx-mu_JoWecHvkfsSch3G"

	jsDropSSHex       = "5e5774c0b431bee04079f2906083ea4f737d1650bbdc326f63d80d12893dd92a"
	jsDropNoteFrom    = "Alice"
	jsDropNoteMessage = "the signed contract"
)

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("bad base64url: %v", err)
	}
	return b
}

func dropHKDF(t *testing.T, secret, salt []byte, info string) []byte {
	t.Helper()
	out := make([]byte, 32)
	if _, err := hkdf.New(sha256.New, secret, salt, []byte(info)).Read(out); err != nil {
		t.Fatalf("hkdf %s: %v", info, err)
	}
	return out
}

// TestDropKeyScheduleMatchesBrowser walks the owner's secret all the way to a
// submission's four keys and compares every step with the browser's.
func TestDropKeyScheduleMatchesBrowser(t *testing.T) {
	owner := mustHex(t, jsDropOwnerSecretHex)

	kemSeed := dropHKDF(t, owner, nil, "pyxis-drop-kem-v1")
	if got := hex.EncodeToString(kemSeed); got != jsDropKemSeedHex {
		t.Errorf("kem seed: got %s want %s", got, jsDropKemSeedHex)
	}
	shareSecret := dropHKDF(t, owner, nil, "pyxis-drop-share-v1")
	if got := hex.EncodeToString(shareSecret); got != jsDropShareSecHex {
		t.Errorf("share secret: got %s want %s", got, jsDropShareSecHex)
	}
	// The public link's secret is handed to strangers, so it must be a dead end.
	if bytes.Equal(shareSecret, owner) || bytes.Equal(shareSecret, kemSeed) {
		t.Fatal("the share secret is one of the private values; the public link would hand out the drop")
	}

	_, _, pub := xwingExpand(t, kemSeed)
	if sum := sha256.Sum256(pub); hex.EncodeToString(sum[:]) != jsDropPublicKeySHA {
		t.Errorf("public key digest: got %x want %s", sum, jsDropPublicKeySHA)
	}

	pkKey := dropHKDF(t, shareSecret, nil, "pyxis-drop-pk-v1")
	if got := hex.EncodeToString(pkKey); got != jsDropPkKeyHex {
		t.Errorf("pk-sealing key: got %s want %s", got, jsDropPkKeyHex)
	}
	token := dropHKDF(t, shareSecret, nil, "pyxis-drop-up-v1")
	if got := hex.EncodeToString(token); got != jsDropTokenHex {
		t.Errorf("upload token: got %s want %s", got, jsDropTokenHex)
	}

	// Opening the sealed public key proves the AAD too: the drop's public id is
	// bound in, so a sealed key cannot be moved between drops.
	sealed := mustB64(t, jsDropSealedPK)
	if len(sealed) != dropSealedPKLen {
		t.Fatalf("sealed public key is %d bytes, want %d", len(sealed), dropSealedPKLen)
	}
	opened := openSealed(t, pkKey, sealed, []byte(dropPKAADPrefix+jsDropPublicID))
	if !bytes.Equal(opened, pub) {
		t.Error("the sealed public key does not hold the key derived from the owner's secret")
	}
	if _, err := tryOpenSealed(pkKey, sealed, []byte(dropPKAADPrefix+jsDropBatchID)); err == nil {
		t.Error("a sealed public key opened under another drop's id")
	}

	// Decapsulation: the server holds this ciphertext and can do nothing with
	// it. Only the seed from the private link turns it into a shared secret.
	ct := mustB64(t, jsDropCT)
	ss := xwingDecapsulate(t, kemSeed, ct)
	if got := hex.EncodeToString(ss); got != jsDropSSHex {
		t.Errorf("shared secret: got %s want %s", got, jsDropSSHex)
	}

	ctDigest := sha256.Sum256(ct)
	root := dropHKDF(t, ss, ctDigest[:], "pyxis-drop-sub-v1")
	if got := hex.EncodeToString(root); got != jsDropRootHex {
		t.Errorf("submission root: got %s want %s", got, jsDropRootHex)
	}

	for _, b := range []struct {
		info, want string
	}{
		{"pyxis-e2e-batch-v1", jsDropBatchKey},
		{"pyxis-e2e-roster-v1", jsDropRosterKey},
		{"pyxis-e2e-name-v1", jsDropNameKey},
		{"pyxis-drop-note-v1", jsDropNoteKey},
	} {
		if got := hex.EncodeToString(dropHKDF(t, root, nil, b.info)); got != b.want {
			t.Errorf("%s branch: got %s want %s", b.info, got, b.want)
		}
	}

	// The sealed sender note, opened with the key Go just derived.
	note := openSealed(t, mustHex(t, jsDropNoteKey), mustB64(t, jsDropSealedNote),
		[]byte(noteAADPrefix+jsDropBatchID))
	var body struct {
		V       int    `json:"v"`
		From    string `json:"from"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(unpadSealedBody(t, note), &body); err != nil {
		t.Fatalf("note json: %v", err)
	}
	if body.From != jsDropNoteFrom || body.Message != jsDropNoteMessage {
		t.Errorf("note: got %q/%q", body.From, body.Message)
	}
	if !validEncNameLen(len(mustB64(t, jsDropSealedNote))) {
		t.Error("the sealed note is not padded to a length the server will accept")
	}
}

// TestSubmissionKeysAreBoundToTheirCiphertext checks the salt actually does
// something: two submissions to one drop must not share a key schedule even if
// a shared secret somehow repeated.
func TestSubmissionKeysAreBoundToTheirCiphertext(t *testing.T) {
	ss := mustHex(t, jsDropSSHex)
	ct := mustB64(t, jsDropCT)
	a := sha256.Sum256(ct)
	other := append([]byte{}, ct...)
	other[0] ^= 0x01
	b := sha256.Sum256(other)
	if bytes.Equal(dropHKDF(t, ss, a[:], "pyxis-drop-sub-v1"), dropHKDF(t, ss, b[:], "pyxis-drop-sub-v1")) {
		t.Error("the submission root ignores its ciphertext")
	}
}

func tryOpenSealed(key, sealed, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, sealed[:dropNonceLen], sealed[dropNonceLen:], aad)
}

func openSealed(t *testing.T, key, sealed, aad []byte) []byte {
	t.Helper()
	out, err := tryOpenSealed(key, sealed, aad)
	if err != nil {
		t.Fatalf("open sealed blob: %v", err)
	}
	return out
}

// unpadSealedBody strips the uint16 length prefix and the zero padding that
// hides how long a sealed name or note actually is.
func unpadSealedBody(t *testing.T, body []byte) []byte {
	t.Helper()
	if len(body) < 2 {
		t.Fatal("sealed body is too short")
	}
	n := int(body[0])<<8 | int(body[1])
	if n == 0 || 2+n > len(body) {
		t.Fatalf("sealed body says %d bytes of content in %d", n, len(body))
	}
	return body[2 : 2+n]
}

// TestServerHasNoAsymmetricCryptography is the claim above, enforced.
//
// A drop's keypair is generated in the owner's browser and the server is never
// sent the half that reads. Nothing in the shipped binary encapsulates,
// decapsulates, signs or generates a keypair — and the way that stays true is
// not a sentence in a README but this test, which fails the build if an
// asymmetric primitive is ever imported outside test scope.
//
// crypto/mlkem, crypto/ecdh and crypto/sha3 are used HERE, as the oracle that
// holds web/static/mlkem.js to the specification. That is the point of the
// distinction: the test may reason about the primitive, the server may not
// perform it.
func TestServerHasNoAsymmetricCryptography(t *testing.T) {
	banned := []string{
		`"crypto/mlkem"`,
		`"crypto/ecdh"`,
		`"crypto/rsa"`,
		`"crypto/ecdsa"`,
		`"crypto/ed25519"`,
		`"crypto/dsa"`,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		checked++
		// Only the import block: a package named in a comment (this file is
		// full of them) is documentation, not a dependency.
		imports := src
		if end := bytes.Index(src, []byte("\n)")); end > 0 {
			imports = src[:end]
		}
		for _, b := range banned {
			if bytes.Contains(imports, []byte(b)) {
				t.Errorf("%s imports %s: the server must hold no asymmetric key material, "+
					"and a drop's keypair belongs to the browser that made it", name, b)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no non-test sources found; the guard would pass vacuously")
	}
}
