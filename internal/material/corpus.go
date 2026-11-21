package material

import gen "krfix/target/material"

// Seed describes one deterministic corpus input generated from the same
// three-anchor frame format as the sealed original material.
type Seed struct {
	Name        string
	Kind        string
	KeyID       uint32
	ServerEpoch uint32
	ClientEpoch uint32
	AttestEpoch uint32
	Note        string
}

// CorpusSeeds returns the fixed attack/benign set. Attack samples reproduce
// the key-rotation failure: the attestation moved to a newer epoch while the
// payload was still sealed under a stale client key. Benign samples stay
// consistent and must be accepted by both harness variants.
func CorpusSeeds() []Seed {
	return []Seed{
		{"atk_epoch_lag1", "attack", 7, 5, 4, 5, "client key one epoch behind"},
		{"atk_epoch_lag2", "attack", 7, 6, 4, 6, "client key two epochs behind"},
		{"atk_rotation_gap", "attack", 9, 8, 3, 8, "key id rotated, stale payload"},
		{"atk_replay_oldkey", "attack", 11, 10, 2, 10, "replay under retired key"},
		{"atk_epoch_zero", "attack", 7, 3, 0, 3, "client epoch never advanced"},
		{"atk_double_rotate", "attack", 13, 12, 9, 12, "two rotations missed"},
		{"benign_current", "benign", 7, 5, 5, 5, "epochs aligned"},
		{"benign_rotated", "benign", 9, 9, 9, 9, "aligned after rotation"},
		{"benign_initial", "benign", 7, 1, 1, 1, "initial epoch aligned"},
	}
}

// Build renders a seed into raw frame bytes.
func (s Seed) Build() []byte {
	var cipher, tag [32]byte
	for i := range cipher {
		cipher[i] = byte(0xA0) ^ byte(i) ^ byte(s.ClientEpoch)
		tag[i] = byte(0x50 + byte(s.AttestEpoch) + byte(i))
	}
	return gen.Build(s.KeyID, s.ServerEpoch, s.ClientEpoch, s.AttestEpoch, cipher, tag)
}
