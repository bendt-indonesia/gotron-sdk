//go:build !windows
// +build !windows

package keystore

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func RecoverPubkey(hash []byte, signature []byte) (common.Address, error) {

	if signature[64] >= 27 {
		signature[64] -= 27
	}

	// Recover the public key from the hash and signature
	sigPublicKey, err := crypto.Ecrecover(hash, signature)
	if err != nil {
		return common.Address{}, err
	}

	// Convert recovered public key bytes to a usable PublicKey struct
	pubKey, err := crypto.UnmarshalPubkey(sigPublicKey)
	if err != nil {
		return common.Address{}, err
	}

	// Convert PublicKey to Ethereum address
	addr := crypto.PubkeyToAddress(*pubKey)
	return addr, nil
}
