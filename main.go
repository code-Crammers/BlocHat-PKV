package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gagliardetto/solana-go"
)

// Bitcoin
func isBTCKey(publicKey string) (bool, bool) {
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return false, false
	}

	parsedKey, err := btcec.ParsePubKey(publicKeyBytes)
	if err != nil {
		return false, false
	}

	if parsedKey.SerializeCompressed()[0] != publicKeyBytes[0] {
		return true, false
	}
	return true, true
}

// Ethereum
func isEthKey(publicKey string) bool {
	if common.IsHexAddress(publicKey) {
		return common.IsHexAddress(publicKey)
	}
	return false
}

// Dogecoin
func isDogeKey(publicKeyStr string) bool {
	publicKeyBytes := base58.Decode(publicKeyStr)

	ok, _ := regexp.MatchString("^D[A-Z0-9]", publicKeyStr)
	if ok {
		if len(publicKeyBytes) != 25 {
			return false
		}
		if publicKeyBytes[0] != 0x1E {
			return false
		}
		hash := doubleSha256(publicKeyBytes[:21])
		if !bytesEqual(hash[:4], publicKeyBytes[21:]) {
			return bytesEqual(hash[:4], publicKeyBytes[21:])
		}
		return true
	} else {
		return false
	}
}

func doubleSha256(data []byte) []byte {
	firstHash := sha256.Sum256(data)
	secondHash := sha256.Sum256(firstHash[:])
	return secondHash[:]
}

func bytesEqual(a []byte, b []byte) bool {
	return hex.EncodeToString(a) == hex.EncodeToString(b)
}

// Solana
func isSolanaKey(publicKey string) bool {
	_, err := solana.PublicKeyFromBase58(publicKey)
	if err == nil {
		return err == nil
	}
	return false
}

// Main function
func main() {
	var key string
	fmt.Print("Enter public key: ")
	fmt.Scanln(&key)

	isBTCKey, isBTCCompressed := isBTCKey(key)
	isEthKey := isEthKey(key)
	isDogeKey := isDogeKey(key)
	isSolanaKey := isSolanaKey(key)

	switch {
	case isBTCKey && isBTCCompressed:
		fmt.Println("Input is a valid Bitcoin's compressed public key")
	case isBTCKey && !isBTCCompressed:
		fmt.Println("Input is a valid Bitcoin's uncompressed public key")
	case isEthKey:
		fmt.Println("Input is a valid Ethereum public key")
	case isDogeKey:
		fmt.Println("Input is a valid Dogecoin public key")
	case isSolanaKey:
		fmt.Println("Input is a valid Solana public key")
	default:
		fmt.Println("Input is not a valid public key")
	}
}
