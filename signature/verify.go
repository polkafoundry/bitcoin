package signature

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"reflect"
)

const ExpectedSignatureLength = 65

const CompressedRecoveryFlag byte = 31
const UncompressedRecoveryFlag byte = 27

// SignedMessage is the representation of verification request.
type SignedMessage struct {
	// Address that was used to sign the Message with.
	Address string
	// Message that has been signed by the Address.
	Message string
	// Signature that has been provided and should be valid against the Address and Message.
	Signature string
}

func VerifyBTCSignature(signedMessage SignedMessage, net *chaincfg.Params, rangedFlag byte) (bool, error) {
	// Decode the address
	address, err := btcutil.DecodeAddress(signedMessage.Address, net)
	if err != nil {
		return false, fmt.Errorf("could not decode address: %w", err)
	}

	// Decode the signature
	signatureEncoded, err := base64.StdEncoding.DecodeString(signedMessage.Signature)
	if err != nil {
		return false, err
	}

	// Ensure signature has proper length
	if len(signatureEncoded) != ExpectedSignatureLength {
		return false, fmt.Errorf("wrong signature length: %d instead of 65", len(signatureEncoded))
	}

	// compressed
	switch address.(type) {
	case *btcutil.AddressPubKeyHash:
		signatureEncoded[0] = CompressedRecoveryFlag
	case *btcutil.AddressScriptHash:
		signatureEncoded[0] = CompressedRecoveryFlag
	case *btcutil.AddressWitnessPubKeyHash:
		signatureEncoded[0] = CompressedRecoveryFlag
	case *btcutil.AddressTaproot:
		signatureEncoded[0] = UncompressedRecoveryFlag
	// Unsupported address
	default:
		return false, fmt.Errorf("unsupported address type '%s'", reflect.TypeOf(address))
	}

	signatureEncoded[0] += rangedFlag

	// Ensure signature has proper recovery flag
	recoveryFlag := int(signatureEncoded[0])

	if !Contains(All(), recoveryFlag) {
		return false, fmt.Errorf("invalid recovery flag: %d", recoveryFlag)
	}

	// Retrieve KeyID
	keyID := GetKeyID(recoveryFlag)

	// Should address be compressed (for checking later)
	compressed := ShouldBeCompressed(recoveryFlag)

	// Reset recovery flag after obtaining keyID for Trezor
	if Contains(Trezor(), recoveryFlag) {
		signatureEncoded[0] = byte(27 + keyID)
	}

	// Make the magic message
	// Hash the message
	messageHash := chainhash.DoubleHashB([]byte(CreateMagicMessage(signedMessage.Message)))

	// Recover the public key from signature and message hash
	publicKey, comp, err := ecdsa.RecoverCompact(signatureEncoded, messageHash)
	if err != nil {
		return false, fmt.Errorf("could not recover pubkey: %w", err)
	}

	// Ensure our initial assumption was correct, except for Trezor as they do something different
	if compressed != comp && !Contains(Trezor(), recoveryFlag) {
		return false, errors.New("we expected the key to be compressed, it wasn't")
	}

	// Verify that the signature is valid
	if err := Verify(signatureEncoded, publicKey, messageHash); err != nil {
		return false, err
	}

	// Get the hash from the public key, so we can check that address matches
	publicKeyHash := GeneratePublicKeyHash(recoveryFlag, publicKey)

	switch address.(type) {
	// Validate P2PKH
	case *btcutil.AddressPubKeyHash:
		ok, err := ValidateP2PKH(recoveryFlag, publicKeyHash, address, net)
		if err != nil {
			return VerifyBTCSignature(signedMessage, net, 1)
		}

		return ok, err
	// Validate P2SH
	case *btcutil.AddressScriptHash:
		ok, err := ValidateP2SH(recoveryFlag, publicKeyHash, address, net)
		if err != nil {
			return VerifyBTCSignature(signedMessage, net, 1)
		}

		return ok, err
	// Validate P2WPKH
	case *btcutil.AddressWitnessPubKeyHash:
		ok, err := ValidateP2WPKH(recoveryFlag, publicKeyHash, address, net)
		if err != nil {
			return VerifyBTCSignature(signedMessage, net, 1)
		}

		return ok, err
	// Validate P2TR
	case *btcutil.AddressTaproot:
		ok, err := ValidateP2TR(recoveryFlag, publicKey, address, net)
		if err != nil {
			return VerifyBTCSignature(signedMessage, net, 1)
		}

		return ok, err
	// Unsupported address
	default:
		return false, fmt.Errorf("unsupported address type '%s'", reflect.TypeOf(address))
	}
}

// VerifyWithChain will verify a SignedMessage based on the recovery flag on the passed network.
// Supported address types are P2PKH, P2WKH, NP2WKH (P2WPKH), P2TR.
func VerifyWithChain(signedMessage SignedMessage, net *chaincfg.Params) (bool, error) {
	return VerifyBTCSignature(signedMessage, net, 0)
}

// GeneratePublicKeyHash returns the public key hash, either compressed or uncompressed, depending on the recovery flag.
func GeneratePublicKeyHash(recoveryFlag int, publicKey *btcec.PublicKey) []byte {
	if Contains(Uncompressed(), recoveryFlag) {
		return btcutil.Hash160(publicKey.SerializeUncompressed())
	}

	return btcutil.Hash160(publicKey.SerializeCompressed())
}

func Contains(slice []int, val int) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}

	return false
}
