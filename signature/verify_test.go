package signature

import (
	"encoding/base64"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

const (
	message                          = "hello world"
	wallet_unisat_taproot_mainnet    = "bc1pead7k9rdu4ged9q7qt2hqcxr6sx2jvxp7z86tqa8a9tncct657dq6cn4y7"
	unisat_taproot_signature_mainnet = "G3loPvTHNcZ8DrPBthoq/VEYoEaH3XXQN4T5gXa5RgG9DHlAn4QFk3oqIjEntXo8CHNoynoH1AF4BMBbXHDWMT4="

	wallet_unisat_nativesegwit_mainnet    = "bc1qp290l5642zjpj0arcqrqjfnk9sm99gcx4egdxg"
	unisat_nativesegwit_signature_mainnet = "HK0zjJT1BNzVyfuY02aPzVLNf71mlw0DQIkKX+iyCOJkKf5CeH8T07xkj+qggmSqy7HliylMd1GKq+b5xlOzHME="

	wallet_unisat_nestedsegwit_mainnet    = "3Pk3gGKJmftjgDc4ykhXRZKkvf7PSwhfwa"
	unisat_nestedsegwit_signature_mainnet = "G34VIXQLfn0BQpdQRVw8zqLXc0F2BZzEjtkqmwsHIngPE80EKKsYcxPzQ/emI5ejG/FkKCViRKG809tcHUR8fbU="

	wallet_unisat_legacy_mainnet    = "1DFox8Q22CAftbgPJwKAA2PZ446ARuepnP"
	unisat_legacy_signature_mainnet = "HC4YrhY0qTsgGlOGRmSzHzwRTUsYIFjkiKRlIffhXV/kUQWAAYG9NDjV441JlwsbqR7WUNrqGGqMcbfTGaa66Z8="

	wallet_unisat_taproot_testnet    = "tb1pead7k9rdu4ged9q7qt2hqcxr6sx2jvxp7z86tqa8a9tncct657dqds9673"
	unisat_taproot_signature_testnet = "HBapBhmp8LcqF+9Nej4nnNvCaLdIQvD1qH27UaNSaq7hCYWsXBRO92mv8tHbv1iPJwkAb+EqXdmDyILd+NxGGf8="

	wallet_unisat_nativesegwit_testnet    = "tb1qp290l5642zjpj0arcqrqjfnk9sm99gcxlln7am"
	unisat_nativesegwit_signature_testnet = "G+UOhPKmZOyfIbiZ3Mv7QQ2fHZ0RntihWbZ46//PCvaOYvYze+Dgb4epd49NbN3RWuKayJxGD1o8oq8Kq54Mgl0="

	wallet_unisat_legacy_testnet    = "msmmFBUzqDbvfiA12WHXywbsv3gsKd1Kke"
	unisat_legacy_signature_testnet = "G3HjU+tnrcmlwnQ7n7q6tToXgk1gcDa1nfxoFumKpQ03aKe4/ymiI7YHvnonnZNa4hKtfvazYXkq2VVtL/Wky2I="

	wallet_unisat_nestedsegwit_testnet    = "2NFJFk1FLP8Q5t1EcetKQ3WK291KZEoUPbm"
	unisat_nestedsegwit_signature_testnet = "G0lDvE3WkasJk33EPH2tFyRCb0I3eEtkHQhqmHGOarG7ODaG5VXQ0Ziclz8naiYbThF20qNJnWgjlzinBuIMZR8="

	wallet_unisat_taproot_mainnet_fail    = "bc1pead7k9rdu4ged9q7qt2hqcxr6sx2jvxp7z86tqa8a9tncct657dq6cn4y71"
	unisat_taproot_signature_mainnet_fail = "G3loPvTHNcZ8DrPBthoq/VEYoEaH3XXQN4T5gXa5RgG9DHlAn4QFk3oqIjEntXo8CHNoynoH1AF4BMBbXHDWMT4=aa"

	wallet_okx_taproot_mainnet    = "bc1prx22p25nvvf5sjvuvdzek095eahmnl5mfapxf4vec94nkm3g49hsf0tg9y"
	okx_taproot_signature_mainnet = "IOIzS2zyKFXyyTP2ZJP5E18bENjlYNHvzbqHHn9muz/6XkuumgcvlyWaSprT7yfNDLPQ6o+IoAEd+wc48iwtGE4="

	wallet_okx_legacy_mainnet    = "12u8y8GbAwZezip25KLpJTPzcuUBTHNbT3"
	okx_legacy_signature_mainnet = "H/Q3xf1Lr1/gMoSLQQec16+gdT8mg/es7X6rFgC2x30FTkU3LxGHkXHEPzke4i3Lmn8EwIhr6zopacWFkgfgKdU="

	wallet_okx_nativesegwit_mainnet    = "bc1qtqnuww423nacmj0d2705qm6r72hqneavvs2gmx"
	okx_nativesegwit_signature_mainnet = "IMW7tLuVMPDcRvA86QQZn912WDUTVbEsaFU/QF8uy3xcMaJZk/Xomwvr6BFiOvIB9qqPHjc02eH2xc0mhF0KtKM="

	wallet_okx_nestedsegwit_mainnet    = "3MTbJEyWaNsYVjRzcjUCc34yoxE5CNZKm4"
	okx_nestedsegwit_signature_mainnet = "H/Or+rgO5LA3UrajQU+lzaoWPhXFyCsepmV4r5gebwKnS3WDb4Vc4XgtHXT/NIejO8gfPQNFEa+dEKCgnNMztPo="

	unisat_nativesegwit_signature_mainnet_fail = "HK0zjJT1BNzVyfuY02aPzVLNf71mlw0DQIkKX+iyCOJkKf5CeH8T07xkj+qggmSqy7HliylMd1GKq+b5xlOzHME=aa"

	unisat_nestedsegwit_signature_mainnet_fail = "G34VIXQLfn0BQpdQRVw8zqLXc0F2BZzEjtkqmwsHIngPE80EKKsYcxPzQ/emI5ejG/FkKCViRKG809tcHUR8fbU=aa"

	unisat_legacy_signature_mainnet_fail = "HC4YrhY0qTsgGlOGRmSzHzwRTUsYIFjkiKRlIffhXV/kUQWAAYG9NDjV441JlwsbqR7WUNrqGGqMcbfTGaa66Z8=aa"

	unisat_taproot_signature_testnet_fail = "HBapBhmp8LcqF+9Nej4nnNvCaLdIQvD1qH27UaNSaq7hCYWsXBRO92mv8tHbv1iPJwkAb+EqXdmDyILd+NxGGf8=aa"

	unisat_nativesegwit_signature_testnet_fail = "G+UOhPKmZOyfIbiZ3Mv7QQ2fHZ0RntihWbZ46//PCvaOYvYze+Dgb4epd49NbN3RWuKayJxGD1o8oq8Kq54Mgl0=aa"

	unisat_legacy_signature_testnet_fail = "G3HjU+tnrcmlwnQ7n7q6tToXgk1gcDa1nfxoFumKpQ03aKe4/ymiI7YHvnonnZNa4hKtfvazYXkq2VVtL/Wky2I=aa"

	unisat_nestedsegwit_signature_testnet_fail = "G0lDvE3WkasJk33EPH2tFyRCb0I3eEtkHQhqmHGOarG7ODaG5VXQ0Ziclz8naiYbThF20qNJnWgjlzinBuIMZR8=aa"

	invalid         = "INVALID"
	wrong_signature = "IOIzS2zyKFXyyTP2ZJP5E18bENjlYNHvzbqHHn9muz/6XkuumgcvlyWaSprT7yfNDLPQ6o+IoAEd+wc48iwtGE4="
)

type Wallet struct {
	address   string
	signature string
	network   *chaincfg.Params
}

func TestVerifyUnisatWallet(t *testing.T) {
	wallets := []Wallet{
		{
			address:   wallet_unisat_taproot_testnet,
			signature: unisat_taproot_signature_testnet,
			network:   &chaincfg.TestNet3Params,
		},
		{
			address:   wallet_unisat_nativesegwit_testnet,
			signature: unisat_nativesegwit_signature_testnet,
			network:   &chaincfg.TestNet3Params,
		},
		{
			address:   wallet_unisat_legacy_testnet,
			signature: unisat_legacy_signature_testnet,
			network:   &chaincfg.TestNet3Params,
		},
		{
			address:   wallet_unisat_nestedsegwit_testnet,
			signature: unisat_nestedsegwit_signature_testnet,
			network:   &chaincfg.TestNet3Params,
		},
		{
			address:   wallet_unisat_taproot_mainnet,
			signature: unisat_taproot_signature_mainnet,
			network:   &chaincfg.MainNetParams,
		},
		{
			address:   wallet_unisat_nativesegwit_mainnet,
			signature: unisat_nativesegwit_signature_mainnet,
			network:   &chaincfg.MainNetParams,
		},
		{
			address:   wallet_unisat_nestedsegwit_mainnet,
			signature: unisat_nestedsegwit_signature_mainnet,
			network:   &chaincfg.MainNetParams,
		},
		{
			address:   wallet_unisat_legacy_mainnet,
			signature: unisat_legacy_signature_mainnet,
			network:   &chaincfg.MainNetParams,
		},
	}

	for _, test := range wallets {
		ok, err := VerifyWithChain(SignedMessage{
			Address:   test.address,
			Message:   message,
			Signature: test.signature,
		}, test.network)

		if err != nil {
			t.Error(err)
		}

		require.Equal(t, true, ok)
	}
}

func TestVerifyOKXWallet(t *testing.T) {
	okxWallet := []Wallet{
		{
			address:   wallet_okx_taproot_mainnet,
			signature: okx_taproot_signature_mainnet,
			network:   &chaincfg.MainNetParams,
		},
		{
			address:   wallet_okx_nativesegwit_mainnet,
			signature: okx_nativesegwit_signature_mainnet,
			network:   &chaincfg.MainNetParams,
		},
		{
			address:   wallet_okx_legacy_mainnet,
			signature: okx_legacy_signature_mainnet,
			network:   &chaincfg.MainNetParams,
		},
		{
			address:   wallet_okx_nestedsegwit_mainnet,
			signature: okx_nestedsegwit_signature_mainnet,
			network:   &chaincfg.MainNetParams,
		},
	}

	for _, test := range okxWallet {
		ok, err := VerifyWithChain(SignedMessage{
			Address:   test.address,
			Message:   message,
			Signature: test.signature,
		}, test.network)

		if err != nil {
			t.Error(err)
		}

		require.Equal(t, true, ok)
	}
}

func TestVerifyFailureAddressMismatched(t *testing.T) {
	wallet := []Wallet{
		{
			address:   wallet_unisat_taproot_testnet,
			signature: unisat_nativesegwit_signature_testnet,
			network:   &chaincfg.TestNet3Params,
		},
		{
			address:   wallet_unisat_taproot_mainnet,
			signature: unisat_nativesegwit_signature_mainnet,
			network:   &chaincfg.MainNetParams,
		},
		{
			address:   wallet_unisat_nativesegwit_testnet,
			signature: unisat_taproot_signature_testnet,
			network:   &chaincfg.TestNet3Params,
		},
		{
			address:   wallet_unisat_nativesegwit_mainnet,
			signature: unisat_taproot_signature_mainnet,
			network:   &chaincfg.MainNetParams,
		},
		{
			address:   wallet_unisat_nestedsegwit_testnet,
			signature: unisat_legacy_signature_testnet,
			network:   &chaincfg.TestNet3Params,
		},
		{
			address:   wallet_unisat_nestedsegwit_mainnet,
			signature: unisat_legacy_signature_mainnet,
			network:   &chaincfg.MainNetParams,
		},
		{
			address:   wallet_unisat_legacy_testnet,
			signature: unisat_nestedsegwit_signature_testnet,
			network:   &chaincfg.TestNet3Params,
		},
		{
			address:   wallet_unisat_legacy_mainnet,
			signature: unisat_nestedsegwit_signature_mainnet,
			network:   &chaincfg.MainNetParams,
		},
	}
	for _, test := range wallet {
		ok, err := VerifyWithChain(SignedMessage{
			Address:   test.address,
			Message:   message,
			Signature: test.signature,
		}, test.network)

		require.Equal(t, err, fmt.Errorf("address mismatched"))
		require.Equal(t, false, ok)
	}
}

func TestVerifyWrongSignature(t *testing.T) {
	wallet := []Wallet{
		{
			address:   wallet_unisat_taproot_testnet,
			signature: unisat_taproot_signature_testnet_fail,
			network:   &chaincfg.TestNet3Params,
		},
		{
			address:   wallet_unisat_taproot_mainnet,
			signature: unisat_taproot_signature_mainnet_fail,
			network:   &chaincfg.MainNetParams,
		},
		{
			address:   wallet_unisat_nativesegwit_testnet,
			signature: unisat_nativesegwit_signature_testnet_fail,
			network:   &chaincfg.TestNet3Params,
		},
		{
			address:   wallet_unisat_nativesegwit_mainnet,
			signature: unisat_nativesegwit_signature_mainnet_fail,
			network:   &chaincfg.MainNetParams,
		},
		{
			address:   wallet_unisat_nestedsegwit_testnet,
			signature: unisat_nestedsegwit_signature_testnet_fail,
			network:   &chaincfg.TestNet3Params,
		},
		{
			address:   wallet_unisat_nestedsegwit_mainnet,
			signature: unisat_nestedsegwit_signature_mainnet_fail,
			network:   &chaincfg.MainNetParams,
		},
		{
			address:   wallet_unisat_legacy_testnet,
			signature: unisat_legacy_signature_testnet_fail,
			network:   &chaincfg.TestNet3Params,
		},
		{
			address:   wallet_unisat_legacy_mainnet,
			signature: unisat_legacy_signature_mainnet_fail,
			network:   &chaincfg.MainNetParams,
		},
	}

	for _, test := range wallet {
		ok, err := VerifyWithChain(SignedMessage{
			Address:   test.address,
			Message:   message,
			Signature: test.signature,
		}, test.network)

		require.Equal(t, err, base64.CorruptInputError(88))
		require.Equal(t, false, ok)
	}
}

func TestVerifyWrongAddress(t *testing.T) {
	wallet := Wallet{
		address:   wallet_unisat_taproot_mainnet_fail,
		signature: unisat_taproot_signature_mainnet,
		network:   &chaincfg.MainNetParams,
	}

	ok, err := VerifyWithChain(SignedMessage{
		Address:   wallet.address,
		Message:   message,
		Signature: wallet.signature,
	}, wallet.network)

	assert.EqualError(t, err, "could not decode address: checksum mismatch")
	assert.Equal(t, false, ok)
}

func TestVerifyInvalidAddress(t *testing.T) {
	wallet := Wallet{
		address:   invalid,
		signature: unisat_taproot_signature_mainnet,
		network:   &chaincfg.MainNetParams,
	}

	ok, err := VerifyWithChain(SignedMessage{
		Address:   wallet.address,
		Message:   message,
		Signature: wallet.signature,
	}, wallet.network)

	assert.EqualError(t, err, "could not decode address: decoded address is of unknown format")
	assert.Equal(t, false, ok)
}

func TestVerifyWrongGeneratedSignature(t *testing.T) {
	wallet := Wallet{
		address:   wallet_unisat_taproot_mainnet,
		signature: wrong_signature,
		network:   &chaincfg.MainNetParams,
	}

	ok, err := VerifyWithChain(SignedMessage{
		Address:   wallet.address,
		Message:   message,
		Signature: wallet.signature,
	}, wallet.network)

	assert.EqualError(t, err, "address mismatched")
	assert.Equal(t, false, ok)
}
