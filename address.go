package cckat

import (
	"crypto/sha256"
	"fmt"
	"math/big"
)

type AddressType uint

// Possible types of the addresses
const (
	P2PKH       AddressType = iota // Pay-to-pubkey-hash
	P2PKHUncomp                    // Pay-to-pubkey-hash (uncompressed pubkey)
	P2SH                           // Pay-to-script-hash
	P2WPKH                         // Pay-to-witness-pubkey-hash
	P2TR                           // Pay-to-taproot
	ETH                            // Ethereum address (mixed-case checksum)
	MaxType
)

// The array of functions of address. All functions accept a compressed or uncompressed public key.
var addresses = [MaxType]func([]byte) (string, error){
	P2PKH:       GetAddressP2PKH,
	P2PKHUncomp: GetAddressP2PKHUncomp,
	P2SH:        GetAddressP2SH,
	P2WPKH:      GetAddressP2WPKH,
	P2TR:        GetAddressP2TR,
	ETH:         GetAddressETH,
}

// GetAddressP2PKH returns the Pay-to-pubkey-hash Bitcoin address (compressed pubkey).
func GetAddressP2PKH(pubKey []byte) (string, error) {
	return getAddressP2PKH(pubKey, true)
}

// GetAddressP2PKHUncomp returns the Pay-to-pubkey-hash Bitcoin address (uncompressed pubkey).
func GetAddressP2PKHUncomp(pubKey []byte) (string, error) {
	return getAddressP2PKH(pubKey, false)
}

// getAddressP2PKH returns the Pay-to-pubkey-hash Bitcoin address (compressed or uncompressed pubkey).
func getAddressP2PKH(pubKey []byte, comp bool) (string, error) {
	p, err := PubKeyCompUncomp(pubKey, comp)
	if err != nil {
		return "", err
	}
	v := make([]byte, 1, 25)
	//v[0] = 0
	v = append(v, HashPubKey(p)...)
	//checksum := checksum(v)
	return string(Base58Encode(append(v, checksum(v)...))), nil
}

// GetAddressP2SH returns the Pay-to-script-hash Bitcoin address.
func GetAddressP2SH(pubKey []byte) (string, error) {
	p, err := PubKeyCompUncomp(pubKey, true)
	if err != nil {
		return "", err
	}
	v := make([]byte, 2, 22)
	v = []byte{0x00, 0x14}
	w := make([]byte, 1, 25)
	w[0] = 0x05
	w = append(w, HashPubKey(append(v, HashPubKey(p)...))...)
	w = append(w, checksum(w)...)
	return string(Base58Encode(w)), nil
}

// GetAddressP2WPKH returns the Pay-to-witness-pubkey-hash Bitcoin address.
func GetAddressP2WPKH(pubKey []byte) (string, error) {
	p, err := PubKeyCompUncomp(pubKey, true)
	if err != nil {
		return "", err
	}
	return Bech32mencode(HashPubKey(p), "bc", 0), nil
}

// GetAddressP2TR returns the Pay-to-taproot Bitcoin address with pubKey as internal key.
func GetAddressP2TR(pubKey []byte) (string, error) {
	pk, err := PubKeyCompUncomp(pubKey, false)
	if err != nil {
		return "", err
	}
	x := new(big.Int).SetBytes(pk[1:33])
	y := new(big.Int).SetBytes(pk[33:65])
	if y.Bit(0) == 1 {
		y.Sub(secp256k1.P, y)
	}
	tw := taggedHash("TapTweak", bytesFull(x))
	tx, ty := secp256k1.ScalarBaseMult(tw)
	qx, _ := secp256k1.Add(x, y, tx, ty)
	return Bech32mencode(bytesFull(qx), "bc", 1), nil
}

func taggedHash(tag string, b []byte) []byte {
	th := sha256.Sum256([]byte(tag))
	th1 := append(th[:], th[:]...)
	r := sha256.Sum256(append(th1, b...))
	return r[:]
}

// GetAddressETH returns the Ethereum address (mixed-case checksum).
func GetAddressETH(pubKey []byte) (string, error) {
	p, err := PubKeyCompUncomp(pubKey, false)
	if err != nil {
		return "", err
	}
	r := []byte(fmt.Sprintf("%x", Keccak256Hash(p[1:])[12:]))
	rh := Keccak256Hash(r)
	for i := 0; i < 40; i++ {
		if r[i] > 64 {
			r[i] ^= (rh[i/2] >> (7 - (i&1)*4) & 1) << 5
		}
	}
	return "0x" + string(r), nil
}
