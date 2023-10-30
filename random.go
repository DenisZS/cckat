package cckat

import (
	cr "crypto/rand"
	"io"
	"log"
	"math/big"
)

var one = new(big.Int).SetInt64(1)

// RandFieldElement returns a random element of the field underlying the given
// curve using the procedure given in [NSA] A.2.1.
//
// Implementation copied from Go's crypto/ecdsa package since the function wasn't public.
func RandFieldElement(rand io.Reader) (k *big.Int, err error) {
	b, err := getRand(rand)
	if err != nil {
		return
	}
	k = fieldElement(b)
	return
}

// RandFieldElementEx returns a random element of the field.
// It obtains input from two of sources (rand io.Reader and ex []byte) and mixes them.
// See https://datatracker.ietf.org/doc/html/rfc4086#section-5.1
//
// Returned RandFieldElement(rand) if len(ex) == 0
func RandFieldElementEx(rand io.Reader, ex []byte) (k *big.Int, err error) {
	if len(ex) == 0 {
		k, err = RandFieldElement(rand)
		return
	}
	b, err := getRand(rand)
	if err != nil {
		return
	}
	be, err := exRand(rand, ex, len(b))
	if err != nil {
		return
	}
	for i := range b {
		b[i] ^= be[i]
	}
	k = fieldElement(b)
	return
}

func getRand(rand io.Reader) (b []byte, err error) {
	b = make([]byte, secp256k1.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	return
}

func fieldElement(b []byte) (k *big.Int) {
	k = new(big.Int)
	k.SetBytes(b)
	n := new(big.Int).Sub(secp256k1.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

// exRand returns []byte of size s.
// The bytes of this slice are the result of the XOR operation on a random number (1-256) of random bytes of slice b.
// Used as a second source for mixing for RandFieldElementEx.
func exRand(rand io.Reader, b []byte, s int) (e []byte, err error) {
	l := new(big.Int).SetInt64(int64(len(b)))
	e = make([]byte, s)
	nb := make([]byte, s)
	_, err = io.ReadFull(rand, nb)
	if err != nil {
		return
	}
	for i, n := range nb {
		ni := int(n) + 1
		for ii := 0; ii < ni; ii++ {
			pb, err := cr.Int(rand, l)
			if err != nil {
				log.Fatal(err)
			}
			e[i] ^= b[pb.Int64()]
		}
	}
	return
}
