package cckat

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
	"log"
	"math/big"
	"strings"
)

var secp256k1 = Secp256k1()

type PrKey struct {
	k      big.Int
	a      AddressType
	uncomp bool
	isset  bool
}

var (
	PKeyOutOfR   = errors.New("private key out of range")
	CoordOutOfR  = errors.New("coordinate(s) out of range")
	NoSuchPoin   = errors.New("no such point exists")
	InvHexStr    = errors.New("invalid hex string")
	InvWIF       = errors.New("invalid WIF")
	InvPubKeyF   = errors.New("invalid public key format")
	InvWIFCSum   = errors.New("invalid WIF checksum")
	InvAddrType  = errors.New("invalid address type")
	BIP38InvCSum = errors.New("BIP38 checksum invalid")
	BIP38PassErr = errors.New("BIP38 wrong password")
)

// Set set k.k. to the value of key and returns k, nil. nil, PKeyOutOfR will be returned if k < 1 or k greater than the order of the base point - 1.
func (k *PrKey) Set(key big.Int) (*PrKey, error) {
	if key.Cmp(secp256k1.N) == -1 && key.Sign() == 1 {
		k.k = key
		k.isset = true
		return k, nil
	}
	return nil, PKeyOutOfR
}

// SetHex set k.k to the value of khex, interpreted as base 16 and returns k, error. khex must be 64 hex digits long and may be prefixed with "0X" or "0x".
// If error != nil, (nil, error) returned.
func (k *PrKey) SetHex(khex string) (*PrKey, error) {
	khex = strings.TrimSpace(khex)
	if khex[:2] == "0x" || khex[:2] == "0X" {
		khex = khex[2:]
	}
	if len(khex) == 64 && isHex(khex) {
		h, _ := new(big.Int).SetString(khex, 16)
		return k.Set(*h)
	}
	return nil, InvHexStr
}

// SetBytes interprets b as the bytes of a big-endian unsigned integer, sets k.k to that value, and returns k, error.
// If error != nil, (nil, error) returned.
func (k *PrKey) SetBytes(b []byte) (*PrKey, error) {
	return k.Set(*new(big.Int).SetBytes(b))
}

// SetWIF interprets w as the WIF private key, sets k.k to that value, and returns k, error.
// If error != nil, (nil, error) returned.
func (k *PrKey) SetWIF(w string) (*PrKey, error) {
	w = strings.TrimSpace(w)
	l := w[:1]
	d, err := Base58Decode([]byte(w))
	if err != nil {
		return nil, err
	}
	if !(((l == `K` || l == `L`) && len(d) == 38) || (l == `5` && len(d) == 37)) {
		return nil, InvWIF
	}
	csum := d[len(d)-4:]
	d = d[:len(d)-4]
	if string(csum) != string(checksum(d)) {
		return nil, InvWIFCSum
	}
	if l == `K` || l == `L` {
		d = d[:len(d)-1]
	} else {
		k.uncomp = true
	}
	return k.Set(*new(big.Int).SetBytes(d[1:]))
}

// SetBIP38 tries to decrypt the BIP38 encrypted private key w with a password p, sets k.k to its value and returns k, error.
// If error != nil, (nil, error) returned.
func (k *PrKey) SetBIP38(w, p string) (*PrKey, error) {
	w = strings.TrimSpace(w)
	t, err := Decrypt(w, p)
	if err != nil {
		return nil, err
	}
	k.SetUncomp(t.uncomp)
	return k.Set(t.k)
}

// SetAddressType sets k.a to t and returns k, error.
// If error != nil, (nil, error) returned.
func (k *PrKey) SetAddressType(t AddressType) (*PrKey, error) {
	if !checkAddressType(t) {
		return nil, InvAddrType
	}
	k.a = t
	return k, nil
}

// BIP38 returns the BIP38 encoded private key k.k.
func (k *PrKey) BIP38(p string) string {
	k.checkIsSet()
	return Encrypt(*k, p)
}

// Bytes returns the private key as 32 byte slice.
func (k *PrKey) Bytes() []byte {
	k.checkIsSet()
	return bytesFull(&k.k)
}

// WIF returns the private key in WIF format.
func (k *PrKey) WIF() string {
	k.checkIsSet()
	pk := bytesFull(&k.k)
	a := make([]byte, 1, 39)
	a[0] = 0x80
	a = append(a, pk...)
	if !k.uncomp {
		a = append(a, 0x01)
	}
	a = append(a, checksum(a)...)
	return string(Base58Encode(a))
}

// Hex returns the private key in HEX format.
func (k *PrKey) Hex() string {
	k.checkIsSet()
	return fmt.Sprintf("%X", bytesFull(&k.k))
}

// PubK returns the uncompressed public key
func (k *PrKey) PubK() []byte {
	k.checkIsSet()
	return PubKey(&k.k, true)
}

/*
func (k *PrKey) PubK() []byte {
	k.checkIsSet()
	return PubK(&k.k, true)
}


func (k *PrKey) PubKeyUncomp() []byte {
	return PubK(&k.k, true)
}
*/

// Address returns the address of the type k.a
func (k *PrKey) Address() (a string) {
	k.checkIsSet()
	a, _ = addresses[k.a](k.PubK())
	return
}

// AddressT returns an address of the given type
func (k *PrKey) AddressT(at AddressType) (a string) {
	k.checkIsSet()
	if !checkAddressType(at) {
		log.Fatal("Invalid address type.")
	}
	a, _ = addresses[at](k.PubK())
	return
}

func (k *PrKey) GetAddressType() AddressType {
	return k.a
}

func (k *PrKey) IsUncomp() bool {
	return k.uncomp
}

func (k *PrKey) SetUncomp(u bool) *PrKey {
	k.uncomp = u
	return k
}

func (k *PrKey) checkIsSet() {
	if !k.isset {
		log.Fatal("Private key not set.")
	}
}

func checkAddressType(t AddressType) bool {
	return t < MaxType
}

// PubKey returns the public key of the private key k in compressed format if comp == true or in uncompressed format if comp == false.
func PubKey(k *big.Int, uncomp bool) []byte {
	px, py := secp256k1.ScalarBaseMult(k.Bytes())
	bx := bytesFull(px)
	if uncomp {
		res := make([]byte, 1, 65)
		res[0] = 0x04
		by := bytesFull(py)
		res = append(res, bx...)
		return append(res, by...)
	}
	f := byte(0x2)
	if py.Bit(0) == 1 {
		f |= 0x1
	}
	res := make([]byte, 1, 33)
	res[1] = f
	return append(res, bx...)
}

// PubKeyCompUncomp returns public key in compressed format if comp == true or in uncompressed format if comp == false.
// k - public key in compressed or uncompressed format.
// Returns nil and InvPubKeyF error if the public key format is invalid.
// WARNING!!!  This function checks only the key format. If the point is not on the
// curve (or at infinity), the behavior is undefined. Use the IsOnCurve function to check this.
func PubKeyCompUncomp(k []byte, comp bool) ([]byte, error) {
	if k[0] == 0x04 && len(k) == 65 {
		if comp {
			f := byte(0x2)
			if k[64]&1 == 1 {
				f |= 0x1
			}
			res := make([]byte, 1, 33)
			res[0] = f
			return append(res, k[1:33]...), nil

		}
		return k, nil
	}
	if (k[0] == 0x03 || k[0] == 0x02) && len(k) == 33 {
		if comp {
			return k, nil
		}
		_, y := PointFromX(k[1:], k[0] == 0x2)
		ret := make([]byte, 1, 65)
		ret[0] = 0x4
		ret = append(ret, k[1:]...)
		return append(ret, bytesFull(y)...), nil
	}
	return nil, InvPubKeyF
}

// HashPubKey returns the Hash160 hash of the pubkey.
func HashPubKey(pubKey []byte) []byte {
	p := sha256.Sum256(pubKey)
	r := ripemd160.New()
	_, err := r.Write(p[:])
	if err != nil {
		return nil
	}
	return r.Sum(nil)
}

func checksum(p []byte) []byte {
	firstSHA := sha256.Sum256(p)
	secondSHA := sha256.Sum256(firstSHA[:])
	return secondSHA[:4]
}

// Keccak256Hash returns the legacy Keccak256 hash of data
func Keccak256Hash(data []byte) (h []byte) {
	w := sha3.NewLegacyKeccak256()
	w.Write(data)
	return w.Sum(nil)
}

// PointFromX returns the x and y coordinates of the point for which x coordinate and even/odd of y coordinate are given.
// WARNING!!! This function does not check is the coordinate valid and if the point exists.
// Use PointFromXc if yoy want to check.
func PointFromX(xb []byte, even bool) (x, y *big.Int) {
	x = new(big.Int).SetBytes(xb)
	y2 := y2fromx(x)
	y = y2.Exp(y2, p4Exp, secp256k1.P)
	if (y.Bit(0) == 1 && even) || (y.Bit(0) == 0 && !even) {
		y.Sub(secp256k1.P, y)
	}
	return
}

// PointFromXc returns the x and y coordinates of the point for which x coordinate and even/odd of y coordinate are given.
// If the point does not exist, an error will be returned
func PointFromXc(xb []byte, even bool) (*big.Int, *big.Int, error) {
	x := new(big.Int).SetBytes(xb)
	if x.Cmp(secp256k1.P) >= 0 {
		return nil, nil, CoordOutOfR
	}
	y2 := y2fromx(x)
	y := new(big.Int).Exp(y2, p4Exp, secp256k1.P)
	yc := new(big.Int).Mul(y, y)
	yc.Mod(yc, secp256k1.P)
	if y2.Cmp(yc) != 0 {
		return nil, nil, NoSuchPoin
	}
	if (y.Bit(0) == 1 && even) || (y.Bit(0) == 0 && !even) {
		y.Sub(secp256k1.P, y)
	}
	return x, y, nil
}

// Y^2 from X
func y2fromx(x *big.Int) *big.Int {
	y2 := new(big.Int).Mul(x, x)
	y2.Mul(y2, x)
	y2.Add(y2, secp256k1.B)
	return y2.Mod(y2, secp256k1.P)
}

func isHex(str string) bool {
	if len(str)%2 != 0 {
		return false
	}
	for _, c := range []byte(str) {
		if !isHexCharacter(c) {
			return false
		}
	}
	return true
}
func isHexCharacter(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

func bytesFull(r *big.Int) []byte {
	ra := r.Bytes()
	s := secp256k1.BitSize / 8
	if len(ra) < s {
		ras := make([]byte, s)
		copy(ras[s-len(ra):], ra)

		return ras
	}
	return ra
}
