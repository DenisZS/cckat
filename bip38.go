package cckat

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"golang.org/x/crypto/scrypt"
)

// Encrypt returns the encrypted private key (BIP038) for the private key k. (no EC multiply).
func Encrypt(k PrKey, passphrase string) string {
	if k.uncomp {
		k.SetAddressType(P2PKHUncomp)
	} else {
		k.SetAddressType(P2PKH)
	}
	ah := checksum([]byte(k.Address()))
	dh, _ := scrypt.Key([]byte(passphrase), ah, 16384, 8, 8, 64)
	var flag byte = 0xE0
	if k.uncomp {
		flag = 0xC0
	}

	data := encrypt(k.Bytes(), dh[:32], dh[32:])
	buf := make([]byte, 3, 43)
	buf = []byte{0x01, 0x42, flag}
	buf = append(buf, ah...)
	buf = append(buf, data...)
	buf = append(buf, checksum(buf)...)
	encryptWif := Base58Encode(buf)

	return string(encryptWif)

}

// Decrypt BIP38 string which does not have the ECMultiply flag set
func Decrypt(b, password string) (*PrKey, error) {
	bk, _ := Base58Decode([]byte(b))
	flag := bk[2]
	h := bk[3:7]
	data := bk[7:]
	if !bytes.Equal(checksum(bk[:len(bk)-4]), data[len(data)-4:]) {
		return nil, BIP38InvCSum
	}
	dh, err := scrypt.Key([]byte(password), h, 16384, 8, 8, 64)
	if err != nil {
		return nil, err
	}
	p := decrypt(data, dh[:32], dh[32:])
	pk, err := new(PrKey).SetBytes(p)
	if err != nil {
		return nil, err
	}
	if flag == 0xC0 {
		pk.SetAddressType(P2PKHUncomp)
		pk.uncomp = true
	} else {
		pk.SetAddressType(P2PKH)
	}
	fmt.Println()
	if !bytes.Equal(h, checksum([]byte(pk.Address()))) {
		return nil, BIP38PassErr
	}
	return pk, nil
}

func encrypt(pk, dh1, dh2 []byte) (dst []byte) {
	c, _ := aes.NewCipher(dh2)
	for i := 0; i < len(dh1); i++ {
		dh1[i] ^= pk[i]
	}
	dst = make([]byte, 48)
	c.Encrypt(dst, dh1[:16])
	c.Encrypt(dst[16:], dh1[16:])
	dst = dst[:32]
	return
}

// AES256 Decryption
func decrypt(src, dh1, dh2 []byte) (pk []byte) {
	c, _ := aes.NewCipher(dh2)
	pk = make([]byte, 48)
	c.Decrypt(pk, src[:16])
	c.Decrypt(pk[16:], src[16:])
	pk = pk[:32]
	for i := range pk {
		pk[i] ^= dh1[i]
	}
	return
}
