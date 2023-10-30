package cckat

import (
	"errors"
	"math/big"
)

var B58Alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

var b58table = [256]byte{
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 255, 255, 255, 255, 255, 255, 255, 9, 10, 11, 12, 13, 14, 15,
	16, 255, 17, 18, 19, 20, 21, 255, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 255, 255, 255, 255, 255,
	255, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 255, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54,
	55, 56, 57, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
}

var exp58 = [...]*big.Int{
	big.NewInt(1),
	big.NewInt(58),
	big.NewInt(58 * 58),
	big.NewInt(58 * 58 * 58),
	big.NewInt(58 * 58 * 58 * 58),
	big.NewInt(58 * 58 * 58 * 58 * 58),
	big.NewInt(58 * 58 * 58 * 58 * 58 * 58),
	big.NewInt(58 * 58 * 58 * 58 * 58 * 58 * 58),
	big.NewInt(58 * 58 * 58 * 58 * 58 * 58 * 58 * 58),
	big.NewInt(58 * 58 * 58 * 58 * 58 * 58 * 58 * 58 * 58),
	big.NewInt(58 * 58 * 58 * 58 * 58 * 58 * 58 * 58 * 58 * 58),
}

// Base58Encode encodes a byte array to Base58
func Base58Encode(input []byte) []byte {
	capas := len(input) + len(input)>>1 + 1
	res := make([]byte, capas)
	cb := capas - 1
	var cd int64
	x := new(big.Int).SetBytes(input)
	mod := new(big.Int)
	isnull := x.Sign() == 0
	for !isnull {
		x.DivMod(x, exp58[10], mod)
		isnull = x.Sign() == 0
		m := mod.Int64()
		for i := 0; i < 10; i++ {
			if isnull && m == 0 {
				break
			}
			cd = m % 58
			m = m / 58
			res[cb] = B58Alphabet[cd]
			cb--
		}
	}
	for _, b := range input {
		if b != 0 {
			break
		}
		res[cb] = B58Alphabet[0]
		cb--
	}
	return res[cb+1:]
}

// Base58Decode decodes Base58-encoded data
func Base58Decode(inp []byte) ([]byte, error) {
	ret := new(big.Int)
	tbig := new(big.Int)
	var z = 0
	var lz = true
	var count = 9
	var tres, c uint64 = 0, 0
	for i, d := range inp {
		if lz {
			if lz = d == B58Alphabet[0]; lz {
				z++
				continue
			}
		}
		if b58table[d] == 255 {
			return nil, errors.New("invalid base58 string")
		}
		c = uint64(b58table[d])
		tres = tres*58 + c
		count--
		if count < 0 || i == (len(inp)-1) {
			tbig.SetUint64(tres)
			ret.Mul(ret, exp58[9-count])
			ret.Add(ret, tbig)
			count = 9
			tres = 0
		}
	}
	rb := ret.Bytes()
	res := make([]byte, z, len(inp))
	res = append(res, rb...)
	return res, nil
}
