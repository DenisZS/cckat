package cckat

import "strings"

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var gen = []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

// Bech32mencode encodes a segwit (Bech32 BIP 0173 / Bech32m BIP 0350) address.
func Bech32mencode(data []byte, hrp string, ver int) string {
	b32const := 1
	if ver > 0 {
		b32const = 0x2bc830a3
	}
	hrp = strings.ToLower(hrp)
	conv := Convbits85(data)
	d := make([]int, 1, len(conv)+7)
	d[0] = ver
	d = append(d, conv...)
	d = append(d, csum(hrp, d, b32const)...)
	var b strings.Builder
	b.Grow(len(d) + len(hrp) + 1)
	b.WriteString(hrp)
	b.WriteString("1")
	for _, v := range d {
		b.WriteByte(charset[v])
	}
	return b.String()
}

// Convbits85 converts a byte slice (8 bits) to int slice (5 bits).
func Convbits85(p []byte) []int {
	ret := make([]int, (len(p)*8+4)/5)
	var pos, b = 0, 8
	var data byte
	for i := 0; pos < len(p); {
		data = p[pos]
		if b > 5 {
			ret[i] = int((data >> (b - 5)) & 31)
			b -= 5
		} else {
			pos++
			if pos < len(p) {
				ret[i] = int(((data << (5 - b)) | (p[pos] >> (3 + b))) & 31)
			} else {
				ret[i] = int((data << (5 - b)) & 31)
			}
			b += 3
		}
		i++
	}
	return ret
}

func polymod(values []int) int {
	chk := 1
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ v
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func hrpExpand(hrp string) []int {
	ret := make([]int, len(hrp)*2+1)
	for i, c := range hrp {
		ret[i] = int(c >> 5)
	}
	for i, c := range hrp {
		ret[i+len(hrp)+1] = int(c & 31)
	}
	return ret
}

// csum returns 6 byte checksum
func csum(hrp string, data []int, mconst int) []int {
	h := hrpExpand(hrp)
	v := make([]int, len(h)+len(data)+6)
	copy(v, h)
	copy(v[len(h):], data)
	mod := polymod(v) ^ mconst
	ret := make([]int, 6)
	for p := 0; p < len(ret); p++ {
		ret[p] = (mod >> uint(5*(5-p))) & 31
	}
	return ret
}
