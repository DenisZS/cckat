// Copyright (c) 2020 DZ. All rights reserved.
// Copyright (c) 2009 The Go Authors. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above
//   copyright notice, this list of conditions and the following disclaimer
//   in the documentation and/or other materials provided with the
//   distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package cckat

import (
	"math/big"
)

var three = new(big.Int).SetUint64(3)
var seven = new(big.Int).SetUint64(7)

// (p+1)/4
var p4Exp, _ = new(big.Int).SetString("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFF0C", 16)

type Secp256k1C struct {
	P       *big.Int // the order of the underlying field
	N       *big.Int // the order of the base point
	B       *big.Int // the constant of the Secp256k1C equation
	Gx, Gy  *big.Int // (x,y) of the base point
	BitSize int      // the size of the underlying field
}

func Secp256k1() *Secp256k1C {
	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	n, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	gx, _ := new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	gy, _ := new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	return &Secp256k1C{
		P:       p,
		N:       n,
		B:       seven,
		Gx:      gx,
		Gy:      gy,
		BitSize: 256,
	}
}

// IsOnCurve returns true if the given (x,y) lies on the BitCurve.
func (curve *Secp256k1C) IsOnCurve(x, y *big.Int) bool {
	var y2, x3 big.Int
	y2.Mul(y, y)
	y2.Mod(&y2, curve.P)
	x3.Mul(x, x)
	x3.Mul(&x3, x)
	x3.Add(&x3, curve.B)
	x3.Mod(&x3, curve.P)
	return x3.Cmp(&y2) == 0
}

func (curve *Secp256k1C) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	z1 := zForAffine(x1, y1)
	return curve.affineFromJacobian(curve.doubleJacobian(x1, y1, z1))
}

// zForAffine returns a Jacobian Z value for the affine point (x, y). If x and
// y are zero, it assumes that they represent the point at infinity because (0,
// 0) is not on any of the curves handled here.
func zForAffine(x, y *big.Int) *big.Int {
	z := new(big.Int)
	if x.Sign() != 0 || y.Sign() != 0 {
		z.SetInt64(1)
	}
	return z
}

// affineFromJacobian reverses the Jacobian transform. See the comment at the
// top of the file. If the point is ∞ it returns 0, 0.
func (curve *Secp256k1C) affineFromJacobian(x, y, z *big.Int) (xOut, yOut *big.Int) {
	if z.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}

	zinv := new(big.Int).ModInverse(z, curve.P)
	zinvsq := new(big.Int).Mul(zinv, zinv)

	xOut = new(big.Int).Mul(x, zinvsq)
	xOut.Mod(xOut, curve.P)
	zinvsq.Mul(zinvsq, zinv)
	yOut = new(big.Int).Mul(y, zinvsq)
	yOut.Mod(yOut, curve.P)
	return
}

func (curve *Secp256k1C) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	z1 := zForAffine(x1, y1)
	z2 := zForAffine(x2, y2)
	return curve.affineFromJacobian(curve.addJacobian(x1, y1, z1, x2, y2, z2))
}

// addJacobian takes two points in Jacobian coordinates, (x1, y1, z1) and
// (x2, y2, z2) and returns their sum, also in Jacobian form.
func (curve *Secp256k1C) addJacobian(x1, y1, z1, x2, y2, z2 *big.Int) (*big.Int, *big.Int, *big.Int) {
	// See http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
	x3, y3, z3 := new(big.Int), new(big.Int), new(big.Int)
	if z1.Sign() == 0 {
		x3.Set(x2)
		y3.Set(y2)
		z3.Set(z2)
		return x3, y3, z3
	}
	if z2.Sign() == 0 {
		x3.Set(x1)
		y3.Set(y1)
		z3.Set(z1)
		return x3, y3, z3
	}

	z1z1 := new(big.Int).Mul(z1, z1)
	z1z1.Mod(z1z1, curve.P)
	z2z2 := new(big.Int).Mul(z2, z2)
	z2z2.Mod(z2z2, curve.P)

	u1 := new(big.Int).Mul(x1, z2z2)
	u1.Mod(u1, curve.P)
	u2 := new(big.Int).Mul(x2, z1z1)
	u2.Mod(u2, curve.P)
	h := new(big.Int).Sub(u2, u1)
	xEqual := h.Sign() == 0
	if h.Sign() == -1 {
		h.Add(h, curve.P)
	}
	i := new(big.Int).Lsh(h, 1)
	i.Mul(i, i)
	j := new(big.Int).Mul(h, i)

	s1 := new(big.Int).Mul(y1, z2)
	s1.Mul(s1, z2z2)
	s1.Mod(s1, curve.P)
	s2 := new(big.Int).Mul(y2, z1)
	s2.Mul(s2, z1z1)
	s2.Mod(s2, curve.P)
	r := new(big.Int).Sub(s2, s1)
	if r.Sign() == -1 {
		r.Add(r, curve.P)
	}
	yEqual := r.Sign() == 0
	if xEqual && yEqual {
		return curve.doubleJacobian(x1, y1, z1)
	}
	r.Lsh(r, 1)
	v := new(big.Int).Mul(u1, i)

	x3.Set(r)
	x3.Mul(x3, x3)
	x3.Sub(x3, j)
	x3.Sub(x3, v)
	x3.Sub(x3, v)
	x3.Mod(x3, curve.P)

	y3.Set(r)
	v.Sub(v, x3)
	y3.Mul(y3, v)
	s1.Mul(s1, j)
	s1.Lsh(s1, 1)
	y3.Sub(y3, s1)
	y3.Mod(y3, curve.P)

	z3.Add(z1, z2)
	z3.Mul(z3, z3)
	z3.Sub(z3, z1z1)
	z3.Sub(z3, z2z2)
	z3.Mul(z3, h)
	z3.Mod(z3, curve.P)

	return x3, y3, z3
}

func (curve *Secp256k1C) ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
	Bz := new(big.Int).SetInt64(1)
	x, y, z := new(big.Int), new(big.Int), new(big.Int)

	for _, b := range k {
		for bitNum := 0; bitNum < 8; bitNum++ {
			x, y, z = curve.doubleJacobian(x, y, z)
			if b&0x80 == 0x80 {
				x, y, z = curve.addJacobian(Bx, By, Bz, x, y, z)
			}
			b <<= 1
		}
	}
	return curve.affineFromJacobian(x, y, z)
}

func (curve *Secp256k1C) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return curve.ScalarMult(curve.Gx, curve.Gy, k)
}

func (curve *Secp256k1C) Params() *Secp256k1C {
	return curve
}

// doubleJacobian takes a point in Jacobian coordinates, (x, y, z), and
// returns its double, also in Jacobian form.
func (curve *Secp256k1C) doubleJacobian(x, y, z *big.Int) (*big.Int, *big.Int, *big.Int) {
	// See http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l

	a := new(big.Int).Mul(x, x) //X1²
	b := new(big.Int).Mul(y, y) //Y1²
	c := new(big.Int).Mul(b, b) //B²

	d := new(big.Int).Add(x, b) //X1+B
	d.Mul(d, d)                 //(X1+B)²
	d.Sub(d, a)                 //(X1+B)²-A
	d.Sub(d, c)                 //(X1+B)²-A-C
	d.Lsh(d, 1)                 //Mul(d, big.NewInt(2))     //2*((X1+B)²-A-C)

	e := new(big.Int).Mul(three, a) //3*A
	f := new(big.Int).Mul(e, e)     //E²

	x3 := new(big.Int).Lsh(d, 1) //Mul(big.NewInt(2), d) //2*D
	x3.Sub(f, x3)                //F-2*D
	x3.Mod(x3, curve.P)

	y3 := new(big.Int).Sub(d, x3) //D-X3
	y3.Mul(e, y3)                 //E*(D-X3)
	y3.Sub(y3, c.Lsh(c, 3))       // y3.Sub(y3, new(big.Int).Mul(big.NewInt(8), c)) //E*(D-X3)-8*C
	y3.Mod(y3, curve.P)

	z3 := new(big.Int).Mul(y, z) //Y1*Z1
	z3.Lsh(z3, 1)                // Mul(big.NewInt(2), z3)    //3*Y1*Z1
	z3.Mod(z3, curve.P)
	return x3, y3, z3
}
