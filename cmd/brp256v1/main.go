// Copyright (c) 2023, Pedro Albanese. All rights reserved.
// Use of this source code is governed by a ISC license that
// can be found in the LICENSE file.
package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/sha3"
	"hash"
	"io"
	"log"
	"math/big"
	"os"
	"strings"

	"github.com/pedroalbanese/brp256v1"
	"github.com/pedroalbanese/randomart"
)

var (
	bit    = flag.Int("bits", 128, "Shared secret bit-length.")
	dec    = flag.Bool("decrypt", false, "Decrypt with Privatekey.")
	derive = flag.Bool("derive", false, "Derive shared secret.")
	enc    = flag.Bool("encrypt", false, "Encrypt with Publickey.")
	key    = flag.String("key", "", "Private/Public key depending on operation.")
	keygen = flag.Bool("keygen", false, "Generate keypair.")
	public = flag.String("pub", "", "Remote's side Public key. (for ECDH)")
	sig    = flag.String("signature", "", "Signature.")
	sign   = flag.Bool("sign", false, "Sign with Private key.")
	verify = flag.Bool("verify", false, "Verify with Public key.")
)

func main() {
	flag.Parse()

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "SETH Cryptosystem (c) 2020-2023 - ALBANESE Research Lab")
		fmt.Fprintln(os.Stderr, "256-bit prime field Weierstrass y^2=x^3+ax+b ECDHE Tool\n")
		fmt.Fprintln(os.Stderr, "Usage of", os.Args[0]+":")
		flag.PrintDefaults()
		os.Exit(1)
	}

	var privatekey *ecdsa.PrivateKey
	var pubkey ecdsa.PublicKey
	var pub *ecdsa.PublicKey
	var err error
	var pubkeyCurve elliptic.Curve

	pubkeyCurve = brp.P256()

	if *keygen {
		if *key != "" {
			privatekey, err = ReadPrivateKeyFromHex(*key)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			privatekey = new(ecdsa.PrivateKey)
			privatekey, err = ecdsa.GenerateKey(pubkeyCurve, rand.Reader)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			if len(WritePrivateKeyToHex(privatekey)) != 64 {
				log.Fatal("Private key too short!")
				os.Exit(1)
			}
		}
		pubkey = privatekey.PublicKey
		fmt.Println("Private= " + WritePrivateKeyToHex(privatekey))
		fmt.Println("Public= " + WritePublicKeyToHex(&pubkey))
		os.Exit(0)
	}

	if *derive {
		private, err := ReadPrivateKeyFromHex(*key)
		if err != nil {
			log.Fatal(err)
		}
		public, err := ReadPublicKeyFromHex(*public)
		if err != nil {
			log.Fatal(err)
		}

		b, _ := public.Curve.ScalarMult(public.X, public.Y, private.D.Bytes())
		Sum256 := func(msg []byte) []byte {
			res := sha3.NewLegacyKeccak256()
			res.Write(msg)
			hash := res.Sum(nil)
			return []byte(hash)
		}

		shared := Sum256(b.Bytes())
		fmt.Printf("Shared= %x\n", shared[:*bit/8])
		os.Exit(0)
	}

	if *enc {
		public, err := ReadPublicKeyFromHexX(*key)
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		scanner := string(buf.Bytes())
		ciphertxt, err := EncryptAsn1(public, []byte(scanner), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", ciphertxt)
		os.Exit(0)
	}

	if *dec {
		private, err := ReadPrivateKeyFromHexX(*key)
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		scanner := string(buf.Bytes())
		str := string(scanner)
		plaintxt, err := DecryptAsn1(private, []byte(str))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", plaintxt)
		os.Exit(0)
	}

	if *sign {
		var h hash.Hash
		h = sha3.NewLegacyKeccak256()

		if _, err := io.Copy(h, os.Stdin); err != nil {
			panic(err)
		}

		privatekey, err = ReadPrivateKeyFromHex(*key)
		if err != nil {
			log.Fatal(err)
		}

		signature, err := Sign(h.Sum(nil), privatekey)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%x\n", signature)
		os.Exit(0)
	}

	if *verify {
		var h hash.Hash
		h = sha3.NewLegacyKeccak256()

		if _, err := io.Copy(h, os.Stdin); err != nil {
			panic(err)
		}

		pub, err = ReadPublicKeyFromHex(*key)
		if err != nil {
			log.Fatal(err)
		}

		sig, _ := hex.DecodeString(*sig)

		verifystatus := Verify(h.Sum(nil), sig, pub)
		fmt.Println(verifystatus)
		if verifystatus {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *public != "" {
		pub, err = ReadPublicKeyFromHex(*public)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Public Key:")
		fmt.Printf("X: %X\n", pub.X)
		fmt.Printf("Y: %X\n", pub.Y)
		print(" ", len(WritePublicKeyToHex(pub))/2, " bytes ", len(WritePublicKeyToHex(pub))*4, " bits\n")
		splitz := SplitSubN(WritePublicKeyToHex(pub), 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 60) {
			fmt.Printf("  %-10s  \n", strings.ToUpper(chunk))
		}
		fmt.Println(randomart.FromString(*public))
		if validateECPublicKey(pubkeyCurve, pub.X, pub.Y) {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *key != "" {
		privatekey, _ = ReadPrivateKeyFromHex(*key)
		pubkey = privatekey.PublicKey
		fmt.Println("Private Key:")

		fmt.Printf("D: %X\n", privatekey.D)
		print(" ", len(WritePrivateKeyToHex(privatekey))/2, " bytes ", len(WritePrivateKeyToHex(privatekey))*4, " bits\n")
		splitx := SplitSubN(WritePrivateKeyToHex(privatekey), 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitx), "[]"), 60) {
			fmt.Printf("  %-10s  \n", strings.ToUpper(chunk))
		}

		fmt.Println("Public Key:")
		fmt.Printf("X: %X\n", pubkey.X)
		fmt.Printf("Y: %X\n", pubkey.Y)
		print(" ", len(WritePublicKeyToHex(&pubkey))/2, " bytes ", len(WritePublicKeyToHex(&pubkey))*4, " bits\n")
		splitz := SplitSubN(WritePublicKeyToHex(&pubkey), 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 60) {
			fmt.Printf("  %-10s  \n", strings.ToUpper(chunk))
		}
		if validateECPublicKey(pubkeyCurve, pubkey.X, pubkey.Y) {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}
}

func Sign(data []byte, privkey *ecdsa.PrivateKey) ([]byte, error) {
	digest := sha3.Sum256(data)

	r, s, err := ecdsa.Sign(rand.Reader, privkey, digest[:])
	if err != nil {
		return nil, err
	}

	params := privkey.Curve.Params()
	curveOrderByteSize := params.P.BitLen() / 8
	rBytes, sBytes := r.Bytes(), s.Bytes()
	signature := make([]byte, curveOrderByteSize*2)
	copy(signature[curveOrderByteSize-len(rBytes):], rBytes)
	copy(signature[curveOrderByteSize*2-len(sBytes):], sBytes)

	return signature, nil
}

func Verify(data, signature []byte, pubkey *ecdsa.PublicKey) bool {
	digest := sha3.Sum256(data)

	curveOrderByteSize := pubkey.Curve.Params().P.BitLen() / 8

	r, s := new(big.Int), new(big.Int)
	r.SetBytes(signature[:curveOrderByteSize])
	s.SetBytes(signature[curveOrderByteSize:])

	return ecdsa.Verify(pubkey, digest[:], r, s)
}

func split(s string, size int) []string {
	ss := make([]string, 0, len(s)/size+1)
	for len(s) > 0 {
		if len(s) < size {
			size = len(s)
		}
		ss, s = append(ss, s[:size]), s[size:]

	}
	return ss
}

func SplitSubN(s string, n int) []string {
	sub := ""
	subs := []string{}

	runes := bytes.Runes([]byte(s))
	l := len(runes)
	for i, r := range runes {
		sub = sub + string(r)
		if (i+1)%n == 0 {
			subs = append(subs, sub)
			sub = ""
		} else if (i + 1) == l {
			subs = append(subs, sub)
		}
	}

	return subs
}

func validateECPublicKey(curve elliptic.Curve, x, y *big.Int) bool {
	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}
	if x.Cmp(curve.Params().P) >= 0 {
		return false
	}
	if y.Cmp(curve.Params().P) >= 0 {
		return false
	}
	if !curve.IsOnCurve(x, y) {
		return false
	}
	return true
}

func ReadPrivateKeyFromHex(Dhex string) (*ecdsa.PrivateKey, error) {
	c := brp.P256()
	d, err := hex.DecodeString(Dhex)
	if err != nil {
		return nil, err
	}
	k := new(big.Int).SetBytes(d)
	params := c.Params()
	one := new(big.Int).SetInt64(1)
	n := new(big.Int).Sub(params.N, one)
	if k.Cmp(n) >= 0 {
		return nil, errors.New("privateKey's D is overflow.")
	}
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

func ReadPublicKeyFromHex(Qhex string) (*ecdsa.PublicKey, error) {
	q, err := hex.DecodeString(Qhex)
	if err != nil {
		return nil, err
	}
	if len(q) == 65 && q[0] == byte(0x04) {
		q = q[1:]
	}
	if len(q) != 64 {
		return nil, errors.New("publicKey is not uncompressed.")
	}
	pub := new(ecdsa.PublicKey)
	pub.Curve = brp.P256()
	pub.X = new(big.Int).SetBytes(q[:32])
	pub.Y = new(big.Int).SetBytes(q[32:])
	return pub, nil
}

func ReadPrivateKeyFromHexX(Dhex string) (*PrivateKey, error) {
	c := brp.P256()
	d, err := hex.DecodeString(Dhex)
	if err != nil {
		return nil, err
	}
	k := new(big.Int).SetBytes(d)
	params := c.Params()
	one := new(big.Int).SetInt64(1)
	n := new(big.Int).Sub(params.N, one)
	if k.Cmp(n) >= 0 {
		return nil, errors.New("privateKey's D is overflow.")
	}
	priv := new(PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

func ReadPublicKeyFromHexX(Qhex string) (*PublicKey, error) {
	q, err := hex.DecodeString(Qhex)
	if err != nil {
		return nil, err
	}
	if len(q) == 65 && q[0] == byte(0x04) {
		q = q[1:]
	}
	if len(q) != 64 {
		return nil, errors.New("publicKey is not uncompressed.")
	}
	pub := new(PublicKey)
	pub.Curve = brp.P256()
	pub.X = new(big.Int).SetBytes(q[:32])
	pub.Y = new(big.Int).SetBytes(q[32:])
	return pub, nil
}

func WritePrivateKeyToHex(key *ecdsa.PrivateKey) string {
	d := key.D.Bytes()
	if n := len(d); n < 32 {
		d = append(zeroByteSlice()[:64-n], d...)
	}
	c := []byte{}
	c = append(c, d...)
	return hex.EncodeToString(c)
}

func WritePublicKeyToHex(key *ecdsa.PublicKey) string {
	x := key.X.Bytes()
	y := key.Y.Bytes()
	if n := len(x); n < 32 {
		x = append(zeroByteSlice()[:32-n], x...)
	}
	if n := len(y); n < 32 {
		y = append(zeroByteSlice()[:32-n], y...)
	}
	c := []byte{}
	c = append(c, x...)
	c = append(c, y...)
	return hex.EncodeToString(c)
}

type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

type PrivateKey struct {
	PublicKey
	D *big.Int
}

type eccrypterCipher struct {
	XCoordinate *big.Int
	YCoordinate *big.Int
	HASH        []byte
	CipherText  []byte
}

func (pub *PublicKey) EncryptAsn1(data []byte, random io.Reader) ([]byte, error) {
	return EncryptAsn1(pub, data, random)
}

func (priv *PrivateKey) DecryptAsn1(data []byte) ([]byte, error) {
	return DecryptAsn1(priv, data)
}

func EncryptAsn1(pub *PublicKey, data []byte, rand io.Reader) ([]byte, error) {
	cipher, err := Encrypt(pub, data, rand, 0)
	if err != nil {
		return nil, err
	}
	return CipherMarshal(cipher)
}

func DecryptAsn1(pub *PrivateKey, data []byte) ([]byte, error) {
	cipher, err := CipherUnmarshal(data)
	if err != nil {
		return nil, err
	}
	return Decrypt(pub, cipher, 0)
}

func CipherMarshal(data []byte) ([]byte, error) {
	data = data[1:]
	x := new(big.Int).SetBytes(data[:32])
	y := new(big.Int).SetBytes(data[32:64])
	hash := data[64:96]
	cipherText := data[96:]
	return asn1.Marshal(eccrypterCipher{x, y, hash, cipherText})
}

func CipherUnmarshal(data []byte) ([]byte, error) {
	var cipher eccrypterCipher
	_, err := asn1.Unmarshal(data, &cipher)
	if err != nil {
		return nil, err
	}
	x := cipher.XCoordinate.Bytes()
	y := cipher.YCoordinate.Bytes()
	hash := cipher.HASH
	if err != nil {
		return nil, err
	}
	cipherText := cipher.CipherText
	if err != nil {
		return nil, err
	}
	if n := len(x); n < 32 {
		x = append(zeroByteSlice()[:32-n], x...)
	}
	if n := len(y); n < 32 {
		y = append(zeroByteSlice()[:32-n], y...)
	}
	c := []byte{}
	c = append(c, x...)
	c = append(c, y...)
	c = append(c, hash...)
	c = append(c, cipherText...)
	return append([]byte{0x04}, c...), nil
}

var errZeroParam = errors.New("zero parameter")
var one = new(big.Int).SetInt64(1)
var two = new(big.Int).SetInt64(2)

func Encrypt(pub *PublicKey, data []byte, random io.Reader, mode int) ([]byte, error) {
	length := len(data)
	for {
		c := []byte{}
		curve := pub.Curve
		k, err := randFieldElement(curve, random)
		if err != nil {
			return nil, err
		}
		x1, y1 := curve.ScalarBaseMult(k.Bytes())
		x2, y2 := curve.ScalarMult(pub.X, pub.Y, k.Bytes())
		x1Buf := x1.Bytes()
		y1Buf := y1.Bytes()
		x2Buf := x2.Bytes()
		y2Buf := y2.Bytes()
		if n := len(x1Buf); n < 32 {
			x1Buf = append(zeroByteSlice()[:32-n], x1Buf...)
		}
		if n := len(y1Buf); n < 32 {
			y1Buf = append(zeroByteSlice()[:32-n], y1Buf...)
		}
		if n := len(x2Buf); n < 32 {
			x2Buf = append(zeroByteSlice()[:32-n], x2Buf...)
		}
		if n := len(y2Buf); n < 32 {
			y2Buf = append(zeroByteSlice()[:32-n], y2Buf...)
		}
		c = append(c, x1Buf...)
		c = append(c, y1Buf...)
		tm := []byte{}
		tm = append(tm, x2Buf...)
		tm = append(tm, data...)
		tm = append(tm, y2Buf...)

		Sum256 := func(msg []byte) []byte {
			res := sha3.NewLegacyKeccak256()
			res.Write(msg)
			hash := res.Sum(nil)
			return []byte(hash)
		}

		h := Sum256(tm)
		c = append(c, h...)
		ct, ok := kdf(length, x2Buf, y2Buf)
		if !ok {
			continue
		}
		c = append(c, ct...)
		for i := 0; i < length; i++ {
			c[96+i] ^= data[i]
		}
		switch mode {

		case 0:
			return append([]byte{0x04}, c...), nil
		case 1:
			c1 := make([]byte, 64)
			c2 := make([]byte, len(c)-96)
			c3 := make([]byte, 32)
			copy(c1, c[:64])
			copy(c3, c[64:96])
			copy(c2, c[96:])
			ciphertext := []byte{}
			ciphertext = append(ciphertext, c1...)
			ciphertext = append(ciphertext, c2...)
			ciphertext = append(ciphertext, c3...)
			return append([]byte{0x04}, ciphertext...), nil
		default:
			return append([]byte{0x04}, c...), nil
		}
	}
}

func Decrypt(priv *PrivateKey, data []byte, mode int) ([]byte, error) {
	switch mode {
	case 0:
		data = data[1:]
	case 1:
		data = data[1:]
		c1 := make([]byte, 64)
		c2 := make([]byte, len(data)-96)
		c3 := make([]byte, 32)
		copy(c2, data[64:len(data)-32])
		copy(c3, data[len(data)-32:])
		c := []byte{}
		c = append(c, c1...)
		c = append(c, c3...)
		c = append(c, c2...)
		data = c
	default:
		data = data[1:]
	}
	length := len(data) - 96
	curve := priv.Curve
	x := new(big.Int).SetBytes(data[:32])
	y := new(big.Int).SetBytes(data[32:64])
	x2, y2 := curve.ScalarMult(x, y, priv.D.Bytes())
	x2Buf := x2.Bytes()
	y2Buf := y2.Bytes()
	if n := len(x2Buf); n < 32 {
		x2Buf = append(zeroByteSlice()[:32-n], x2Buf...)
	}
	if n := len(y2Buf); n < 32 {
		y2Buf = append(zeroByteSlice()[:32-n], y2Buf...)
	}
	c, ok := kdf(length, x2Buf, y2Buf)
	if !ok {
		return nil, errors.New("Decrypt: failed to decrypt")
	}
	for i := 0; i < length; i++ {
		c[i] ^= data[i+96]
	}
	tm := []byte{}
	tm = append(tm, x2Buf...)
	tm = append(tm, c...)
	tm = append(tm, y2Buf...)

	Sum256 := func(msg []byte) []byte {
		res := sha3.NewLegacyKeccak256()
		res.Write(msg)
		hash := res.Sum(nil)
		return []byte(hash)
	}

	h := Sum256(tm)
	if bytes.Compare(h, data[64:96]) != 0 {
		return c, errors.New("Decrypt: failed to decrypt")
	}
	return c, nil
}

func randFieldElement(c elliptic.Curve, random io.Reader) (k *big.Int, err error) {
	if random == nil {
	}
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(random, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

func intToBytes(x int) []byte {
	var buf = make([]byte, 4)

	binary.BigEndian.PutUint32(buf, uint32(x))
	return buf
}

func kdf(length int, x ...[]byte) ([]byte, bool) {
	var c []byte
	ct := 1
	h := sha3.NewLegacyKeccak256()
	for i, j := 0, (length+31)/32; i < j; i++ {
		h.Reset()
		for _, xx := range x {
			h.Write(xx)
		}
		h.Write(intToBytes(ct))
		hash := h.Sum(nil)
		if i+1 == j && length%32 != 0 {
			c = append(c, hash[:length%32]...)
		} else {
			c = append(c, hash...)
		}
		ct++
	}
	for i := 0; i < length; i++ {
		if c[i] != 0 {
			return c, true
		}
	}
	return c, false
}

func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

func zeroByteSlice() []byte {
	return []byte{
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
}
