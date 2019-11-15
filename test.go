package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"strconv"
	"time"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
)

const (
	SHA1        int = 0
	SHA256      int = 1
	SHA384      int = 2
	SHA512      int = 3
	SHA3_256    int = 4
	SHA3_384    int = 5
	SHA3_512    int = 6
	BLAKE2s_256 int = 7
	BLAKE2b_256 int = 8
	BLAKE2b_384 int = 9
	BLAKE2b_512 int = 10
	SCRIPT      int = 11
)

func main() {

	start := time.Now()

	list := make(map[int][]byte)
	for i := 0; i < 8; i++ {
		list[i] = []byte(strconv.FormatInt(int64(i), 10))
	}
	fmt.Printf("%x", merkleHash20(list))

	finish := time.Now()
	elapsed := finish.Sub(start)
	fmt.Printf("\n%f", elapsed.Minutes())
}

func sha1Hash(input []byte) [20]byte {
	hashValue := sha1.Sum(input)
	return hashValue
}
func sha256Hash(input []byte) [32]byte {
	hashValue := sha256.Sum256(input)
	return hashValue
}
func sha384Hash(input []byte) [48]byte {
	hashValue := sha512.Sum384(input)
	return hashValue
}
func sha512Hash(input []byte) [64]byte {
	hashValue := sha512.Sum512(input)
	return hashValue
}
func sha3_256Hash(input []byte) [32]byte {
	hashValue := sha3.Sum256(input)
	return hashValue
}
func sha3_384Hash(input []byte) [48]byte {
	hashValue := sha3.Sum384(input)
	return hashValue
}
func sha3_512Hash(input []byte) [64]byte {
	hashValue := sha3.Sum512(input)
	return hashValue
}
func blake2s256Hash(input []byte) [32]byte {
	hashValue := blake2s.Sum256(input)
	return hashValue
}
func blake2b256Hash(input []byte) [32]byte {
	hashValue := blake2b.Sum256(input)
	return hashValue
}
func blake2b384Hash(input []byte) [48]byte {
	hashValue := blake2b.Sum384(input)
	return hashValue
}
func blake2b512Hash(input []byte) [64]byte {
	hashValue := blake2b.Sum512(input)
	return hashValue
}
func scrypt512Hash(input []byte, difParam int) []byte {
	hashValue, _ := scrypt.Key(input, []byte(""), difParam, 8, 1, 64) //difParam:  16384 - 1048576 - optimal
	return hashValue
}

func merkleNode20(leaf1 [20]byte, leaf2 [20]byte, hashFunc int) [20]byte {
	hash1 := leaf1[:]
	hash2 := leaf2[:]
	hash3 := append(hash1, hash2...)
	switch hashFunc {
	case SHA1:
		hash4 := sha1Hash(hash3)
		return hash4
	}
	return leaf1
}
func merkleNode32(leaf1 [32]byte, leaf2 [32]byte, hashFunc int) [32]byte {
	hash1 := leaf1[:]
	hash2 := leaf2[:]
	hash3 := append(hash1, hash2...)
	switch hashFunc {
	case SHA256:
		hash4 := sha256Hash(hash3)
		return hash4
	case SHA3_256:
		hash4 := sha3_256Hash(hash3)
		return hash4
	case BLAKE2s_256:
		hash4 := blake2s256Hash(hash3)
		return hash4
	case BLAKE2b_256:
		hash4 := blake2b256Hash(hash3)
		return hash4
	}
	return leaf1
}
func merkleNode48(leaf1 [48]byte, leaf2 [48]byte, hashFunc int) [48]byte {
	hash1 := leaf1[:]
	hash2 := leaf2[:]
	hash3 := append(hash1, hash2...)
	switch hashFunc {
	case SHA384:
		hash4 := sha384Hash(hash3)
		return hash4
	case SHA3_384:
		hash4 := sha3_384Hash(hash3)
		return hash4
	case BLAKE2b_384:
		hash4 := blake2b384Hash(hash3)
		return hash4
	}
	return leaf1
}
func merkleNode64(leaf1 [64]byte, leaf2 [64]byte, hashFunc int) [64]byte {
	hash1 := leaf1[:]
	hash2 := leaf2[:]
	hash3 := append(hash1, hash2...)
	switch hashFunc {
	case SHA512:
		hash4 := sha512Hash(hash3)
		return hash4
	case SHA3_512:
		hash4 := sha3_512Hash(hash3)
		return hash4
	case BLAKE2b_512:
		hash4 := blake2b512Hash(hash3)
		return hash4
	}
	return leaf1
}
func merkleNodeScript(leaf1 []byte, leaf2 []byte, difParam int) []byte {
	hash1 := leaf1[:]
	hash2 := leaf2[:]
	hash3 := append(hash1, hash2...)
	hash4 := scrypt512Hash(hash3, difParam)
	return hash4
}

func merkleHash20(data map[int][]byte) [20]byte {
	layer0 := make(map[int][20]byte)
	for i := 0; i < 8; i++ {
		layer0[i] = sha1Hash(data[i])
	}
	layer1 := make(map[int][20]byte)
	layer1[0] = merkleNode20(layer0[0], layer0[1], SHA1)
	layer1[1] = merkleNode20(layer0[2], layer0[3], SHA1)
	layer1[2] = merkleNode20(layer0[4], layer0[5], SHA1)
	layer1[3] = merkleNode20(layer0[6], layer0[7], SHA1)
	layer2 := make(map[int][20]byte)
	layer2[0] = merkleNode20(layer1[0], layer1[1], SHA1)
	layer2[1] = merkleNode20(layer1[2], layer1[3], SHA1)
	hash := merkleNode20(layer2[0], layer2[1], SHA1)
	return hash
}
