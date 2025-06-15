package main

import (
	"fmt"

	"example.com/arif/crypto_lib"
)

const (
	plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key = "ICE"
)


func main() {

	plaintextBytes := []byte(plaintext)
	keyBytes := []byte(key)

	ciphertextBytes := crypto_lib.XorEncrypt(plaintextBytes, keyBytes)

	ciphertextString := crypto_lib.HexEncode(ciphertextBytes)

	fmt.Println(ciphertextString)

}