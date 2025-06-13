package main

import (
	"fmt"
	"log"

	"example.com/arif/crypto_lib"
)

const (
	hexCiphertext = "1c0111001f010100061a024b53535009181c"
	xorKey = "686974207468652062756c6c277320657965"
)

func main() {


	rawCipherTextBytes, err := crypto_lib.HexDecode(hexCiphertext)

	if err != nil {
		log.Fatal(err)
	}

	rawKeyBytes, err := crypto_lib.HexDecode(xorKey)

	if err != nil {
		log.Fatal(err)
	}

	rawPlaintextBytes := crypto_lib.XorDecrypt(rawCipherTextBytes, rawKeyBytes)

	hexPlaintextString := crypto_lib.HexEncode(rawPlaintextBytes)

	fmt.Printf("Plaintext message: %s\n", hexPlaintextString)

}