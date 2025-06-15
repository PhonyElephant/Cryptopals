package main

import (
	"fmt"
	"log"
	"unicode"

	"example.com/arif/crypto_lib"
)

const (
	ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
)

func main() {

	rawCiphertextBytes, err := crypto_lib.HexDecode(ciphertext)

	if err != nil {
		log.Fatal(err)
	}

	possiblePlaintexts := make([]string, 0, 4)

	// all possible values for a byte
	for i := 0; i < 256; i++ {

		rawPlaintextBytes := crypto_lib.XorDecryptSingle(rawCiphertextBytes, byte(i))

		plaintext := string(rawPlaintextBytes)

		if crypto_lib.IsText(plaintext) {
			fmt.Printf("Key: %#x | Possible plaintext: %s\n", i, plaintext)
			possiblePlaintexts = append(possiblePlaintexts, plaintext)
		}

	}

	punctiationFrequencies := make(map[int]int)

	// count the amount of punctiation used in the plaintexts
	for i, s := range(possiblePlaintexts) {

		for _, ch := range(s) {
			if (unicode.IsPunct(ch)) {
				punctiationFrequencies[i] += 1
			}
		}

	}

	decidedPlaintextIndex := -1
	punctCount := 999

	// decide which plaintext has the least amount of punctiation
	for k, v := range(punctiationFrequencies) {
		if v < punctCount {
			decidedPlaintextIndex = k
			punctCount = v
		}
	}


	fmt.Printf("\nDecided plaintext: %s\n", possiblePlaintexts[decidedPlaintextIndex])


}