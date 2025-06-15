package crypto_lib

import (
	"fmt"
	"math"
	"strconv"
	"unicode"
)

func HexToByteValue(hex string) (byte, error) {

	val, err := strconv.ParseUint(hex, 16, 8)

	if err != nil {
		return 0xff, err
	}

	return byte(val), nil

}

func HexDecode(hexString string) ([]byte, error) {

	rawBytes := make([]byte, 0, len(hexString)/2)

	for i := 0; i < len(hexString); i += 2 {

		hexByte := hexString[i: i+2]

		byteVal, err := HexToByteValue(hexByte)

		if err != nil {
			return nil, err
		}

		rawBytes = append(rawBytes, byteVal)

	}

	return rawBytes, nil

}

func HexEncode(rawBytes []byte) string {

	hexString := ""

	for _, b := range(rawBytes) {
		hexString += strconv.FormatUint(uint64(b), 16)
	}

	return hexString

}

func _xorEncrypt(plaintext, key []byte) []byte {

	ciphertext := make([]byte, 0, len(plaintext))

	for i := 0; i < len(plaintext); i++ {
		ciphertext = append(ciphertext, plaintext[i] ^ key[i])
	}

	return ciphertext

}

func _xorEncryptRepeating(plaintext, key []byte) []byte {

	ciphertext := make([]byte, 0, len(plaintext))


	for i := 0; i < len(plaintext); i++ {
		ciphertext = append(ciphertext, plaintext[i] ^ key[i % len(key)])
	}

	return ciphertext

}

func XorEncrypt(plaintext, key []byte) []byte {

	if len(plaintext) == len(key) {
		return _xorEncrypt(plaintext, key)

	} else {
		return _xorEncryptRepeating(plaintext, key)

	}

}

func XorDecrypt(ciphertext, key []byte) []byte {

	return XorEncrypt(ciphertext, key)


}

func XorDecryptSingle(ciphertext []byte, key byte) []byte {
	return XorEncryptSingle(ciphertext, key)
}

func XorEncryptSingle(plaintext []byte, key byte) []byte {

	ciphertext := make([]byte, 0, len(plaintext))

	for i := 0; i < len(plaintext); i++ {
		ciphertext = append(ciphertext, plaintext[i] ^ key)
	}

	return ciphertext

}

func IsText(s string) bool {

	// iterate over the whole string
	for _, c := range(s) {

		// if not a letter, return false
		if !unicode.IsLetter(c) {
			if !unicode.IsPunct(c) {

				if c != '\n' {
					if c != '\t' {
						if c != ' ' {
							return false
						}
					}
				}
			}
		}
	}

	return true

}

// Finds possible plaintexts for a "Single Byte XOR Encrypted" ciphertext.
//
// Warning:
// ciphertext should be actual byte values, so if it is in hex encoded format
// you should decode it first by using HexDecode()
func FindSingleByteXorPairs(ciphertext []byte) (map[byte]string, error) {

	// key, plaintext pairs
	possiblePlaintexts := make(map[byte]string)

	// try all possible byte values (0 to 255)
	var key byte
	for key = range math.MaxUint8 {
		
		plaintextBytes := XorDecryptSingle(ciphertext, key)

		plaintext := string(plaintextBytes)

		// if plaintext looks like a 'text'
		if IsText(plaintext) {
			possiblePlaintexts[key] = plaintext
		}

	}

	// if no possible plaintext is found
	if len(possiblePlaintexts) == 0 {
		return nil, fmt.Errorf("no possible plaintext found for: %s", HexEncode(ciphertext))
	}

	return possiblePlaintexts, nil

}

// Selects the more likely the correct plaintext among the possible plaintext
// using heuristic methods. 
func DecideForThePlaintext(possiblePlaintexts map[byte]string) (string, error) {

	// we will use punctiation frequencies to decide which
	// plaintext is a better candidate for real plaintext
	punctiationFrequencies := make(map[byte]int)

	// count the amount of punctiations used in the plaintexts
	for k, v := range(possiblePlaintexts) {

		punctiationFrequencies[k] = 0;

		for _, ch := range(v) {
			if (unicode.IsPunct(ch)) {
				punctiationFrequencies[k] += 1
			}
		}

	}

	var decidedPlaintextIndex byte = math.MaxUint8
	punctCount := math.MaxInt

	// decide which plaintext has the least amount of punctiation
	// (less punctiation = more likely to be the real plaintext)
	for i, v := range(punctiationFrequencies) {
		if v <= punctCount {
			decidedPlaintextIndex = i
			punctCount = v
		}
	}

	if decidedPlaintextIndex == math.MaxUint8 {
		return "", fmt.Errorf("unable to decide for 'the plaintext' in between %#v", possiblePlaintexts)
	}

	return possiblePlaintexts[decidedPlaintextIndex], nil

}