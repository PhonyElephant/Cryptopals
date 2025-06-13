package crypto_lib

import (
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

func XorEncrypt(plaintext, key []byte) []byte {

	ciphertext := make([]byte, 0, len(plaintext))

	for i := 0; i < len(plaintext); i++ {
		ciphertext = append(ciphertext, plaintext[i] ^ key[i])
	}

	return ciphertext

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

func IsAlpha(s string) bool {

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