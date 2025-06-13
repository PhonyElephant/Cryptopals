package main

import (
	"encoding/base64"
	"fmt"
	"log"

	"example.com/arif/crypto_lib"
)

const (
	hex_message = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
)

func main() {


	raw_bytes, err := crypto_lib.HexDecode(hex_message)

	if err != nil {
		log.Fatal(err)
	}

	enc_string := base64.RawStdEncoding.EncodeToString(raw_bytes)

	fmt.Printf("Encoded string: %s\n", enc_string)

}