package crypto_lib

import (
	"strconv"
)

func hexToByteValue(hex string) (byte, error) {

	val, err := strconv.ParseUint(hex, 16, 8)

	if err != nil {
		return 0xff, err
	}

	return byte(val), nil

}

func HexDecode(s string) ([]byte, error) {

	rawBytes := make([]byte, 0, len(s)/2)

	for i := 0; i < len(s); i += 2 {

		hexByte := s[i: i+2]

		byteVal, err := hexToByteValue(hexByte)

		if err != nil {
			return nil, err
		}

		rawBytes = append(rawBytes, byteVal)

	}

	return rawBytes, nil

}