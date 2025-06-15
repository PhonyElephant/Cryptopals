package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"example.com/arif/crypto_lib"
)

const (
	ciphertextsFileName = "4.txt"
	resultFileName = "result.txt"
)

func main() {

	// open the file where ciphertexts are stored
	ciphertextFileHandle, err := os.Open(ciphertextsFileName)

	if err != nil {
		log.Fatal(err)
	}

	defer ciphertextFileHandle.Close()

	// use bufio for reading data more ergonomically
	ciphertextFileReader := bufio.NewReader(ciphertextFileHandle)

	// it is easier to analyze the results from a file
	resultFileHandle, err := os.Create(resultFileName)
	resultFileWriter := bufio.NewWriter(resultFileHandle)

	defer resultFileHandle.Close()

	if err != nil {
		log.Fatal()
	}

	// we need a mutex for parallel writing to a file
	var resultFileMutex sync.Mutex

	// useful for waiting all goroutines to finish
	var wg sync.WaitGroup

	for {
		

		// read a ciphertextLine (a ciphertext) from the file
		ciphertextLine, err := ciphertextFileReader.ReadString('\n')

		if err != nil {
			break;
		}

		// get rid of the trailing newline character
		ciphertextLine = strings.TrimRight(ciphertextLine, "\n")

		// decode the string into bytes
		ciphertextBytes, err := crypto_lib.HexDecode(ciphertextLine)

		if (err != nil) {
			log.Fatal(err)
		}

		wg.Add(1)

		go func() {

			defer wg.Done()

			// find possible keys and their corresponding plaintexts
			possiblePlaintexts, err := crypto_lib.FindSingleByteXorPairs(ciphertextBytes)

			if err != nil {
				log.Println(err)
				return
			}
		
			// thePlaintext is the plaintext where the most likely the correct plaintext
			thePlaintext, err := crypto_lib.DecideForThePlaintext(possiblePlaintexts)

			// if an index is decided for 'the plaintext'
			if err != nil {
				log.Println(err)
			}


			resultFileMutex.Lock()

			s := "--------------------------------------------\n"
			s += fmt.Sprintf("Ciphertext: %s\nPlaintext: %#v\n", ciphertextLine, thePlaintext)
			s += "--------------------------------------------\n\n"

			resultFileWriter.WriteString(s)
			resultFileWriter.Flush()


			resultFileMutex.Unlock()


		}()

	}

	wg.Wait()

	fmt.Println("\n\nComputations finished.\nYou can find the results in 'result.txt' file.")


}