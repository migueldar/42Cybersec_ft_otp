package main

import (
	"crypto/aes"
	"log"
	"fmt"
	"os"
)

var key_aes = [16]byte{226, 97, 2, 136, 60, 123, 178, 35, 125, 144, 94, 0, 12, 164, 58, 23}

func aes_en64(data []byte) []byte {
	cipher, err := aes.NewCipher(key_aes[:])
	if err != nil {
		log.Fatal(err)
	}
	data_encrypted := make([]byte, 64)
	cipher.Encrypt(data_encrypted[:16], data[:16])
	cipher.Encrypt(data_encrypted[16:32], data[16:32])
	cipher.Encrypt(data_encrypted[32:48], data[32:48])
	cipher.Encrypt(data_encrypted[48:], data[48:])
	return data_encrypted
}

func aes_de64(data []byte) []byte {
	if (len(data) != 64) {
		fmt.Println("Incorrect file format, please introduce a file generated with this program's -g option")
		os.Exit(1)
	}
	cipher, err := aes.NewCipher(key_aes[:])
	if err != nil {
		log.Fatal(err)
	}
	data_decrypted := make([]byte, 64)
	cipher.Decrypt(data_decrypted[:16], data[:16])
	cipher.Decrypt(data_decrypted[16:32], data[16:32])
	cipher.Decrypt(data_decrypted[32:48], data[32:48])
	cipher.Decrypt(data_decrypted[48:], data[48:])
	return data_decrypted
}