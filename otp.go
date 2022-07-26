package main

import (
	"fmt"
	"flag"
	"crypto/sha1"
	"os"
	"log"
	"crypto/aes"
	"encoding/hex"
	"time"
	"io/ioutil"
)

var (
	key_aes = [16]byte{226, 97, 2, 136, 60, 123, 178, 35, 125, 144, 94, 0, 12, 164, 58, 23}
	ipad, opad [64]byte
)

func parser() (*string, *string) {
	defer flag.Parse()
	return flag.String("g", "", "recieve file where key is allocated and store in an encrypted file"), 
	flag.String("k", "", "generate a new key based on the password saved key")
}

func init_globals() {
	for i := 0; i < len(ipad); i++ {
		ipad[i] = 0x36
		opad[i] = 0x5C
	}
}

//returns true if program must continue
func start() bool {
	gptr, kptr := parser()
	gFlag , kFlag := *gptr, *kptr
	if gFlag != "" {
		if !do_gFlag(gFlag) {
			return false
		}
	}
	if kFlag != "" {
		if kFlag != "ft_otp.key" {
			fmt.Println("Incorrect argument for -k flag, must be: ft_otp.key")
			return false
		}
		init_globals()
		return true
	}
	return false
}

func do_gFlag(key string) bool {
	if (len(key) < 64 || len(key) > 128) {
		fmt.Println("Key must have between 64 and 128 hex characters")
		return false
	}
	if (len(key) % 2 == 1) {
		key += "0"
	}
	data, err := hex.DecodeString(key)
	if err != nil {
		log.Fatal(err)
	}
	cipher, err := aes.NewCipher(key_aes[:])
	if err != nil {
		log.Fatal(err)
	}
	for len(data) < 64 {
		data = append(data, 0)
	}
	data_encrypted := make([]byte, 64)
	cipher.Encrypt(data_encrypted, data)
	cipher.Encrypt(data_encrypted[16:], data[16:])
	cipher.Encrypt(data_encrypted[32:], data[32:])
	cipher.Encrypt(data_encrypted[48:], data[48:])
	err = os.WriteFile("ft_otp.key", data_encrypted, 0600)
	if err != nil {
		log.Fatal(err)
	}
	return false
}

func hmac_sha1(key, time []byte) [20]byte {
	xorRes := xorSli(ipad[:], key)
	firstMsg := append(xorRes, time...)
	firstSha := sha1.Sum(firstMsg)
	xorRes = xorSli(opad[:], key)
	secondMsg := append(xorRes, firstSha[:]...)
	secondSha := sha1.Sum(secondMsg)
	return secondSha
}

func trunc(shaRes [20]byte) int {
	offset := int(shaRes[19] & 0x0f)
	truncRes := shaRes[offset:offset+4]
	truncRes[0] &= 0x7f
	result := byte4toint(truncRes)
	return result
}

func getKey() []byte {
	file, err := ioutil.ReadFile("ft_otp.key")
	if err != nil {
		log.Fatal(err)
	}
	cipher, err := aes.NewCipher(key_aes[:])
	if err != nil {
		log.Fatal(err)
	}
	de_file := make([]byte, 64)
	cipher.Decrypt(de_file, file)
	cipher.Decrypt(de_file[16:], file[16:])
	cipher.Decrypt(de_file[32:], file[32:])
	cipher.Decrypt(de_file[48:], file[48:])
	return de_file
}

func main() {
	if !start() {
		return 
	}
	key := getKey()
	unixTime := time.Now().Unix()
	time := []byte(fmt.Sprint(unixTime/30))
	shaRes := hmac_sha1(key[:], time)
	result := trunc(shaRes)
	//append 0 at begin
	totp := fmt.Sprint(result % 1000000)
	for len(totp) < 6 {
		totp = "0" + totp
	}
	fmt.Println(totp)
}
