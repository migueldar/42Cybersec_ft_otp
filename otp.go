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


//coger uppercase y lowercase hex key

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
		return(do_gFlag(gFlag))
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

//check key size
func do_gFlag(key string) bool {
	if !check_gFlag(key) {
		fmt.Println("Incorrect key: must only contain hexadecimal characters")
		return false
	}
	cipher, err := aes.NewCipher(key_aes[:])
	if err != nil {
		log.Fatal(err)
	}
	data := make([]byte, 64, 64)
	fmt.Println(data)
	data, err = hex.DecodeString(key)

	if err != nil {
		log.Fatal(err)
	}
	cipher.Encrypt(data, data)
	file, err := os.OpenFile("ft_otp.key", os.O_WRONLY | os.O_CREATE | os.O_TRUNC, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	//fmt.Printf("%T %d", data, data)
	//byteSlice := make([]byte, 32)
	//bytesRead, err := file.Read(byteSlice)
	return false
}

func hmac_sha1(key, time []byte) [20]byte {
	xorRes := xorSli(ipad[:], key[:])
	firstMsg := append(xorRes, time...)
	firstSha := sha1.Sum(firstMsg)
	xorRes = xorSli(opad[:], key[:])
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

//manage len < 64 of key, what if > 128 (hex chars)
//add 0 at end
func check_gFlag(gFlag string) bool {
	for _, v := range gFlag {
		b := byte(v)
		if (!((b >= 'a' && b <= 'f') || (b >= '0' && b <= '9') || (b >= 'A' && b <= 'F'))) {
			return false
		}
	}
	return true
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
	var de_file []byte
	cipher.Decrypt(file, de_file)
	return de_file
}

func main() {
	//key := [64]byte{2, 3, 5, 7, 11, 13, 90, 99, 100, 1, 9}

	if !start() {
		return 
	}
	key := getKey()

	fmt.Println(key)
	unixTime := time.Now().Unix()
	time := []byte(fmt.Sprint(unixTime))
	shaRes := hmac_sha1(key[:], time)
	result := trunc(shaRes)
	//append 0 at begin
	totp := fmt.Sprint(result % 1000000)
	for len(totp) < 6 {
		totp = "0" + totp
	}
	fmt.Println(totp)
}
