package main

import (
	"fmt"
	"flag"
	"crypto/sha1"
	"os"
	"log"
	"encoding/hex"
	"time"
	"io/ioutil"
	"encoding/binary"
)

var ipad, opad [64]byte

func parser() (*string, *string) {
	defer flag.Parse()
	return flag.String("g", "", "recieve key and store in an encrypted file"), 
	flag.String("k", "", "generate a new key based on the password contained in the file")
}

func init_globals() {
	for i := 0; i < len(ipad); i++ {
		ipad[i] = 0x36
		opad[i] = 0x5C
	}
}

//returns true if program must continue
func start() (string, bool) {
	gptr, kptr := parser()
	gFlag , kFlag := *gptr, *kptr
	if gFlag != "" {
		if !do_gFlag(gFlag) {
			return "", false
		}
	}
	if kFlag != "" {
		init_globals()
		return kFlag, true
	}
	return "", false
}

func do_gFlag(key string) bool {
	if (len(key) < 64 || len(key) > 128) {
		fmt.Println("Key must have between 64 and 128 hex characters")
		return false
	}
	if (len(key) % 2 == 1) {
		fmt.Println("Key must have an even number of hex characters")
		return false
	}
	data, err := hex.DecodeString(key)
	if err != nil {
		log.Fatal(err)
	}
	for len(data) < 64 {
		data = append(data, 0)
	}
	data_encrypted := aes_en64(data)
	err = os.WriteFile("ft_otp.key", data_encrypted, 0600)
	if err != nil {
		log.Fatal(err)
	}
	return true
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

func getKey(path string) []byte {
	file, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	de_file := aes_de64(file)
	return de_file
}

func main() {
	path, cont := start() 
	if !cont {
		return 
	}
	key := getKey(path)
	unixTime := time.Now().Unix()
	time := make([]byte, 8)
	binary.BigEndian.PutUint64(time, uint64(unixTime/30))
	shaRes := hmac_sha1(key[:], time)
	result := trunc(shaRes)
	totp := fmt.Sprint(result % 1000000)
	for len(totp) < 6 {
		totp = "0" + totp
	}
	fmt.Println(totp)
}
