package main

import (
	"fmt"
	"flag"
	"crypto/sha1"
	//"crypto/aes"
	//"encoding/hex"
	"time"
)

var ipad, opad [64]byte

func parser() (*string, *string){
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

func xorSli(sli1, sli2 []byte) []byte{
	for i, v := range sli1 {
		sli2[i] ^= v
	}
	return sli2
}

func byte4toint(sli []byte) int{
	ret := int(sli[3])
	ret += int(sli[2]) * 0x100
	ret += int(sli[1]) * 0x10000
	ret += int(sli[0]) * 0x1000000
	return ret
}

func init() {
	// gFlag, kFlag := parser()
	// if *gFlag != "" {
	// 	return
	// }
	// if *kFlag != "" {
	// 	return
	// }
	init_globals()
}

func main() {
	key := [64]byte{2, 3, 5, 7, 11, 13, 90, 99, 100, 1, 9}
	xorRes := xorSli(ipad[:], key[:])
	unixTime := time.Now().Unix()
	time := []byte(fmt.Sprint(unixTime/30))
	firstMsg := append(xorRes, time...)
	firstSha := sha1.Sum(firstMsg)
	//fmt.Println(firstSha)
	xorRes = xorSli(opad[:], key[:])
	secondMsg := append(xorRes, firstSha[:]...)
	secondSha := sha1.Sum(secondMsg)
	fmt.Println(secondSha)
	offset := int(secondSha[19] & 0x0f)
	fmt.Println(offset)
	truncRes := secondSha[offset:offset+4]
	fmt.Println(truncRes)
	truncRes[0] &= 0x7f
	fmt.Println(truncRes)
	result := byte4toint(truncRes)
	//add 0 at begin
	fmt.Println(result % 1000000)
}
