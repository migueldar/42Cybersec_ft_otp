package main

import (
	"fmt"
	"flag"
	//"crypto/sha256"
	//"crypto/aes"
	//"encoding/hex"
)

var ipad, opad [64]byte

func parser() (*string, *string){
	defer flag.Parse()
	return flag.String("g", "", "recieve file where key is allocated and store in an encrypted file"), 
	flag.String("k", "", "generate a new key based on the password saved on string")
}

func init_globals() {
	for i := 0; i < len(ipad); i++ {
		ipad[i] = 0x36
		opad[i] = 0x5C
	}
}

func main() {
	gFlag, kFlag := parser()
	if *gFlag != "" {
		return
	}
	if *kFlag != "" {
		return
	}
	init_globals()
	fmt.Println(ipad)
	fmt.Println(opad)
}
