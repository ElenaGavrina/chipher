package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"flag"
	"encoding/binary"
)

func main(){
	mes := flag.String("message","text","text message")
	chipherKey := flag.Bool("key","key","key chipher")
	fmt.Println(EncryptMessage(*chipherKey,*mes))
}

func EncryptMessage(key []byte, message string) (string,error){
	key := []byte(message)
	return base64.StdEncoding.EncodeToString(cipherText),nil

}