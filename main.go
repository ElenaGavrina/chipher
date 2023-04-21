package main

import (
	"encoding/base64"
	"fmt"
	"flag"
)

func main(){
	var mes = flag.String("message","text","text message")
    	var choose = flag.Bool("mode",true,"encode")
	flag.Parse()
	if *choose{
		encryptResult, err := EncryptMessage(*mes);if err!= nil{
			fmt.Println(err)
		}
		fmt.Println(encryptResult)
	}else{
	    decryptResult, err := DecryptMessage(*mes);if err!= nil{
			fmt.Println(err)
		}
		fmt.Println(decryptResult)
	}
}

func EncryptMessage(message string) (string,error) {
	byteMsg := []byte(message)
	return base64.StdEncoding.EncodeToString(byteMsg),nil
}

func DecryptMessage(message string) (string, error) {
	cipherText, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "", fmt.Errorf("could not base64 decode: %v", err)
	}
	return string(cipherText), nil
}
