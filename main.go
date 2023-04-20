package main

import (
	"encoding/base64"
	"fmt"
	"flag"
)

func main(){
	mes := flag.String("message","text","text message")
	chose := flag.Bool("choosing method",true,"encode")
	if *chose{
		encryptResult, err := EncryptMessage(*mes);if err!= nil{
			fmt.Println(err)
		}
		fmt.Println(encryptResult)
	}
	if *chose!=true{
	    decryptResult, err := DecryptMessage(encryptResult);if err!= nil{
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
