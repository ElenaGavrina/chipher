package main

import (
	"encoding/base64"
	"fmt"
	"flag"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

var mes = flag.String("message","text","text message")
var choose = flag.Bool("mode",true,"encode")
var key =flag.String("key","1234567890abcdef","key chipher")

func main(){
	
	flag.Parse()
	if *choose{
		encryptResult, err := EncryptMessage(fromStrToByte(*key),*mes);if err!= nil{
			fmt.Println(err)
		}
		fmt.Println(encryptResult)
	}else{
	    decryptResult, err := DecryptMessage(fromStrToByte(*key),*mes);if err!= nil{
			fmt.Println(err)
		}
		fmt.Println(decryptResult)
	}
}

func EncryptMessage(key []byte, message string) (string,error) {
	byteMsg := []byte(message)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}
	cipherText := make([]byte, aes.BlockSize+len(byteMsg))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("could not encrypt: %v", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], byteMsg)
	return base64.StdEncoding.EncodeToString(byteMsg),nil
}

func DecryptMessage(key []byte,message string) (string, error) {
	cipherText,err := base64.StdEncoding.DecodeString(message)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}
	if err != nil {
		return "", fmt.Errorf("could not base64 decode: %v", err)
	}
	
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)
	return string(cipherText), nil
}

func fromStrToByte(key string)[]byte{
	newKey:= []byte(key)
	return newKey
}
