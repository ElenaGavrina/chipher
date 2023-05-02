package main

import (
	"encoding/base64"
	"fmt"
	"flag"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io/ioutil"
	"io"
	"log"
)

var mes = flag.String("mes","text","text message")
var mode = flag.Bool("mode",true,"encode")
var key = flag.String("k","1234567890abcdef","key chipher")
var file = flag.String("fp","myfile.txt","file path")


func main(){
	flag.Parse()
	if *file != ""{
		encryptR,err := Encode(*key,fromFileToByte(*file));if err!= nil{
			fmt.Println(err)
		}	
		fmt.Println(encryptR,nil)
	}

	if *mes !=""{
		if *mode{
			encryptResult, err := Encode(*key,fromMesToByte(*mes));if err!= nil{
				fmt.Println(err)
			}	
			fmt.Println(encryptResult)
		}else{
	    	decryptResult, err := DecryptMessage(*key,*mes);if err!= nil{
				fmt.Println(err)
			}
			fmt.Println(decryptResult)
		}
	}
	
}

func Encode(key string, message []byte) (string,error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}
	cipherText := make([]byte, aes.BlockSize+len(message))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("could not encrypt: %v", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], message)
	return base64.StdEncoding.EncodeToString(message),nil
}

func DecryptMessage(key string,message string) (string, error) {
	cipherText, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "", fmt.Errorf("could not base64 decode: %v", err)
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}
	
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)
	return string(cipherText), nil
}

func decryptFile(key string) {
	cipherText, err := ioutil.ReadFile("myfile.bin")
	if err != nil {
		log.Fatal(err)
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatalf("cipher err: %v", err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("cipher GCM err: %v", err.Error())
	}
	nonce := cipherText[:gcm.NonceSize()]
	cipherText = cipherText[gcm.NonceSize():]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		log.Fatalf("decrypt file err: %v", err.Error())
	}

	err = ioutil.WriteFile("myfile.txt", plainText, 0777)
	if err != nil {
		log.Fatalf("write file err: %v", err.Error())
	}
}
func fromMesToByte(message string)[]byte{
	byteMsg := []byte(message)
	return byteMsg
}
func fromFileToByte(message string)[]byte{
	plainText, err := ioutil.ReadFile(message)
	if err != nil {
		log.Fatalf("read file err: %v", err.Error())
	}
	return plainText
}

