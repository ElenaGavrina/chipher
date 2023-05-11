package main

import (
	"flag"
	"log"
	"io/ioutil"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"fmt"
	"encoding/base64"
)

var mes = flag.String("mes","text","text message")
var mode = flag.Bool("mode",true,"encode")
var key = flag.String("k","1234567890abcdef","key chipher")
var file = flag.String("fp","","file path")

func main(){
	flag.Parse()
	if *mode { 
		if *file != ""{
			plainText, err := ioutil.ReadFile(*file)
			encriptText, _ := EncryptMessage([]byte(*key), string(plainText))
			errWrite := ioutil.WriteFile("ciphertextresult.txt", []byte(encriptText), 0777)
			if errWrite != nil {
				log.Fatalf("write file err: %v", err.Error())
			}
			if err != nil {
				log.Fatalf("write file err: %v", err.Error())
			}
		}
		if *mes != ""{
			encM,_:=EncryptMessage([]byte(*key), *mes,)
			fmt.Println(encM)
		}
	}else{
		if *file !=""{
			encriptPlainTextT, _ := ioutil.ReadFile(*file)
			decriptTextT, err := DecryptMessage([]byte(*key), string(encriptPlainTextT))
			if err != nil {
				log.Fatalf("write file err: %v", err.Error())
			}
			errWrite:= ioutil.WriteFile("textresult.txt", []byte(decriptTextT), 0777)
			if errWrite != nil {
				log.Fatalf("write file err: %v", err.Error())
			}
			if err != nil {
				log.Fatalf("write file err: %v", err.Error())
			}
		}
		if *mes != ""{
			decM,_:=DecryptMessage([]byte(*key),*mes)
			fmt.Println(decM)
			}
		 
	}
}

func EncryptMessage(key []byte, message string) (string, error) {
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

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func DecryptMessage(key []byte, message string) (string, error) {
	cipherText, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "", fmt.Errorf("could not base64 decode: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}

	if len(cipherText) < aes.BlockSize {
		return "", fmt.Errorf("invalid ciphertext block size")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), nil
}
