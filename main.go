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
			encF := fromFileToByte(*file, *key)
			err := ioutil.WriteFile("ciphertext.txt", []byte(encF), 0777)
			if err != nil {
				log.Fatalf("write file err: %v", err.Error())
			}
		}
		if *mes != ""{
			encM:=fromMesToByte(*mes, *key)
			fmt.Println(encM)
		}
	}else{
		if *file !=""{
			decF := fromFileToByte(*file, *key)
			err := ioutil.WriteFile("myfile.txt", []byte(decF), 0777)
			if err != nil {
				log.Fatalf("write file err: %v", err.Error())
			}
		}
		if *mes != ""{
			decM:=fromMesToByte(*mes, *key)
			fmt.Println(decM)
			}
		 
	}
}

func fromMesToByte (message string, key string) string {
	byteMsg := []byte(message)
	if *mode{
		res,err:=encode(byteMsg, key)
		if err!= nil{
			return err.Error()
		}
		return res
	}else{
		res,err:=decode(byteMsg, key)
		if err!= nil{
			return err.Error()
		}
		return res
	}
}

func fromFileToByte (message string, key string) string {
	plainText, err := ioutil.ReadFile(message)
	if err != nil {
		log.Fatalf("read file err: %v", err.Error())
	}
	if *mode{
		res,err := encode(plainText, key)
		if err!= nil{
			return err.Error()
		}	
		return res
	}else{
		res,err := decode(plainText, key)
		if err!= nil{
			return err.Error()
		}	
		return res
	}
	
}

func encode(message []byte, key string) (string, error) {
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

func decode(message []byte,key string) (string, error){
	cipherText, err := base64.StdEncoding.DecodeString(string(message))
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
