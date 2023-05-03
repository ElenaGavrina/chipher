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
			err := (ioutil.WriteFile("ciphertext.bin", []byte(encF), 0777))
			if err != nil {
				log.Fatalf("write file err: %v", err.Error())
			}
		}
		if *mes != ""{
			encM,err:=fromMesToByte(*mes, *key)
			if err!=nil{
				log.Fatalf("write string err: %v", err.Error())
			}
			fmt.Println(base64.StdEncoding.EncodeToString(encM))
		}
	}
}

func fromMesToByte(message string, key string) ([]byte,error){
	byteMsg := []byte(message)
	res,err:=encode(byteMsg, key)
	if err!= nil{
		return nil,err
	}
	return res,nil
}
func fromFileToByte(message string, key string)[]byte{
	plainText, err := ioutil.ReadFile(message)
	if err != nil {
		log.Fatalf("read file err: %v", err.Error())
	}
	res,err := encode(plainText, key)
	if err!= nil{
		return nil
	}
	return res
}
func encode(message []byte,key string)([]byte,error){
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, fmt.Errorf("could not create new cipher: %v", err)
	}
	cipherText := make([]byte, aes.BlockSize+len(message))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("could not encrypt: %v", err)
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], message)
	return message,nil
}
