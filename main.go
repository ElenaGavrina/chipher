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
	"os"
	"strings"
	//"path/filepath"
)

var mess = flag.String("mess","","Enter your text for encription/dencription ")
var mode = flag.Bool("mode",true,"Select encription/dencription mode")
var key = flag.String("key","1234567890abcdef","Enter key for encription/dencription your text")
var file = flag.String("input","","Enter path to your text file")
var result = flag.String("output","","Enter path to file with output result")

func main(){
	flag.Parse()
	if *mode { 
		if *file != ""{
			if checkOutputName(*result){
				log.Fatal("This name is already taken! Please choose another one")
			}
			plainText, err := ioutil.ReadFile(*file)
			if err != nil {
				log.Fatalf("write file err: %v", err.Error())
			}
			encriptText, _ := EncryptMessage([]byte(*key), string(plainText))
			if err != nil {
				log.Fatalf("write file err: %v", err.Error())
			}
			errWrite := ioutil.WriteFile(*result, []byte(encriptText), 0777)
			fmt.Println("The encrypted file has been created")
			if errWrite != nil {
				log.Fatalf("write file err: %v", err.Error())
			}
		}
		if *mess != ""{
			encM, err :=EncryptMessage([]byte(*key), *mess,)
			if err != nil {
				log.Fatalf("write file err: %v", err.Error())
			}
			fmt.Println(encM)
		}
	}else{
		if *file !=""{
			if checkOutputName(*result){
				log.Fatal("This name is already taken! Please choose another one")
			}
			encriptPlainTextT, _ := ioutil.ReadFile(*file)
			decriptTextT, err := DecryptMessage([]byte(*key), string(encriptPlainTextT))
			if err != nil {
				log.Fatalf("write file err: %v", err.Error())
			}
			errWrite:= ioutil.WriteFile(*result, []byte(decriptTextT), 0777)
			fmt.Println("The decrypted file has been created")
			if errWrite != nil {
				log.Fatalf("write file err: %v", err.Error())
			}
		}
		if *mess != ""{
			decM, err :=DecryptMessage([]byte(*key),*mess)
			if err != nil {
				log.Fatalf("write file err: %v", err.Error())
			}
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


func checkOutputName(path string) bool {
	slOfStr := strings.Split(path,string(os.PathSeparator))
	name := slOfStr[len(slOfStr)-1]
	folder := strings.Join(slOfStr[:len(slOfStr)-1],"\\")

	files, err := ioutil.ReadDir(folder)
	if err != nil {
    	fmt.Println(err)
    	os.Exit(1)
	}
 	for _, file := range files {
    	if name == file.Name(){
			return true
    	}
	}
	return false
}
