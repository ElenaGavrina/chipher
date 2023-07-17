package main

import (
	"log"
	"io/ioutil"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"fmt"
	"encoding/base64"
	"os"
	"net/http"
	"encoding/json"
	
)

func encodingString (w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		http.Error(w, "Invalid request method.", http.StatusMethodNotAllowed)
	}

	data, _ := io.ReadAll(r.Body)
	defer r.Body.Close()

	var TextRequest struct {
		Text string
		Key string
	}

	err := json.Unmarshal(data, &TextRequest)
	if err != nil {
		log.Fatalf("Error happened in JSON unmarshal. Err: %s", err)
	}

	enc,err := EncryptMessage(TextRequest.Text, []byte(TextRequest.Key))
	if err != nil {
		log.Fatalf("%v", err.Error())
	}

	res, err := json.Marshal(enc)
	if err != nil {
		log.Fatalf("Error happened in JSON marshal. Err: %s", err)
	}

	fmt.Println(string(res))
	
}

func decodingString (w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		http.Error(w, "Invalid request method.", http.StatusMethodNotAllowed)
	}

	data, _ := ioutil.ReadAll(r.Body)
	defer r.Body.Close()

	var CipherRequest struct {
		Cipher string
		Key string
	}

	err := json.Unmarshal(data, &CipherRequest)
	if err != nil {
		log.Fatalf("Error happened in JSON unmarshal. Err: %s", err)
	}
    
	dec, err := DecryptMessage(CipherRequest.Cipher, []byte(CipherRequest.Key))
	if err != nil {
		log.Fatalf("%v", err.Error())
	}

	res, err := json.Marshal(dec)
	if err != nil {
		log.Fatalf("Error happened in JSON marshal. Err: %s", err)
	}

	fmt.Println(string(res))

}

func encodingFile (w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Invalid request method.", http.StatusMethodNotAllowed)
	}
	
	r.ParseMultipartForm(10 << 20)
	multForm:=r.MultipartForm
	for key := range multForm.File {
		file, fileHeader, err := r.FormFile(key)
    	if err != nil {
        	fmt.Println("Error Retrieving the File")
        	fmt.Println(err)
        	return
    	}
		defer file.Close()
		fmt.Printf("the uploaded file: name[%s], size[%d], header[%#v]\n",
            fileHeader.Filename, fileHeader.Size, fileHeader.Header)

			tempFile, err := ioutil.TempFile("temp-text", "upload-*.txt")
			if err != nil {
				fmt.Println(err)
			}
			defer tempFile.Close()
		
			fileBytes, err := ioutil.ReadAll(file)
			if err != nil {
				fmt.Println(err)
			}
			eKey := multForm.Value["key"][0]
			enc, err := EncryptMessage(string(fileBytes), []byte(eKey))
		
			tempFile.Write([]byte(enc))
	}

}

func decodingFile (w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Invalid request method.", http.StatusMethodNotAllowed)
	}
	
	r.ParseMultipartForm(10 << 20)
	multForm:=r.MultipartForm
	for key := range multForm.File {
		file, fileHeader, err := r.FormFile(key)
    	if err != nil {
        	fmt.Println("Error Retrieving the File")
        	fmt.Println(err)
        	return
    	}
		defer file.Close()
		fmt.Printf("the uploaded file: name[%s], size[%d], header[%#v]\n",
            fileHeader.Filename, fileHeader.Size, fileHeader.Header)

			tempFile, err := ioutil.TempFile("dec-file", "decrypt-*.txt")
			if err != nil {
				fmt.Println(err)
			}
			defer tempFile.Close()
		
			fileBytes, err := ioutil.ReadAll(file)
			if err != nil {
				fmt.Println(err)
			}
			eKey := multForm.Value["key"][0]
			dec, err := DecryptMessage(string(fileBytes), []byte(eKey))
		
			tempFile.Write([]byte(dec))
	}

}

func main(){
	mux := http.NewServeMux()
	mux.HandleFunc("/es", encodingString)
	mux.HandleFunc("/ds", decodingString)
	mux.HandleFunc("/ef", encodingFile)
	mux.HandleFunc("/df", decodingFile)
	err := http.ListenAndServe(":8080", mux)
	if err != nil {
		fmt.Printf("error starting server: %s\n", err)
		os.Exit(1)
	}
	
}

func EncryptMessage(message string,key []byte) (string, error) {
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

func DecryptMessage(message string, key []byte) (string, error) {
	
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
