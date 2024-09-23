package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

func generateRsaKeyPair(size int) (privKey *rsa.PrivateKey, pubKey *rsa.PublicKey) {
	privKey, _ = rsa.GenerateKey(rand.Reader, size) // step 1
	pubKey = &privKey.PublicKey                     // step 2
	return
}

func exportKeytoPEM(privKey *rsa.PrivateKey, pubKey *rsa.PublicKey) (privPEM, pubPEM string, err error) {
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)
	privPEMBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privKeyBytes,
		},
	)
	privPEM = string(privPEMBytes)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return
	}
	pubPEMBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubKeyBytes,
		},
	)

	pubPEM = string(pubPEMBytes)
	return
}

func main() {
	// Generate the keys
	priv, pub := generateRsaKeyPair(4096)

	// Format the keys into PEM
	privPem, pubPem, _ := exportKeytoPEM(priv, pub)

	// Store the key to file
	writeFile([]byte(privPem), "private.pem")
	writeFile([]byte(pubPem), "public.pem")
	err := http.ListenAndServe(":3333", nil)
	if errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("server closed\n")
	} else if err != nil {
		fmt.Printf("error starting server: %s\n", err)
		os.Exit(1)
	}
}

func writeFile(content []byte, filename string) (err error) {
	filepath := fmt.Sprintf("%s", filename)

	err = ioutil.WriteFile(filepath, content, 0644)
	if err != nil {
		return
	}
	return
}
