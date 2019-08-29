package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"golang.org/x/crypto/acme"
	"io/ioutil"
	"os"
	"path/filepath"
)

const (
	acmeFile      = ".letsencrypt"
	acmeHeaderURI = "uri"
	acmeDirectory = "https://acme-v01.api.letsencrypt.org/directory"
	acmeType      = "ACME INFO"
)

var (
	InvalidFormat = errors.New("Invalid file format")
)

func newAcmeClient(ctx context.Context) (*acme.Client, error) {

	fullpath, err := getAcmePath(acmeFile)
	if err != nil {
		return nil, err
	}

	pemBytes, err := ioutil.ReadFile(fullpath)
	if err != nil {
		return nil, err
	}

	pemData, _ := pem.Decode(pemBytes)

	if pemData.Type != acmeType {
		return nil, InvalidFormat
	}

	key, err := x509.ParseECPrivateKey(pemData.Bytes)
	if err != nil {
		return nil, err
	}

	client := &acme.Client{
		Key:          key,
		DirectoryURL: acmeDirectory,
	}
	regUri := pemData.Headers[acmeHeaderURI]

	if regUri == "" {
		return nil, InvalidFormat
	}
	_, err = client.GetReg(ctx, regUri)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func newAcmeReg(ctx context.Context, contact []string) (*acme.Client, error) {
	fullpaht, err := getAcmePath(acmeFile)
	if err != nil {
		return nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	client := &acme.Client{
		Key:          key,
		DirectoryURL: acmeDirectory,
	}

	account, err := client.Register(ctx, &acme.Account{Contact: contact}, acme.AcceptTOS)
	if err != nil {
		return nil, err
	}

	file, err := os.OpenFile(fullpaht, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	bytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	b := &pem.Block{Type: acmeType, Bytes: bytes, Headers: map[string]string{acmeHeaderURI: account.URI}}
	if err := pem.Encode(file, b); err != nil {
		return nil, err
	}
	return client, nil
}

func getAcmePath(base string) (string, error) {
	homedir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homedir, base), nil
}
