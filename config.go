package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"

	"golang.org/x/crypto/acme"
)

const (
	acmeFile = ".letsencrypt"
	acmeType = "ACME INFO"
)

var (
	InvalidFormat = errors.New("Invalid file format")
)

func newAcmeClient(ctx context.Context) (*acme.Client, error) {

	homedir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	pemBytes, err := ioutil.ReadFile(filepath.Join(homedir, acmeFile))
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
		DirectoryURL: "https://acme-v01.api.letsencrypt.org/directory",
	}
	regUri := pemData.Headers["uri"]

	if regUri == "" {
		return nil, InvalidFormat
	}
	_, err = client.GetReg(ctx, regUri)
	if err != nil {
		return nil, err
	}

	return client, nil
}
