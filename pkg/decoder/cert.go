package decoder

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func DecodePemCert(data []byte) (cert *x509.Certificate, rest []byte, err error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, rest, errors.New("decode cert failed: bad cert")
	}
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, rest, err
	}
	return cert, rest, nil
}

func DecodePemPrivateKey(data []byte) (key *rsa.PrivateKey, rest []byte, err error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, rest, errors.New("decode private key failed: bad key")
	}
	key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, rest, err
	}
	return key, rest, nil
}
