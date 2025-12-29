// Package rsa
// @Description: RSA + AES-GCM 混合加密
package rsa

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
)

// GenerateRSAKeyPairBase64 生成 RSA 公钥/私钥（Base64）
func GenerateRSAKeyPairBase64() (pubB64, priB64 string, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	priBytes := x509.MarshalPKCS1PrivateKey(priv)
	priB64 = base64.StdEncoding.EncodeToString(priBytes)

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", "", err
	}
	pubB64 = base64.StdEncoding.EncodeToString(pubBytes)
	return
}

func parsePublicKey(b64 string) (*rsa.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}

	keyAny, err := x509.ParsePKIXPublicKey(raw)
	if err != nil {
		return nil, err
	}

	pub, ok := keyAny.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not rsa public key")
	}
	return pub, nil
}

func parsePrivateKey(b64 string) (*rsa.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PrivateKey(raw)
}

// HybridEncryptBase64
// 返回一个 Base64 加密串
func HybridEncryptBase64(publicKeyB64 string, plain []byte) (string, error) {
	pub, err := parsePublicKey(publicKeyB64)
	if err != nil {
		return "", err
	}
	aesKey := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, aesKey); err != nil {
		return "", err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	cipherData := gcm.Seal(nil, nonce, plain, nil)
	encryptedKey, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		pub,
		aesKey,
		nil,
	)
	if err != nil {
		return "", err
	}
	buf := bytes.NewBuffer(nil)
	_ = binary.Write(buf, binary.BigEndian, uint32(len(encryptedKey)))
	buf.Write(encryptedKey)
	buf.Write(nonce)
	buf.Write(cipherData)

	//return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
	return base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil

}

// HybridDecryptBase64
// 只需要私钥 + 加密串
func HybridDecryptBase64(privateKeyB64 string, cipherB64 string) ([]byte, error) {
	priv, err := parsePrivateKey(privateKeyB64)
	if err != nil {
		return nil, err
	}

	raw, err := base64.RawURLEncoding.DecodeString(cipherB64)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewReader(raw)
	var keyLen uint32
	if err = binary.Read(buf, binary.BigEndian, &keyLen); err != nil {
		return nil, err
	}
	encryptedKey := make([]byte, keyLen)
	if _, err = io.ReadFull(buf, encryptedKey); err != nil {
		return nil, err
	}
	aesKey, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		priv,
		encryptedKey,
		nil,
	)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(buf, nonce); err != nil {
		return nil, err
	}
	cipherData, err := io.ReadAll(buf)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, cipherData, nil)
}
