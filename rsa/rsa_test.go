package rsa

import (
	"bytes"
	"testing"
)

func TestHybridOneString(t *testing.T) {
	pub, pri, _ := GenerateRSAKeyPairBase64()

	plain := []byte(`{"uid":1001,"scope":"admin"}`)

	enc, err := HybridEncryptBase64(pub, plain)
	if err != nil {
		t.Fatal(err)
	}

	dec, err := HybridDecryptBase64(pri, enc)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plain, dec) {
		t.Fatal("decrypt mismatch")
	}

	t.Log("success:", string(dec))
}
