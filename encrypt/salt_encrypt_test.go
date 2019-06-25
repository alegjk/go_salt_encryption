package encrypt

import (
	"crypto/md5"
	"encoding/hex"
	"testing"
)

func TestEncryptWithDefaultOptions(t *testing.T) {
	salt, encryptStr := Encrypt("hello,world", nil)
	encryptBytes, err := hex.DecodeString(encryptStr)
	if err != nil {
		t.Errorf("the encrypt result can't be decoded:%s.\n", encryptStr)
	}
	t.Logf("the salt length is:%d.\n", len(salt))
	t.Logf("the encryptBytes length is:%d.\n", len(encryptBytes))
}

func TestEncryptWithCertainOptions(t *testing.T) {
	options := &Options{KeyLen: 256,
		SaltLen:  32,
		Iter:     4096,
		HashFunc: md5.New,
	}
	_, encryptStr := Encrypt("hello,world", options)
	_, err := hex.DecodeString(encryptStr)
	if err != nil {
		t.Errorf("the encrypt result can't be decoded:%s.\n", encryptStr)
	}
}

func TestValidate(t *testing.T) {
	password := "hello,world"
	salt, encryptStr := Encrypt(password, nil)
	result := Validate(salt, encryptStr, "hello,world", nil)
	if !result {
		t.Error("The validation function does not perform as expected, please check the source code.")
	}
}
