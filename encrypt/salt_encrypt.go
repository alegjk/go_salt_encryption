package encrypt

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"golang.org/x/crypto/pbkdf2"
	"hash"
)

// the Options struct
type Options struct {
	KeyLen   int
	SaltLen  int
	Iter     int
	HashFunc func() hash.Hash
}

// u
func loadDefaultOptions() *Options {
	return &Options{
		KeyLen:   256,
		SaltLen:  16,
		Iter:     1024,
		HashFunc: sha512.New,
	}
}

func Encrypt(password string, options *Options) (string, string) {
	if options == nil {
		options = loadDefaultOptions()
	}
	salt := newSalt(options.SaltLen)
	return string(salt), hex.EncodeToString(pbkdf2.Key([]byte(password), salt, options.Iter, options.KeyLen, options.HashFunc))
}

func Validate(salt, encryptPassword, rawPassword string, options *Options) bool {
	if options == nil {
		options = loadDefaultOptions()
	}
	return hex.EncodeToString(pbkdf2.Key([]byte(rawPassword), []byte(salt), options.Iter, options.KeyLen, options.HashFunc)) == encryptPassword
}

// The raw source string used to generate the salt.
const sourceStr = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

//Generate a random salt of the specified length
func newSalt(length int) []byte {
	salt := make([]byte, length)
	_, _ = rand.Read(salt)
	for i, item := range salt {
		salt[i] = sourceStr[item%byte(len(sourceStr))]
	}
	return salt
}
