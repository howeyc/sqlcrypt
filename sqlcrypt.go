package sqlcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"unicode/utf16"
)

// Message Format
// 01 bytes - Version
// 03 bytes - Reserved (zeros)
// 16 bytes - IV
// XX bytes - Encrypted Portion:
//      04 bytes - MAGIC Bytes
//      02 bytes - Auth Verification Length
//      02 bytes - Plaintext Length (before padding)
//      XX bytes - Encrypted Plaintext (padded)

var magicNum uint32 = 0xBAADF00D

const sql_v2 = 0x02

func passphraseToKey(passphrase string) []byte {
	var runes []rune
	for _, l := range passphrase {
		runes = append(runes, l)
	}
	windowsPhrase := utf16.Encode(runes)
	var keybuf bytes.Buffer
	binary.Write(&keybuf, binary.LittleEndian, windowsPhrase)

	key := sha256.Sum256(keybuf.Bytes())
	return key[:]
}

// EncryptByPassphrase creates an encrypted byte slice matching the same
// format and as the SQL Server function. It creates a V2 format, without
// authenticator.
// It can be decrypted by SQL Server 2017 or later.
func EncryptByPassphrase(passphrase, plaintext string) ([]byte, error) {
	var encbuf bytes.Buffer
	encbuf.WriteByte(sql_v2)
	encbuf.WriteByte(0x00)
	encbuf.WriteByte(0x00)
	encbuf.WriteByte(0x00)

	iv := make([]byte, aes.BlockSize)
	io.ReadFull(rand.Reader, iv)
	encbuf.Write(iv)

	var ptbuf bytes.Buffer
	binary.Write(&ptbuf, binary.LittleEndian, magicNum)
	binary.Write(&ptbuf, binary.LittleEndian, uint16(0)) // No Authenticator
	binary.Write(&ptbuf, binary.LittleEndian, uint16(len(plaintext)))
	ptbuf.WriteString(plaintext)

	padLen := aes.BlockSize - (ptbuf.Len() % aes.BlockSize)
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	ptbuf.Write(padding)

	cyphertext := make([]byte, ptbuf.Len())

	key := passphraseToKey(passphrase)
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cyphertext, ptbuf.Bytes())

	encbuf.Write(cyphertext)

	return encbuf.Bytes(), nil
}

// DecryptByPassphrase decrypts an encrypted byte slice in the SQL format, only
// only V2 format is supported. Authenticator is unsupported.
func DecryptByPassphrase(passphrase string, cyphertext []byte) (string, error) {
	// Only support V2 (AES)
	if cyphertext[0] != sql_v2 {
		return "", errors.New("SQL V2 Only!")
	}

	key := passphraseToKey(passphrase)

	block, e := aes.NewCipher(key)
	if e != nil {
		return "", e
	}

	iv := make([]byte, aes.BlockSize)
	io.ReadFull(rand.Reader, iv)

	mode := cipher.NewCBCDecrypter(block, cyphertext[4:20])

	dst := make([]byte, len(cyphertext)-20)
	mode.CryptBlocks(dst, cyphertext[20:])

	if binary.LittleEndian.Uint32(dst[:4]) != magicNum {
		return "", errors.New("Magic Bytes failed!")
	}
	if binary.LittleEndian.Uint16(dst[4:6]) != 0 {
		return "", errors.New("Authenticator unsupported.")
	}

	ptLen := binary.LittleEndian.Uint16(dst[6:8])

	return string(dst[8 : 8+ptLen]), nil
}
