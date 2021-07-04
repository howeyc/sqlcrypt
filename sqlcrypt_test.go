package sqlcrypt

import (
	"encoding/hex"
	"strings"
	"testing"
)

type testCase struct {
	name         string
	encryptedMsg string
	passphrase   string
	plaintext    string
}

var testCases = []testCase{
	testCase{
		"test1",
		"0x02000000B6950C0318B36D3CD43276E1112A1C32836D706B51CA570785CF37E0E9E9901F",
		"YOUR PASSPHRASE",
		"MESSAGE",
	},
	testCase{
		"short",
		"0x020000006447C52131F536209B1FB5D308E99D5218C971E74C85337CEE8B835C82219D60",
		"a",
		"b",
	},
	testCase{
		"long",
		"0x0200000061B89B98A0589CEDCC7DD1990205F76B801D8C71198565F7465FD008B027E909D00E8F748406D504D1D5028758299342EF89C7CB2C62272C6824BC0F9B5CFA35E37E6C35A6BBC6FCCB07D5F76B62B84F",
		"super long passphrase",
		"a longer encrypted string here, make a poem",
	},
}

func TestDecrypt(t *testing.T) {
	for _, tc := range testCases {
		ct, _ := hex.DecodeString(strings.TrimPrefix(tc.encryptedMsg, "0x"))
		pt, e := DecryptByPassphrase(tc.passphrase, ct)
		if e != nil {
			t.Errorf("Error(%s): %s", tc.name, e)
		}
		if pt != tc.plaintext {
			t.Errorf("Error(%s): expected `%s` got `%s`", tc.name, []byte(tc.plaintext), []byte(pt))
		}
	}
}

func TestCrypto(t *testing.T) {
	for _, tc := range testCases {
		ct, ee := EncryptByPassphrase(tc.passphrase, tc.plaintext)
		if ee != nil {
			t.Errorf("Error(%s): %s", tc.name, ee)
		}
		pt, e := DecryptByPassphrase(tc.passphrase, ct)
		if e != nil {
			t.Errorf("Error(%s): %s", tc.name, e)
		}
		if pt != tc.plaintext {
			t.Errorf("Error(%s): expected `%s` got `%s`", tc.name, []byte(tc.plaintext), []byte(pt))
		}
	}
}
