package jwtful

import (
	"github.com/dgrijalva/jwt-go"
	"testing"
	"time"
)

func TestSigning(t *testing.T) {
	priv, _, err := GenerateKey(512)
	if err != nil {
		t.Fatal()
	}
	//println(EncodePrivateKey(priv))
	signer := NewJwtEncoder(EncodePrivateKey(priv), jwt.SigningMethodRS256)
	token, err := signer.SignToken("fasdf", "fsda", false)
	if err != nil {
		print(err.Error())
	}
	time.Sleep(500 * time.Millisecond)
	//println(token)
	tokenInfo, err := signer.Verify(token)
	if err != nil {
		print(err.Error())
	}
	println(tokenInfo.String())
}
