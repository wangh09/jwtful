package authenticator

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"strings"
)

func (ag *JwtHandler) updatePrivateKey(key []byte, method jwt.SigningMethod) error {
	ag.signedKey = key
	ag.method = method
	if ag.isEs() {
		privateKey, err := jwt.ParseECPrivateKeyFromPEM(ag.signedKey)
		if err != nil {
			return err
		}
		ag.privateKey = privateKey
		ag.publicKey = privateKey.PublicKey
	} else if ag.isRsOrPS() {
		privKey, err := jwt.ParseRSAPrivateKeyFromPEM(key)
		if err != nil {
			return err
		}
		ag.privateKey = privKey
		ag.publicKey = privKey.Public()
	} else if ag.isHs() {
		ag.privateKey = ag.signedKey
	} else {
		return errors.New("invalid method type")
	}
	return nil
}
func (ag *JwtHandler) updatePublicKey(key []byte, method jwt.SigningMethod) error {
	ag.method = method
	if ag.isEs() {
		publicKey, err := jwt.ParseECPublicKeyFromPEM(key)
		if err != nil {
			return err
		}
		ag.publicKey = publicKey
	} else if ag.isRsOrPS() {
		publicKey, err := jwt.ParseRSAPublicKeyFromPEM(key)
		if err != nil {
			return err
		}
		ag.publicKey = publicKey
	} else if ag.isHs() {
		ag.privateKey = key
	} else {
		return errors.New("invalid method type")
	}
	return nil
}
func (a *JwtHandler) isEs() bool {
	return strings.HasPrefix(a.method.Alg(), "ES")
}
func (a *JwtHandler) isRsOrPS() bool {
	isRs := strings.HasPrefix(a.method.Alg(), "RS")
	isPs := strings.HasPrefix(a.method.Alg(), "PS")
	return isRs || isPs
}
func (a *JwtHandler) isHs() bool {
	return strings.HasPrefix(a.method.Alg(), "HS")
}

