package authenticator

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/golang/protobuf/proto"
	"strings"
	"time"
)
type JwtHandler struct {
	IsEncoder 		bool
	signedKey    	[]byte
	method 			jwt.SigningMethod
	privateKey    	interface{}
	publicKey    	interface{}
	accessExpSec 	int64
	refreshExpSec 	int64
}
func NewJwtEncoder(privKeyPem []byte, method jwt.SigningMethod) *JwtHandler {
	ag := &JwtHandler{}
	err :=ag.updatePrivateKey(privKeyPem, method)
	if err != nil {
		return nil
	}
	ag.IsEncoder = true
	return ag
}
func NewJwtDecoder(pubKeyPem []byte, method jwt.SigningMethod) *JwtHandler {
	ag := &JwtHandler{}
	err := ag.updatePublicKey(pubKeyPem, method)
	if err != nil {
		return nil
	}
	ag.IsEncoder = false
	return ag
}
func (s *JwtHandler) SetTokenExpTime(accessExpSec int64, refreshExpSec int64) {
	s.accessExpSec = accessExpSec
	s.refreshExpSec = refreshExpSec
}
func (s *JwtHandler) SignToken(info string, tokenIdx string, isRefresh bool) (string, error) {
	if s.method == nil {
		return "", fmt.Errorf("Invalid signing method.")
	}
	if s.accessExpSec == 0 || s.refreshExpSec == 0 {
		return "", fmt.Errorf("call SetTokenExpTime(accessExpireTime, refreshExpireTime) first")
	}
	i := &TokenInfo{}
	i.Info = info
	i.ExpiresAt = time.Now().Unix()
	if isRefresh {
		i.ExpiresAt += s.refreshExpSec
	} else {
		i.ExpiresAt += s.accessExpSec
	}
	i.Identifier = tokenIdx
	buf, err := proto.Marshal(i)
	if err != nil {
		return "", err
	}
	raw := strings.TrimRight(base64.URLEncoding.EncodeToString(buf), "=")
	sig, err := s.method.Sign(raw, s.privateKey)
	if err != nil {
		return "", err
	}
	token := strings.Join([]string{raw, sig}, ".")
	return token, nil
}
func (s *JwtHandler) GenToken(info string, tokenIdx string) (accessToken string, refreshToken string, err error) {
	accessToken, err = s.SignToken(info, tokenIdx, false)
	if err != nil {
		return
	}
	refreshToken, err = s.SignToken(info, tokenIdx, true)
	if err != nil {
		return
	}
	return
}
func (s *JwtHandler) RefreshToken(oldRefreshToken string) (accessToken string, refreshToken string, err error) {
	ti, err := s.Verify(oldRefreshToken)
	if err != nil {
		return
	}
	if ti.ExpiresAt > time.Now().Unix() {
		err = fmt.Errorf("TOKEN_EXPIRED")
		return
	}
	return s.GenToken(ti.Info, ti.Identifier)
}
func (s *JwtHandler) Verify(token string) (*TokenInfo, error) {
	keys := strings.Split(token, ".")
	err := s.method.Verify(keys[0], keys[1], s.publicKey)
	if err != nil {
		return nil, err
	}
	seg := keys[0]
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}
	buf, err := base64.URLEncoding.DecodeString(seg)
	if err != nil {
		return nil, err
	}
	info := &TokenInfo{}
	err = proto.Unmarshal(buf, info)
	if err != nil {
		return nil, err
	}
	if info.ExpiresAt < time.Now().Unix() {
		return nil, errors.New("TOKEN_EXPIRED")
	}
	return info, nil
}