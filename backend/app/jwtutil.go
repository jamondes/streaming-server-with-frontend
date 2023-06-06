package app

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

const (
	secretKey  = "secret-key-zapping"
	expiration = time.Hour * 24
)

func GenerateToken(user User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"exp":   time.Now().Add(expiration).Unix(),
	})

	return token.SignedString([]byte(secretKey))
}
