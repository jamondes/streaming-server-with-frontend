package app

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"
)

var blacklistedTokens = make(map[string]bool)

func LoginHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var loginReq LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		user, err := RetrieveUserByEmail(db, loginReq.Email)
		if err != nil {
			HandleDBError(w, err)
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginReq.Password)); err != nil {
			http.Error(w, "Invalid email or password", http.StatusUnauthorized)
			return
		}

		tokenString, err := GenerateToken(user)
		if err != nil {
			log.Println("Error generating JWT:", err)
			http.Error(w, "Failed to log in", http.StatusInternalServerError)
			return
		}

		RespondWithToken(w, tokenString, user.Email)
	}
}

func CreateAccountHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user User
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		if err := CreateUser(db, &user); err != nil {
			HandleDBError(w, err)
			return
		}

		tokenString, err := GenerateToken(user)
		if err != nil {
			log.Println("Error generating JWT:", err)
			http.Error(w, "Failed to create account", http.StatusInternalServerError)
			return
		}

		RespondWithToken(w, tokenString, user.Email)
	}
}

// Additional helper functions could be added here to handle common tasks, e.g.:
func HandleDBError(w http.ResponseWriter, err error) {
	if err == gorm.ErrRecordNotFound {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
	} else {
		log.Println("Error retrieving user:", err)
		http.Error(w, "Failed to log in", http.StatusInternalServerError)
	}
}

// ExtractTokenFromHeader extracts JWT token from the Authorization header
func ExtractTokenFromHeader(authorizationHeader string) (string, error) {
	if authorizationHeader == "" {
		return "", fmt.Errorf("no Authorization header provided")
	}

	parts := strings.Split(authorizationHeader, " ")
	if len(parts) != 2 {
		return "", fmt.Errorf("malformed Authorization header")
	}

	return parts[1], nil
}

// TokenValidationMiddleware to validate the JWT token
func TokenValidationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorizationHeader := r.Header.Get("Authorization")

		if authorizationHeader == "" {
			http.Error(w, "Unauthorized1", http.StatusUnauthorized)
			return
		}
		// Parse the token from the Authorization header
		tokenString := strings.Split(authorizationHeader, " ")[1]

		if _, exists := blacklistedTokens[tokenString]; exists {
			http.Error(w, "Unauthorized - blacklisted token", http.StatusUnauthorized)
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Provide your secret key used for signing the tokens
			return []byte("secret-key-zapping"), nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized2", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func BlacklistToken(token string) {
	blacklistedTokens[token] = true
}

func RespondWithToken(w http.ResponseWriter, tokenString string, email string) {
	tokenResponse := map[string]string{
		"token": tokenString,
		"email": email,
	}
	json.NewEncoder(w).Encode(tokenResponse)
}
