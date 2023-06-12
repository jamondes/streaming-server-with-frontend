package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	"github.com/mileusna/useragent"
	"golang.org/x/crypto/bcrypt"
)

func SignOutHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	authorizationHeader := r.Header.Get("Authorization")
	if authorizationHeader == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tokenString, err := ExtractTokenFromHeader(authorizationHeader)
	if err != nil {
		http.Error(w, "Failed to extract token from header", http.StatusBadRequest)
		return
	}

		removeDeviceByToken(db, tokenString)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Token has been blacklisted"))
}
}

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
		userAgent := r.Header.Get("User-Agent")
		deviceInfo := getDeviceInfoFromUserAgent(userAgent)

		createDeviceToken(user.Email, tokenString, deviceInfo, db)

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

		userAgent := r.Header.Get("User-Agent")
		deviceInfo := getDeviceInfoFromUserAgent(userAgent)

		createDeviceToken(user.Email, tokenString, deviceInfo, db)

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

// TokenValidationMiddleware to validate the JWT token
func TokenValidationMiddleware2(next http.HandlerFunc) http.HandlerFunc {
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

		next(w, r)
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
func TestHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Connection to PostgreSQL successful!")
}

func GetUserDevicesHandler(w http.ResponseWriter, r *http.Request) {
	// Extract the user email from the authentication token
	userEmail, err := extractUserEmailFromToken(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Query the database to fetch all devices associated with the user email
	devices, err := fetchUserDevicesFromDB(userEmail)
	if err != nil {
		http.Error(w, "Failed to fetch user devices", http.StatusInternalServerError)
		return
	}

	// Return the list of devices as a response
	response := struct {
		Devices []Device `json:"devices"`
	}{
		Devices: devices,
	}
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonBytes)
}

func extractUserEmailFromToken(tokenString string) (string, error) {
	// Parse the token from the string
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Provide your secret key used for signing the tokens
		return []byte("secret-key-zapping"), nil
	})
	if err != nil {
		return "", err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userEmail := claims["email"].(string)
		return userEmail, nil
	}
	return "", fmt.Errorf("Invalid token")
}
