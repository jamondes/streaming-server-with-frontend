package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
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
		deviceInfo := getDeviceInfoFromUserAgentAndRequest(userAgent, r)

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
		deviceInfo := getDeviceInfoFromUserAgentAndRequest(userAgent, r)

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

// DeviceTokenValidationMiddleware to validate the token against the Device table
func DeviceTokenValidationMiddlewareForFiles(db *gorm.DB, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isTokenValid := TokenValidationMiddleware(db, w, r)

		if isTokenValid {
			next.ServeHTTP(w, r)
		}
	})
}

// TokenValidationMiddleware to validate the JWT token
func DeviceTokenValidationMiddlewareForRoutes(db *gorm.DB, next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isTokenValid := TokenValidationMiddleware(db, w, r)

		if isTokenValid {
			next(w, r)
		}
	})
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

func GetUserDevicesHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the token from the request header
		authorizationHeader := r.Header.Get("Authorization")
		if authorizationHeader == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		tokenString := strings.Split(authorizationHeader, " ")[1]

		// Extract the user's email from the token
		userEmail, err := extractUserEmailFromToken(tokenString)

		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Fetch the user's devices from the database
		devices, err := fetchUserDevicesFromDB(db, userEmail)
		if err != nil {
			http.Error(w, "Failed to fetch devices", http.StatusInternalServerError)
			return
		}

		// Return the devices as JSON response
		response := struct {
			Devices []Device `json:"devices"`
		}{
			Devices: devices,
		}
		json.NewEncoder(w).Encode(response)
	}

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
	return "", fmt.Errorf("invalid token")
}

func fetchUserDevicesFromDB(db *gorm.DB, userEmail string) ([]Device, error) {
	// Query the database to fetch the user's devices based on the email using the provided db parameter
	// Implement your own logic to query the database and retrieve the devices
	// Example:
	var devices []Device
	if err := db.Where("user_email = ?", userEmail).Find(&devices).Error; err != nil {
		return nil, err
	}
	return devices, nil
}

func createDeviceToken(email string, token string, deviceInfo string, db *gorm.DB) (string, error) {
	// Create a new Device instance
	device := Device{
		UserEmail:  email,
		DeviceName: deviceInfo,
		Token:      token,
	}

	// Store the Device in the database
	if err := db.Create(&device).Error; err != nil {
		return "Error while creating the token in the device table", err
	}

	return token, nil
}

func getDeviceInfoFromUserAgentAndRequest(userAgentArg string, r *http.Request) string {
	ua := useragent.Parse(userAgentArg)
	deviceInfo := fmt.Sprintf("Device: %s %s  Ip: %s", ua.OS, ua.OSVersion, r.RemoteAddr)
	return deviceInfo
}

func removeDeviceByToken(db *gorm.DB, token string) error {
	// Delete records from the device table where the token matches
	result := db.Where("token = ?", token).Delete(&Device{})
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func RemoveUserDeviceHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authorizationHeader := r.Header.Get("Authorization")
		if authorizationHeader == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		tokenString := strings.Split(authorizationHeader, " ")[1]

		// Verify the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Provide your secret key used for signing the tokens
			return []byte("secret-key-zapping"), nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized - Invalid token", http.StatusUnauthorized)
			return
		}

		// Extract the email from the token claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Unauthorized - Invalid token", http.StatusUnauthorized)
			return
		}
		email, ok := claims["email"].(string)
		if !ok {
			http.Error(w, "Unauthorized - Invalid token", http.StatusUnauthorized)
			return
		}

		// Get the device ID from the request URL params
		deviceID := mux.Vars(r)["deviceID"]

		// Get the device with the provided ID
		var device Device
		result := db.Where("id = ?", deviceID).First(&device)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				http.Error(w, "Device not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Check if the device email matches the token email
		if device.UserEmail != email {
			http.Error(w, "Unauthorized - Device email does not match token email", http.StatusUnauthorized)
			return
		}

		// Delete the device from the table
		if err := db.Delete(&device).Error; err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
	}
}

func TokenValidationMiddleware(db *gorm.DB, w http.ResponseWriter, r *http.Request) bool {
	authorizationHeader := r.Header.Get("Authorization")

	if authorizationHeader == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}

	// Parse the token from the Authorization header
	tokenString := strings.Split(authorizationHeader, " ")[1]

	// Verify the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Provide your secret key used for signing the tokens
		return []byte("secret-key-zapping"), nil
	})

	if err != nil || !token.Valid {
		removeDeviceByToken(db, tokenString)
		http.Error(w, "Unauthorized - Invalid token", http.StatusUnauthorized)
		return false
	}

	// Check if the token exists in the Device table
	var device Device
	result := db.Where("token = ?", tokenString).First(&device)
	if result.Error != nil {
		removeDeviceByToken(db, tokenString)
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			http.Error(w, "Unauthorized - Invalid token", http.StatusUnauthorized)
			return false
		}
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return false
	}
	return true
}
