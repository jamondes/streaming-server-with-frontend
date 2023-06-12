package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"

	"backend/app"
)

func connectToDatabase(connStr string) (*gorm.DB, error) {
	const maxRetries = 5
	var db *gorm.DB
	var err error

	for i := 0; i < maxRetries; i++ {
		db, err = gorm.Open("postgres", connStr)
		if err == nil {
			return db, nil
		}

		log.Printf("Failed to connect to the database. Retrying in %d seconds...", (i+1)*2)
		time.Sleep(time.Duration(i+1) * 2 * time.Second)
	}

	return nil, err
}

func main() {
	connStr := "postgres://myuser:mypassword@db:5432/myapp?sslmode=disable"

	corsMiddleware := handlers.CORS(
		handlers.AllowedOrigins([]string{"*", "http://localhost:3000"}),
		handlers.AllowedMethods([]string{"GET", "POST", "DELETE"}),
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization"}),
	)

	db, err := connectToDatabase(connStr)
	if err != nil {
		log.Fatal("Failed to connect to the database:", err)
	}
	defer db.Close()

	const hlsDir = "hls"
	const port = 8080
	addr := fmt.Sprintf(":%d", port)

	db.AutoMigrate(&app.User{})
	db.AutoMigrate(&app.Device{})
	db.AutoMigrate(&app.Subscription{})

	fmt.Println("Connected to the PostgreSQL database!")

	router := mux.NewRouter()

	router.HandleFunc("/api/create-account", app.CreateAccountHandler(db)).Methods("POST")
	router.HandleFunc("/api/login", app.LoginHandler(db)).Methods("POST")
	router.HandleFunc("/test", app.TestHandler)
	router.PathPrefix("/stream/").Handler(app.DeviceTokenValidationMiddlewareForFiles(db, http.StripPrefix("/stream/", http.FileServer(http.Dir(hlsDir)))))
	router.HandleFunc("/api/sign-out", app.SignOutHandler(db)).Methods("POST")
	router.HandleFunc("/api/user/devices/{deviceID}", app.DeviceTokenValidationMiddlewareForRoutes(db, app.RemoveUserDeviceHandler(db))).Methods("DELETE")
	router.HandleFunc("/api/user/devices", app.DeviceTokenValidationMiddlewareForRoutes(db, app.GetUserDevicesHandler(db))).Methods("GET")

	fmt.Printf("Starting server on %v\n", port)

	loggerHandler := handlers.LoggingHandler(os.Stdout, corsMiddleware(router))

	log.Fatal(http.ListenAndServe(addr, loggerHandler))
}
