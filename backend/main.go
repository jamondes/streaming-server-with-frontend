package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"

	"backend/app"
)

func main() {
	connStr := "postgres://myuser:mypassword@db:5432/myapp?sslmode=disable"

	corsMiddleware := handlers.CORS(
		handlers.AllowedOrigins([]string{"*", "http://localhost:3000"}),
		handlers.AllowedMethods([]string{"GET", "POST"}),
		handlers.AllowedHeaders([]string{"Content-Type", "Authorization"}),
	)

	db, err := gorm.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Failed to connect to the database:", err)
	}
	defer db.Close()

	db.AutoMigrate(&app.User{})

	fmt.Println("Connected to the PostgreSQL database!")

	router := mux.NewRouter()
	router.HandleFunc("/api/create-account", app.CreateAccountHandler(db)).Methods("POST")
	router.HandleFunc("/api/login", app.LoginHandler(db)).Methods("POST")

	router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Connection to PostgreSQL successful!")
	})

	const hlsDir = "hls"
	const port = 8080

	router.PathPrefix("/stream/").Handler(app.TokenValidationMiddleware(http.StripPrefix("/stream/", http.FileServer(http.Dir(hlsDir)))))

	router.HandleFunc("/api/sign-out", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
		}

		authorizationHeader := r.Header.Get("Authorization")
		if authorizationHeader == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		tokenString, err := app.ExtractTokenFromHeader(authorizationHeader)
		if err != nil {
			log.Fatal("Failed to extract token from header:", err)
		}

		app.BlacklistToken(tokenString)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Token has been blacklisted"))
	})

	fmt.Printf("Starting server on %v\n", port)

	loggerHandler := handlers.LoggingHandler(os.Stdout, corsMiddleware(router))
	log.Fatal(http.ListenAndServe(":8080", loggerHandler))
}
