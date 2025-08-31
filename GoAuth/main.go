package main

import (
	"GoAuth/handlers"
	mw "GoAuth/middleware"
	"GoAuth/models"
	"GoAuth/repos"
	"GoAuth/services"
	"fmt"
	"log"
	"net/http"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/rs/cors"
	"github.com/spf13/viper"
)

var DB *gorm.DB

func Migrate() {
	log.Println("running database migrations...")

	err := DB.AutoMigrate(
		&models.User{},
		&models.UserPass{},
		&models.UserVerification{},
		&models.AdminStatus{},
		&models.RefreshToken{},
	)
	if err != nil {
		log.Fatalf("migrations failed: %v", err)
	}

	log.Println("database migrated successfully")
}

func Connect() *gorm.DB {
	var err error

	dsn := fmt.Sprintf("host=%v user=%v password=%v dbname=%v port=%v sslmode=disable TimeZone=America/Sao_Paulo",
		viper.GetString("HOST"),
		viper.GetString("DATABASE_USER"),
		viper.GetString("DATABASE_PASS"),
		viper.GetString("DATABASE"),
		viper.GetString("DATABASE_PORT"))

	gormCfg := &gorm.Config{}
	gormCfg.Logger = logger.Default.LogMode(logger.Info)

	DB, err = gorm.Open(postgres.Open(dsn), gormCfg)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	log.Println("connected to postgres instance")
	return DB
}

func main() {
	viper.AutomaticEnv()
	database := Connect()
	Migrate()

	authRepo := repos.NewAuthRepo(database)
	authService := services.NewAuthService(authRepo, viper.GetString("JWT_SECRET"))
	authHandler := handlers.NewAuthHandler(authService)

	mux := http.NewServeMux()
	authMiddleware := mw.AuthMiddleware(authService)

	mux.HandleFunc("POST /v1/register", authHandler.Register)
	mux.HandleFunc("POST /v1/login", authHandler.Login)
	mux.Handle("POST /v1/logout", authMiddleware(http.HandlerFunc(authHandler.Logout)))
	mux.Handle("POST /v1/revoke", authMiddleware(http.HandlerFunc(authHandler.RevokeRefreshToken)))
	mux.Handle("POST /v1/verify", authMiddleware(http.HandlerFunc(authHandler.VerifyAccount)))
	mux.Handle("POST /v1/forgot", authMiddleware(http.HandlerFunc(authHandler.ForgotPassword)))
	mux.Handle("POST /v1/change", authMiddleware(http.HandlerFunc(authHandler.ChangePassword)))
	mux.Handle("POST /v1/resend", authMiddleware(http.HandlerFunc(authHandler.ResendVerificationCode)))
	mux.HandleFunc("GET /v1/users", authHandler.GetUsers)
	//mux.HandleFunc("POST /v1/verify-tokens", authHandler.VerifyJWT)

	corsMux := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization", "Refresh"},
		AllowCredentials: true,
	}).Handler(mux)

	log.Println("Started server on port: " + viper.GetString("PORT"))
	log.Fatal(http.ListenAndServe(":"+viper.GetString("PORT"), corsMux))
}
