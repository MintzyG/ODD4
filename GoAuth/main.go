package main

import (
	"GoAuth/handlers"
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

	mux.HandleFunc("POST /v1/register", authHandler.Register)
	mux.HandleFunc("POST /v1/login", authHandler.Login)
	mux.HandleFunc("POST /v1/logout", authHandler.Logout)
	mux.HandleFunc("POST /v1/revoke", authHandler.RevokeRefreshToken)
	mux.HandleFunc("POST /v1/verify", authHandler.VerifyAccount)
	mux.HandleFunc("POST /v1/forgot", authHandler.ForgotPassword)
	mux.HandleFunc("POST /v1/change", authHandler.ChangePassword)
	mux.HandleFunc("POST /v1/resend", authHandler.ResendVerificationCode)
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
