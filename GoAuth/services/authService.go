package services

import (
	"GoAuth/models"
	"GoAuth/repos"
	"GoAuth/utilities"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AuthService struct {
	AuthRepo  *repos.AuthRepo
	JWTSecret string
}

func NewAuthService(repo *repos.AuthRepo, secret string) *AuthService {
	return &AuthService{
		AuthRepo:  repo,
		JWTSecret: secret,
	}
}

func (s *AuthService) Register(email, password, name, last_name string, isUenf bool, uenfSemester int) error {
	if email == "" || password == "" || name == "" || last_name == "" {
		return errors.New("all fields are required")
	}

	if uenfSemester < 1 || uenfSemester > 10 {
		return errors.New("uenf semester must be between 1 and 10, inclusive")
	}

	email = strings.TrimSpace(strings.ToLower(email))

	// Regex to check email
	if !utilities.IsValidEmail(email) {
		return errors.New("invalid email format")
	}

	exists, err := s.AuthRepo.UserExists(email)
	if err != nil {
		return err
	}

	if exists {
		return errors.New("user already exists")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	userID := uuid.New().String()
	user := &models.User{
		ID:           userID,
		Name:         name,
		LastName:     last_name,
		Email:        email,
		IsVerified:   false,
		IsUenf:       isUenf,
		UenfSemester: uenfSemester,
		UserPass: models.UserPass{
			ID:       userID,
			Password: string(hashedPassword),
		},
	}

	if err := s.AuthRepo.CreateUser(user); err != nil {
		return err
	}

	verificationNumber := utilities.GenerateVerificationCode()

	if err := s.AuthRepo.CreateUserVerification(user.ID, verificationNumber); err != nil {
		return err
	}

	go func() {
		if err := s.SendVerificationEmail(user, verificationNumber); err != nil {
			log.Printf("Failed to send verification email to %s: %v", user.Email, err)
		}
	}()

	return nil
}

type verificationEmailData struct {
	UserName         string
	VerificationCode string
	SupportEmail     string
}

var templateFuncs = template.FuncMap{
	"substr": func(s string, i, j int) string {
		if i >= len(s) {
			return ""
		}
		if j > len(s) {
			j = len(s)
		}
		return s[i:j]
	},
}

func (s *AuthService) SendVerificationEmail(user *models.User, verificationNumber int) error {
	// Skip email sending in test mode
	if os.Getenv("TEST_MODE") == "true" {
		return nil
	}

	from := viper.GetString("SCTI_EMAIL")
	password := viper.GetString("SCTI_APP_PASSWORD")

	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	templatePath := filepath.Join("templates", "verification_email.html")

	file, err := os.Open(templatePath)
	if err != nil {
		return fmt.Errorf("failed to open email template: %v", err)
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read email template: %v", err)
	}

	tmpl, err := template.New("emailTemplate").Funcs(templateFuncs).Parse(string(content))
	if err != nil {
		return fmt.Errorf("failed to parse template: %v", err)
	}

	verificationCode := fmt.Sprintf("%06d", verificationNumber)

	data := verificationEmailData{
		UserName:         user.Name + " " + user.LastName,
		VerificationCode: verificationCode,
		SupportEmail:     viper.GetString("SCTI_EMAIL"),
	}

	var body strings.Builder
	if err := tmpl.Execute(&body, data); err != nil {
		return fmt.Errorf("failed to execute template: %v", err)
	}

	subject := "Verificação de Conta"

	message := []byte(fmt.Sprintf("Subject: %s\r\nMIME-version: 1.0;\r\nContent-Type: text/html; charset=\"UTF-8\";\r\n\r\n%s",
		subject, body.String()))

	auth := smtp.PlainAuth("", from, password, smtpHost)

	err = smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{user.Email}, message)
	if err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}

	return nil
}

func (s *AuthService) VerifyUser(user *models.User, token string) error {
	if user.IsVerified {
		return errors.New("user is already verified")
	}

	storedToken, err := s.AuthRepo.GetUserVerification(user.ID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {

			return errors.New("no verification token found")
		}
		return err
	}

	if storedToken.ExpiresAt.Before(time.Now()) {
		if err := s.AuthRepo.DeleteUserVerification(user.ID); err != nil {
			return errors.New("failed deleting expired verification token: " + err.Error())
		}
		return errors.New("token has expired")
	}

	tokenInt, err := strconv.Atoi(token)
	if err != nil {
		return errors.New("Couldn't parse verification token: " + err.Error())
	}

	if storedToken.VerificationNumber != tokenInt {
		return errors.New("invalid verification token")
	}

	user.IsVerified = true
	err = s.AuthRepo.UpdateUser(user)
	if err != nil {
		return err
	}

	err = s.AuthRepo.DeleteUserVerification(user.ID)
	if err != nil {
		return err
	}
	return nil
}

func (s *AuthService) Login(email, password string, r *http.Request) (string, string, error) {
	if email == "" || password == "" {
		return "", "", errors.New("all fields are required")
	}

	email = strings.TrimSpace(strings.ToLower(email))

	user, err := s.AuthRepo.FindUserByEmail(email)
	if err != nil {
		return "", "", err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.UserPass.Password), []byte(password)); err != nil {
		return "", "", errors.New("invalid password")
	}

	accessToken, err := s.GenerateAcessToken(user)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := s.GenerateRefreshToken(user.ID, r)
	if err != nil {
		return "", "", err
	}

	if err := s.AuthRepo.CreateRefreshToken(user.ID, refreshToken); err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func (s *AuthService) Logout(ID, refreshTokenString string) error {
	err := s.AuthRepo.DeleteRefreshToken(ID, refreshTokenString)
	if err != nil {
		return err
	}
	return nil
}

func (s *AuthService) GetRefreshTokens(userID string) ([]models.RefreshToken, error) {
	tokens, err := s.AuthRepo.GetRefreshTokens(userID)
	if err != nil {
		return nil, err
	}
	return tokens, nil
}

func (s *AuthService) RevokeRefreshToken(userID, tokenStr string) error {
	err := s.AuthRepo.DeleteRefreshToken(userID, tokenStr)
	if err != nil {
		return err
	}
	return nil
}

func (s *AuthService) MakeJSONAdminMap(userID string) (string, error) {
	statuses, err := s.AuthRepo.GetAllAdminStatusFromUser(userID)
	if err != nil && err != gorm.ErrRecordNotFound {
		return "", err
	}

	if len(statuses) == 0 {
		return "", errors.New("user has no admin status")
	}

	adminMap := make(map[string]string)
	for _, status := range statuses {
		adminMap[status.EventID] = string(status.AdminType)
	}

	jsonBytes, err := json.Marshal(adminMap)
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

func (s *AuthService) GenerateTokenPair(user models.User, r *http.Request) (string, string, error) {
	accessToken, err := s.GenerateAcessToken(user)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := s.GenerateRefreshToken(user.ID, r)
	if err != nil {
		return "", "", err
	}

	if err := s.AuthRepo.CreateRefreshToken(user.ID, refreshToken); err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func (s *AuthService) GenerateAcessToken(user models.User) (string, error) {
	adminMap, err := s.MakeJSONAdminMap(user.ID)
	if err != nil && err.Error() != "user has no admin status" {
		return "", err
	}

	if adminMap == "" {
		adminMap = "{}"
	}

	var refreshExpireTime int
	if os.Getenv("TEST_MODE") == "true" {
		refreshExpireTime, err = strconv.Atoi(os.Getenv("TEST_REFRESH_EXPIRE_TIME"))
		if err != nil {
			return "", errors.New("coudln't parse TEST_REFRESH_EXIRE_TIME: " + err.Error())
		}
	} else {
		refreshExpireTime, err = strconv.Atoi(os.Getenv("REFRESH_EXPIRE_TIME"))
		if err != nil {
			return "", errors.New("coudln't parse REFRESH_EXIRE_TIME: " + err.Error())
		}
	}

	expirationTime := time.Now().Add(time.Duration(refreshExpireTime) * time.Minute)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":               user.ID,
		"name":             user.Name,
		"last_name":        user.LastName,
		"email":            user.Email,
		"admin_status":     adminMap,
		"is_verified":      user.IsVerified,
		"is_event_creator": user.IsEventCreator,
		"is_super":         user.IsSuperUser,
		"exp":              expirationTime.Unix(),
	})
	return token.SignedString([]byte(s.JWTSecret))
}

func (s *AuthService) GenerateRefreshToken(userID string, r *http.Request) (string, error) {
	userAgent := r.UserAgent()

	// Se o server estiver atrás de um proxy, use o seguinte:
	ipAddress := r.Header.Get("X-Forwarded-For")

	// ipAddress := r.RemoteAddr

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":         userID,
		"user_agent": userAgent,
		"ip_address": ipAddress,
		"last_used":  time.Now(),
		"exp":        time.Now().Add(2 * 24 * time.Hour).Unix(),
	})
	return token.SignedString([]byte(s.JWTSecret))
}

func (s *AuthService) FindRefreshToken(userID, tokenStr string) (*models.RefreshToken, error) {
	return s.AuthRepo.FindRefreshToken(userID, tokenStr)
}

func (s *AuthService) GeneratePasswordResetToken(userID string) (string, error) {
	claims := &models.PasswordResetClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		UserID:          userID,
		IsPasswordReset: true,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.JWTSecret))
}

func (s *AuthService) SendPasswordResetEmail(user *models.User, resetToken string) error {
	from := viper.GetString("SCTI_EMAIL")
	password := viper.GetString("SCTI_APP_PASSWORD")

	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	resetLink := fmt.Sprintf("%s/change-password?token=%s", viper.GetString("SITE_URL"), resetToken)

	templatePath := filepath.Join("templates", "password_reset_email.html")
	file, err := os.Open(templatePath)
	if err != nil {
		return fmt.Errorf("failed to open email template: %v", err)
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read email template: %v", err)
	}

	tmpl, err := template.New("resetTemplate").Parse(string(content))
	if err != nil {
		return fmt.Errorf("failed to parse template: %v", err)
	}

	data := struct {
		UserName     string
		ResetLink    string
		SupportEmail string
	}{
		UserName:     user.Name + " " + user.LastName,
		ResetLink:    resetLink,
		SupportEmail: viper.GetString("SCTI_EMAIL"),
	}

	var body strings.Builder
	if err := tmpl.Execute(&body, data); err != nil {
		return fmt.Errorf("failed to execute template: %v", err)
	}

	subject := "Redefinição de Senha"
	message := []byte(fmt.Sprintf(
		"Subject: %s\r\nMIME-version: 1.0;\r\nContent-Type: text/html; charset=\"UTF-8\";\r\n\r\n%s",
		subject, body.String()))

	auth := smtp.PlainAuth("", from, password, smtpHost)
	return smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{user.Email}, message)
}

func (s *AuthService) InitiatePasswordReset(email string) error {
	user, err := s.AuthRepo.FindUserByEmail(email)
	if err != nil {
		return errors.New("user not found")
	}

	resetToken, err := s.GeneratePasswordResetToken(user.ID)
	if err != nil {
		return err
	}

	go func() {
		if err := s.SendPasswordResetEmail(&user, resetToken); err != nil {
			log.Printf("Failed to send password reset email to %s: %v", user.Email, err)
		}
	}()

	return nil
}

func (s *AuthService) ChangePassword(userID string, newPassword string) error {
	if newPassword == "" {
		return errors.New("new password cannot be empty")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	return s.AuthRepo.UpdateUserPassword(userID, string(hashedPassword))
}

// SwitchEventCreatorStatus toggles the event creator status for a user
// Only superusers can use this functionality
func (s *AuthService) SwitchEventCreatorStatus(requester models.User, targetUserEmail string) error {
	if !requester.IsSuperUser {
		return errors.New("only superusers can change event creator status")
	}

	targetUser, err := s.AuthRepo.FindUserByEmail(targetUserEmail)
	if err != nil {
		return errors.New("target user not found: " + err.Error())
	}

	targetUser.IsEventCreator = !targetUser.IsEventCreator

	err = s.AuthRepo.UpdateUser(&targetUser)
	if err != nil {
		return errors.New("failed to update user: " + err.Error())
	}

	return nil
}

func (s *AuthService) ChangeUserName(user models.User, name, lastName string) error {
	if name == "" {
		return errors.New("name can't be empty")
	}
	if lastName == "" {
		return errors.New("last name can't be empty")
	}

	user.Name = name
	user.LastName = lastName

	return s.AuthRepo.UpdateUser(&user)
}

func (s *AuthService) ResendVerificationCode(user *models.User) error {
	verificationNumber := utilities.GenerateVerificationCode()
	if err := s.AuthRepo.UpdateUserVerification(user.ID, verificationNumber); err != nil {
		return err
	}

	go func() {
		if err := s.SendVerificationEmail(user, verificationNumber); err != nil {
			log.Printf("Failed to resend verification email to %s: %v", user.Email, err)
		}
	}()

	return nil
}
