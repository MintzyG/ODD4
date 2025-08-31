package repos

import (
	"GoAuth/models"
	"errors"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AuthRepo struct {
	DB *gorm.DB
}

func NewAuthRepo(db *gorm.DB) *AuthRepo {
	return &AuthRepo{DB: db}
}

func (r *AuthRepo) CreateUser(user *models.User) error {
	err := r.DB.Create(user).Error
	if err != nil {
		return errors.New("error creating user: " + err.Error())
	}
	return nil
}

func (r *AuthRepo) CreateUserVerification(userID string, verificationNumber int) error {
	v := &models.UserVerification{
		ID:                 userID,
		VerificationNumber: verificationNumber,
		ExpiresAt:          time.Now().Add(time.Minute * 15),
	}
	if err := r.DB.Create(v).Error; err != nil {
		return errors.New("could not create verification number: " + err.Error())
	}
	return nil
}

func (r *AuthRepo) GetUserVerification(userID string) (models.UserVerification, error) {
	var verification models.UserVerification
	err := r.DB.Where("id = ?", userID).First(&verification).Error
	return verification, err
}

func (r *AuthRepo) DeleteUserVerification(userID string) error {
	return r.DB.Where("id = ?", userID).Unscoped().Delete(&models.UserVerification{}).Error
}

func (r *AuthRepo) UpdateUserVerification(userID string, verificationNumber int) error {
	result := r.DB.Model(&models.UserVerification{}).
		Where("id = ?", userID).
		Updates(map[string]interface{}{
			"verification_number": verificationNumber,
			"expires_at":          time.Now().Add(time.Minute * 15),
		})

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return r.CreateUserVerification(userID, verificationNumber)
	}

	return nil
}

func (r *AuthRepo) CreateSuperUser() {
	var existingUser models.User
	err := r.DB.Where("email = ?", viper.GetString("SCTI_EMAIL")).First(&existingUser).Error
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(viper.GetString("MASTER_USER_PASS")), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal("could not hash password for master user")
	}

	userID := uuid.New().String()
	MasterUser := &models.User{
		ID:         userID,
		Name:       "Master",
		LastName:   "User",
		Email:      viper.GetString("SCTI_EMAIL"),
		IsVerified: true,
		UserPass: models.UserPass{
			ID:       userID,
			Password: string(hashedPassword),
		},
		IsEventCreator: true,
		IsSuperUser:    true,
	}

	err = r.DB.Create(MasterUser).Error
	if err != nil {
		log.Fatal("could not create master user")
	}
}

func (r *AuthRepo) UserExists(email string) (bool, error) {
	var user models.User
	err := r.DB.Where("email = ?", email).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (r *AuthRepo) FindUserByEmail(email string) (models.User, error) {
	var user models.User
	err := r.DB.
		Preload("UserPass").
		Where("email = ?", email).
		First(&user).Error

	if err != nil {
		return models.User{}, err
	}
	return user, nil
}

func (r *AuthRepo) FindUserByID(id string) (models.User, error) {
	var user models.User
	err := r.DB.
		Preload("UserPass").
		Where("id = ?", id).
		First(&user).Error

	if err != nil {
		return models.User{}, err
	}
	return user, nil
}

func (r *AuthRepo) UpdateUser(user *models.User) error {
	return r.DB.Save(user).Error
}

func (r *AuthRepo) CreateRefreshToken(userID, refreshToken string) error {
	token := models.RefreshToken{
		UserID:   userID,
		TokenStr: refreshToken,
	}

	err := r.DB.Create(&token).Error
	if err != nil {
		return err
	}

	return nil
}

func (r *AuthRepo) GetRefreshTokens(userID string) ([]models.RefreshToken, error) {
	var tokens []models.RefreshToken
	err := r.DB.Where("user_id = ?", userID).Find(&tokens).Error
	if err != nil {
		return nil, err
	}
	return tokens, nil
}

func (r *AuthRepo) UpdateRefreshToken(userID, oldToken, newToken string) error {
	return r.DB.Model(&models.RefreshToken{}).
		Where("user_id = ? AND token_str = ?", userID, oldToken).
		Update("token_str", newToken).Error
}

func (r *AuthRepo) FindRefreshToken(userID, tokenStr string) (*models.RefreshToken, error) {
	var token models.RefreshToken
	err := r.DB.
		Where("user_id = ? AND token_str = ?", userID, tokenStr).
		First(&token).Error

	if err != nil {
		return nil, err
	}

	return &token, nil
}

func (r *AuthRepo) DeleteRefreshToken(userID, tokenStr string) error {
	return r.DB.
		Where("user_id = ? AND token_str = ?", userID, tokenStr).
		Delete(&models.RefreshToken{}).Error
}

func (r *AuthRepo) GetAllAdminStatusFromUser(userID string) ([]models.AdminStatus, error) {
	var adminStatuses []models.AdminStatus
	err := r.DB.Where("user_id = ?", userID).Find(&adminStatuses).Error
	if err != nil {
		return nil, err
	}
	return adminStatuses, nil
}

func (r *AuthRepo) UpdateUserPassword(userID string, hashedPassword string) error {
	result := r.DB.Model(&models.UserPass{}).
		Where("id = ?", userID).
		Update("password", hashedPassword)

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	return nil
}

func (r *AuthRepo) ChangeUserName(userID string, name, lastName string) error {
	return r.DB.Model(&models.User{}).
		Where("id = ?", userID).
		Update("name", name).
		Update("last_name", lastName).Error
}
