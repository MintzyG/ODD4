package models

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

type User struct {
	ID         string `gorm:"type:varchar(36);primaryKey;" json:"id"`
	Name       string `gorm:"not null" json:"name"`
	LastName   string `gorm:"not null" json:"last_name"`
	Email      string `gorm:"unique;not null" json:"email"`
	Password   string `gorm:"not null" json:"-"`
	IsVerified bool   `gorm:"default:false" json:"is_verified"`

	CreatedAt time.Time      `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time      `gorm:"autoUpdateTime" json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"autoDeleteTime" json:"deleted_at,omitempty"`

	IsEventCreator bool `gorm:"default:false" json:"is_event_creator"`
	IsSuperUser    bool `gorm:"default:false" json:"is_super_user"`
}

type UserDTO struct {
	ID         string `gorm:"type:varchar(36);primaryKey;" json:"id"`
	Name       string `gorm:"not null" json:"name"`
	LastName   string `gorm:"not null" json:"last_name"`
	Email      string `gorm:"unique;not null" json:"email"`
	IsVerified bool   `gorm:"default:false" json:"is_verified"`

	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`

	IsEventCreator bool `gorm:"default:false" json:"is_event_creator"`
	IsSuperUser    bool `gorm:"default:false" json:"is_super_user"`
}

func (User) TableName() string {
	return "users"
}

type RefreshToken struct {
	gorm.Model
	UserID   string `gorm:"type:varchar(36);" json:"user_id"`
	TokenStr string `gorm:"type:varchar(1024);" json:"token_str"`
}

type UserRegisterRequest struct {
	Name     string `json:"name" validate:"required,min=2,max=50"`
	LastName string `json:"last_name" validate:"required,min=2,max=50"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8,passwd"`
}

type UserLoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8,passwd"`
}

type RevokeTokenRequest struct {
	Token string `json:"refresh_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." validate:"required,jwt"`
}

type VerifyAccountRequest struct {
	Token string `json:"token" example:"123456" validate:"required,len=6"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type ChangePasswordRequest struct {
	NewPassword string `json:"new_password" validate:"required,passwd"`
}

type SwitchEventCreatorStatusRequest struct {
	Email string `json:"email" example:"user@example.com" validate:"required,email"`
}

type ChangeUserNameRequest struct {
	Name     string `json:"name" validate:"required,min=2,max=50"`
	LastName string `json:"last_name" validate:"required,min=2,max=100"`
}

type AuthTokensResponse struct {
	AccessToken  string `json:"access_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken string `json:"refresh_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
}

type PasswordResetClaims struct {
	jwt.RegisteredClaims
	UserID          string `json:"user_id"`
	IsPasswordReset bool   `json:"is_password_reset"`
}

type UserClaims struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Email       string `json:"email"`
	LastName    string `json:"last_name"`
	IsVerified  bool   `json:"is_verified"`
	AdminStatus string `json:"admin_status"`
	IsMaster    bool   `json:"is_master"`
	IsSuper     bool   `json:"is_super"`
	jwt.RegisteredClaims
}

type UserVerification struct {
	ID                 string    `gorm:"type:varchar(36);primaryKey" json:"id"`
	VerificationNumber int       `gorm:"not null" json:"verification_number"`
	ExpiresAt          time.Time `json:"expires_at"`

	CreatedAt time.Time      `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time      `gorm:"autoUpdateTime" json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"autoDeleteTime" json:"deleted_at,omitempty"`
}

type AdminType string

const (
	AdminTypeMaster AdminType = "master_admin"
	AdminTypeNormal AdminType = "admin"
)

// AdminStatus represents user admin status for events
type AdminStatus struct {
	gorm.Model
	UserID    string    `gorm:"type:varchar(36)"`
	EventID   string    `gorm:"type:varchar(36)"`
	AdminType AdminType `gorm:"type:varchar(20)"`
}

func (AdminStatus) TableName() string {
	return "admin_statuses"
}

type UserContext string

const UserContextValue UserContext = "user"
