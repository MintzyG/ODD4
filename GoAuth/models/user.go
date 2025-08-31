package models

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

type User struct {
	ID           string   `gorm:"type:varchar(36);primaryKey;" json:"id"`
	Name         string   `gorm:"not null" json:"name"`
	LastName     string   `gorm:"not null" json:"last_name"`
	Email        string   `gorm:"unique;not null" json:"email"`
	IsVerified   bool     `gorm:"default:false" json:"is_verified"`
	UserPass     UserPass `gorm:"foreignKey:ID;references:ID;constraint:OnDelete:CASCADE" json:"-"`
	IsUenf       bool     `json:"is_uenf"`
	UenfSemester int      `json:"uenf_semester"`

	CreatedAt time.Time      `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time      `gorm:"autoUpdateTime" json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"autoDeleteTime" json:"deleted_at,omitempty"`

	IsEventCreator bool `gorm:"default:false" json:"is_event_creator"`
	IsSuperUser    bool `gorm:"default:false" json:"is_super_user"`
}

func (User) TableName() string {
	return "users"
}

type UserPass struct {
	ID       string `gorm:"type:varchar(36);primaryKey" json:"id"`
	Password string `gorm:"not null" json:"password"`

	CreatedAt time.Time      `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time      `gorm:"autoUpdateTime" json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"autoDeleteTime" json:"deleted_at,omitempty"`
}

func (UserPass) TableName() string {
	return "user_pass"
}

type RefreshToken struct {
	gorm.Model
	UserID   string `gorm:"type:varchar(36);" json:"user_id"`
	TokenStr string `gorm:"type:varchar(1024);" json:"token_str"`
}

type UserRegister struct {
	gorm.Model
	Name         string `gorm:"not null"`
	LastName     string `gorm:"not null" json:"last_name"`
	Email        string `gorm:"unique;not null"`
	Password     string `gorm:"not null"`
	IsUenf       bool   `json:"is_uenf"`
	UenfSemester int    `json:"uenf_semester"`
}

type UserLogin struct {
	gorm.Model
	Email    string `gorm:"unique;not null"`
	Password string `gorm:"not null"`
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
