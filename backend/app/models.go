package app

import (
	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	gorm.Model
	Name     string `json:"name"`
	Email    string `json:"email" gorm:"unique_index"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Device struct {
	ID         uint   `gorm:"primaryKey"`
	UserEmail  string `gorm:"not null; foreignKey:UserEmail; references:Email"`
	DeviceName string `gorm:"not null"`
	Token      string `gorm:"not null"`
}

type Subscription struct {
	UserEmail         string `gorm:"not null; foreignKey:UserEmail; references:Email"`
	SubscriptionLevel string `gorm:"not null"`
}

func RetrieveUserByEmail(db *gorm.DB, email string) (User, error) {
	var user User
	err := db.Where("email = ?", email).First(&user).Error
	return user, err
}

func CreateUser(db *gorm.DB, user *User) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.Password = string(hashedPassword)
	return db.Create(user).Error
}
