package main

import (
	"database/sql"

	"golang.org/x/crypto/bcrypt"
)

type user struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (u *user) createUser(db *sql.DB) error {
	err := db.QueryRow(
		"INSERT INTO users(username, email, password) VALUES($1, $2, $3) RETURNING id",
		u.Username, u.Email, u.Password).Scan(&u.ID)
	if err != nil {
		return err
	}
	return nil
}

func (u *user) getUserID(db *sql.DB, username string) error {
	return db.QueryRow("SELECT id FROM users WHERE username=$1", username).Scan(&u.ID)
}

func (u *user) deleteUser(db *sql.DB) error {
	_, err := db.Exec("DELETE FROM users WHERE id=$1", u.ID)
	return err
}

func (u *user) updateUsername(db *sql.DB) error {
	_, err :=
		db.Exec("UPDATE users SET username=$1 WHERE id=$2",
			u.Username, u.ID)

	return err
}

func (u *user) updatePassword(db *sql.DB) error {
	_, err :=
		db.Exec("UPDATE users SET password=$1 WHERE id=$2",
			u.Password, u.ID)

	return err
}

func (u *user) updateEmail(db *sql.DB) error {
	_, err :=
		db.Exec("UPDATE users SET email=$1 WHERE id=$2",
			u.Email, u.ID)

	return err
}

func (u *user) getUser(db *sql.DB) error {
	return db.QueryRow("SELECT username, email, password FROM users WHERE id=$1",
		u.ID).Scan(&u.Username, &u.Email, &u.Password)
}

func (u *user) hashPassword() error {
	bytes, err := bcrypt.GenerateFromPassword([]byte(u.Password), 14)
	u.Password = string(bytes)
	return err
}
