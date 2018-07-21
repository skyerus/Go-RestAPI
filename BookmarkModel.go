package main

import "database/sql"

type bookmark struct {
	ID       int    `json:"id"`
	Title    string `json:"title"`
	About    string `json:"about"`
	Link     string `json:"link"`
	Category string `json:"category"`
	UserID   int    `json:"userid"`
}

func (b *bookmark) createBookmark(db *sql.DB) error {
	err := db.QueryRow(
		"INSERT INTO bookmarks(title, about, link, category, userid) VALUES($1, $2, $3, $4, $5) RETURNING id",
		b.Title, b.About, b.Link, b.Category, b.UserID).Scan(&b.ID)

	if err != nil {
		return err
	}

	return nil
}

func (b *bookmark) updateBookmark(db *sql.DB) error {
	_, err :=
		db.Exec("UPDATE bookmarks SET title=$1, about=$2, link=$3, category=$4 WHERE id=$5",
			b.Title, b.About, b.Link, b.Category, b.ID)

	return err
}

func (u *user) getBookmarks(db *sql.DB) ([]bookmark, error) {
	rows, err := db.Query(
		"SELECT * FROM bookmarks INNER JOIN users ON (bookmarks.userid= $1)", u.ID)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	bookmarks := []bookmark{}
	for rows.Next() {
		var b bookmark
		if err := rows.Scan(&b.ID, &b.Title, &b.About, &b.Link, &b.Category, &b.UserID); err != nil {
			return nil, err
		}
		bookmarks = append(bookmarks, b)
	}
	return bookmarks, nil
}

func (b *bookmark) getBookmark(db *sql.DB) error {
	return db.QueryRow("SELECT * FROM bookmarks WHERE id=$1",
		b.ID).Scan(&b.ID, &b.Title, &b.About, &b.Link, &b.Category, &b.UserID)
}

func (b *bookmark) deleteBookmark(db *sql.DB) error {
	_, err := db.Exec("DELETE FROM bookmarks WHERE id=$1", b.ID)
	return err
}
