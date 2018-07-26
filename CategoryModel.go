package main

import (
	"database/sql"

	"github.com/lib/pq"
)

type category struct {
	ID            int     `json:"id"`
	Name          string  `json:"name"`
	Parent        int     `json:"parent"`
	Children      []uint8 `json:"children"`
	BookmarkOrder []uint8 `json:"bookmarkorder"`
	CategoryLoc   []uint8 `json:"categoryloc"`
	Order         []uint8 `json:"order"`
	UserID        int     `json:"userid"`
	OrderID       int     `json:"orderid"`
}

func (c *category) createCategory(db *sql.DB) error {
	err := db.QueryRow(
		"INSERT INTO categories(name,parent,children,bookmarkorder,categoryloc,orderarray,userid,orderid) VALUES($1, $2, $3, $4, $5,$6,$7,$8) RETURNING id",
		c.Name, c.Parent, pq.Array(c.Children), pq.Array(c.BookmarkOrder), pq.Array(c.CategoryLoc), pq.Array(c.Order), c.UserID, c.OrderID).Scan(&c.ID)

	if err != nil {
		return err
	}

	return nil
}

func (c *category) updateCategory(db *sql.DB) error {
	_, err :=
		db.Exec("UPDATE categories SET name=$1,children=$2,bookmarkorder=$3,categoryloc=$4,orderarray=$5 WHERE userid=$6 AND id=$7",
			c.Name, pq.Array(c.Children), pq.Array(c.BookmarkOrder), pq.Array(c.CategoryLoc), pq.Array(c.Order), c.UserID, c.ID)

	return err
}

func (c *category) getChildrenCategories(db *sql.DB) ([]category, error) {
	rows, err := db.Query(
		"SELECT * FROM categories INNER JOIN users ON (categories.userid= $1) WHERE categories.parent=$2", c.UserID, c.Name)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	categories := []category{}
	for rows.Next() {
		var cc category
		if err := rows.Scan(&cc.ID, &cc.Name, &cc.Parent, &cc.Children, &cc.BookmarkOrder, &cc.CategoryLoc, &cc.Order, &cc.UserID, &cc.OrderID); err != nil {
			return nil, err
		}
		categories = append(categories, cc)
	}
	return categories, nil
}

func (c *category) deleteCategoryChildren(db *sql.DB) error {
	if _, err := db.Exec("DELETE from categories WHERE parent=$1 AND userid=$2", c.Name, c.UserID); err != nil {
		return err
	}
	_, err := db.Exec("DELETE from bookmarks WHERE category=$1 AND userid=$2", c.Name, c.UserID)
	return err
}

func (c *category) deleteCategory(db *sql.DB) error {
	_, err := db.Exec("DELETE FROM categories WHERE id=$1", c.ID)
	return err
}

func (c *category) getCategory(db *sql.DB) error {
	return db.QueryRow("SELECT * FROM categories WHERE id=$1", c.ID).Scan(&c.ID, &c.Name, &c.Parent, &c.Children, &c.BookmarkOrder, &c.CategoryLoc, &c.Order, &c.UserID, &c.OrderID)
}

func (c *category) getUserCategories(db *sql.DB) ([]category, error) {
	rows, err := db.Query(
		"SELECT * FROM categories WHERE userid= $1", c.UserID)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	categories := []category{}
	for rows.Next() {
		var cc category
		if err := rows.Scan(&cc.ID, &cc.Name, &cc.Parent, &cc.Children, &cc.BookmarkOrder, &cc.CategoryLoc, &cc.Order, &cc.UserID, &cc.OrderID); err != nil {
			return nil, err
		}
		categories = append(categories, cc)
	}
	return categories, nil
}
