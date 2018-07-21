package main_test

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	. "github.com/skyerus/restapi"
)

var a App
var users string = "users"
var bookmarks string = "bookmarks"
var testcookies []*http.Cookie

func TestMain(m *testing.M) {
	a = App{}
	a.Initialize(
		os.Getenv("TEST_DB_USERNAME"),
		os.Getenv("TEST_DB_PASSWORD"),
		os.Getenv("TEST_DB_NAME"))
	ensureTableExists(users)
	ensureTableExists(bookmarks)

	code := m.Run()

	clearTable(users)
	clearTable(bookmarks)

	os.Exit(code)
}

func TestCreateUser(t *testing.T) {
	clearTable(users)

	payload := []byte(`{"username":"bobby","password":"123456","email":"hello@example.com"}`)

	req, _ := http.NewRequest("POST", "/api/sign_up", bytes.NewBuffer(payload))
	response := executeRequest(req)
	testcookies = response.Result().Cookies()
	if testcookies == nil {
		t.Errorf("Expected cookies to be returned")
	}
	checkResponseCode(t, http.StatusCreated, response.Code)

	var m map[string]interface{}
	json.Unmarshal(response.Body.Bytes(), &m)
	if m["result"] != "success" {
		t.Errorf("Expected result to be 'success'. Got '%v'", m["result"])
	}
}

func TestLoginUser(t *testing.T) {
	payload := []byte(`{"username":"bobby","password":"123456"}`)

	req, _ := http.NewRequest("POST", "/api/login", bytes.NewBuffer(payload))
	response := executeRequest(req)
	testcookies = nil
	testcookies = response.Result().Cookies()
	if testcookies == nil {
		t.Errorf("Expected cookies to be returned")
	}
	checkResponseCode(t, http.StatusOK, response.Code)
	var m map[string]interface{}
	json.Unmarshal(response.Body.Bytes(), &m)
	if m["result"] != "success" {
		t.Errorf("Expected result to be 'success'. Got '%v'", m["result"])
	}
}

func TestLogoutUser(t *testing.T) {
	req, _ := http.NewRequest("GET", "/api/logout", nil)
	response := executeRequest(req)
	cookie := response.Result().Cookies()[0]
	if cookie.MaxAge > 0 {
		t.Errorf("Expected MaxAge to be negative")
	}
	checkResponseCode(t, http.StatusOK, response.Code)
	var m map[string]interface{}
	json.Unmarshal(response.Body.Bytes(), &m)
	if m["result"] != "success" {
		t.Errorf("Expected result to be 'success'. Got '%v'", m["result"])
	}
}

func TestLoginUserAgain(t *testing.T) {
	payload := []byte(`{"username":"bobby","password":"123456"}`)

	req, _ := http.NewRequest("POST", "/api/login", bytes.NewBuffer(payload))
	response := executeRequest(req)
	testcookies = nil
	testcookies = response.Result().Cookies()
	if testcookies == nil {
		t.Errorf("Expected cookies to be returned")
	}
	checkResponseCode(t, http.StatusOK, response.Code)
	var m map[string]interface{}
	json.Unmarshal(response.Body.Bytes(), &m)
	if m["result"] != "success" {
		t.Errorf("Expected result to be 'success'. Got '%v'", m["result"])
	}
}

func TestLoginUserWithWrongPW(t *testing.T) {
	payload := []byte(`{"username":"bobby","password":"2123456"}`)

	req, _ := http.NewRequest("POST", "/api/login", bytes.NewBuffer(payload))
	req.AddCookie(testcookies[0])
	response := executeRequest(req)
	checkResponseCode(t, 403, response.Code)

	var m map[string]interface{}
	json.Unmarshal(response.Body.Bytes(), &m)
	if m["result"] == "success" {
		t.Errorf("Expected result to be 'Wrong password'. Got '%v'", m["result"])
	}
}

func TestUpdateUsername(t *testing.T) {
	payload := []byte(`{"username":"newbobby"}`)

	req, _ := http.NewRequest("PUT", "/api/user/edit/username", bytes.NewBuffer(payload))
	req.AddCookie(testcookies[0])
	response := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, response.Code)

	var m map[string]interface{}
	json.Unmarshal(response.Body.Bytes(), &m)
	if m["result"] != "success" {
		t.Errorf("Expected result to be 'success'. Got '%v'", m["result"])
	}
}

func TestUpdateEmail(t *testing.T) {
	payload := []byte(`{"email":"test@newemail.com"}`)

	req, _ := http.NewRequest("PUT", "/api/user/edit/email", bytes.NewBuffer(payload))
	req.AddCookie(testcookies[0])
	response := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, response.Code)

	var m map[string]interface{}
	json.Unmarshal(response.Body.Bytes(), &m)
	if m["result"] != "success" {
		t.Errorf("Expected result to be 'success'. Got '%v'", m["result"])
	}
}

func TestUpdatePassword(t *testing.T) {
	payload := []byte(`{"password":"newpassword"}`)

	req, _ := http.NewRequest("PUT", "/api/user/edit/password", bytes.NewBuffer(payload))
	req.AddCookie(testcookies[0])
	response := executeRequest(req)
	checkResponseCode(t, http.StatusCreated, response.Code)

	var m map[string]interface{}
	json.Unmarshal(response.Body.Bytes(), &m)
	if m["result"] != "success" {
		t.Errorf("Expected result to be 'success'. Got '%v'", m["result"])
	}
}

func TestGetNonExistentBookmark(t *testing.T) {
	clearTable(bookmarks)

	req, _ := http.NewRequest("GET", "/api/user/bookmark/1", nil)
	response := executeRequest(req)

	checkResponseCode(t, http.StatusNotFound, response.Code)

	var m map[string]string
	json.Unmarshal(response.Body.Bytes(), &m)
	if m["error"] != "Bookmark not found" {
		t.Errorf("Expected the 'error' key of the response to be set to 'Bookmark not found'. Got '%s'", m["error"])
	}
}

func TestCreateBookmark(t *testing.T) {
	clearTable(bookmarks)

	payload := []byte(`{"title":"bobby","about":"123456","link":"hello@example.com"}`)

	req, _ := http.NewRequest("POST", "/api/user/bookmark", bytes.NewBuffer(payload))
	req.AddCookie(testcookies[0])
	response := executeRequest(req)

	checkResponseCode(t, http.StatusCreated, response.Code)

	var m map[string]interface{}
	json.Unmarshal(response.Body.Bytes(), &m)

	if m["title"] != "bobby" {
		t.Errorf("Expected username to be 'bobby'. Got '%v'", m["username"])
	}

	if m["about"] != "123456" {
		t.Errorf("Expected password to be '123456'. Got '%v'", m["password"])
	}

	if m["link"] != "hello@example.com" {
		t.Errorf("Expected email to be 'hello@example.com'. Got '%v'", m["email"])
	}

	if m["error"] != nil {
		t.Errorf("Error message: %v", m["error"])
	}

	// the id is compared to 1.0 because JSON unmarshaling converts numbers to
	// floats, when the target is a map[string]interface{}
	if m["id"] != 1.0 {
		t.Errorf("Expected product ID to be '1'. Got '%v'", m["id"])
	}
}

func TestGetBookmark(t *testing.T) {
	req, _ := http.NewRequest("GET", "/api/user/bookmark/1", nil)
	response := executeRequest(req)

	checkResponseCode(t, http.StatusOK, response.Code)
}

func TestUpdateBookmark(t *testing.T) {
	req, _ := http.NewRequest("GET", "/api/user/bookmark/1", nil)
	response := executeRequest(req)
	var originalProduct map[string]interface{}
	json.Unmarshal(response.Body.Bytes(), &originalProduct)

	payload := []byte(`{"title":"bobby -new","about":"12233456","link":"hello@example.comwesr"}`)
	req, _ = http.NewRequest("PUT", "/api/user/bookmark/1", bytes.NewBuffer(payload))
	req.AddCookie(testcookies[0])
	response = executeRequest(req)

	checkResponseCode(t, http.StatusOK, response.Code)

	var m map[string]interface{}
	json.Unmarshal(response.Body.Bytes(), &m)

	if m["id"] != originalProduct["id"] {
		t.Errorf("Expected the id to remain the same (%v). Got %v", originalProduct["id"], m["id"])
	}

	if m["title"] == originalProduct["title"] {
		t.Errorf("Expected the title to change from '%v' to '%v'. Got '%v'", originalProduct["title"], m["title"], m["title"])
	}

	if m["about"] == originalProduct["about"] {
		t.Errorf("Expected the about to change from '%v' to '%v'. Got '%v'", originalProduct["about"], m["about"], m["about"])
	}

	if m["link"] == originalProduct["link"] {
		t.Errorf("Expected the link to change from '%v' to '%v'. Got '%v'", originalProduct["link"], m["link"], m["link"])
	}
}

func TestDeleteBookmark(t *testing.T) {

	req, _ := http.NewRequest("DELETE", "/api/user/bookmark/1", nil)
	req.AddCookie(testcookies[0])
	response := executeRequest(req)

	checkResponseCode(t, http.StatusOK, response.Code)
	var m map[string]string
	json.Unmarshal(response.Body.Bytes(), &m)
	if m["result"] != "success" {
		t.Errorf("Expected the 'result' key of the response to be set to 'Success'. Got '%s'", m["result"])
	}
}

func TestDeleteUser(t *testing.T) {
	payload := []byte(`{"password":"newpassword"}`)

	req, _ := http.NewRequest("PUT", "/api/user/delete", bytes.NewBuffer(payload))
	req.AddCookie(testcookies[0])
	response := executeRequest(req)
	checkResponseCode(t, http.StatusOK, response.Code)

	var m map[string]interface{}
	json.Unmarshal(response.Body.Bytes(), &m)
	if m["result"] != "success" {
		t.Errorf("Expected result to be 'success'. Got '%v'", m["result"])
	}
}

func executeRequest(req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	a.Router.ServeHTTP(rr, req)

	return rr
}

func checkResponseCode(t *testing.T, expected, actual int) {
	if expected != actual {
		t.Errorf("Expected response code %d. Got %d\n", expected, actual)
	}
}

func ensureTableExists(table string) {
	if table == "users" {
		if _, err := a.DB.Exec(tableUsersCreationQuery); err != nil {
			log.Fatal(err)
		}
	} else if table == "bookmarks" {
		if _, err := a.DB.Exec(tableBookmarksCreationQuery); err != nil {
			log.Fatal(err)
		}
	}
}

func clearTable(table string) {
	if table == "users" {
		a.DB.Exec("DELETE FROM users")
		a.DB.Exec("ALTER SEQUENCE users_id_seq RESTART WITH 1")
	} else if table == "bookmarks" {
		a.DB.Exec("DELETE FROM bookmarks")
		a.DB.Exec("ALTER SEQUENCE bookmarks_id_seq RESTART WITH 1")
	}
}

const tableUsersCreationQuery = `CREATE TABLE IF NOT EXISTS users
(
id SERIAL,
username TEXT NOT NULL,
email TEXT NOT NULL,
password TEXT NOT NULL,
CONSTRAINT users_pkey PRIMARY KEY (id)
)`

const tableBookmarksCreationQuery = `CREATE TABLE IF NOT EXISTS bookmarks
(
id SERIAL,
title TEXT NOT NULL,
about TEXT NOT NULL,
link TEXT NOT NULL,
category TEXT,
userid INTEGER REFERENCES users(id),
CONSTRAINT bookmarks_pkey PRIMARY KEY (id)
)`
