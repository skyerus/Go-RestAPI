package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/handlers"

	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

// App export
type App struct {
	Router *mux.Router
	DB     *sql.DB
}

var Store = sessions.NewCookieStore(securecookie.GenerateRandomKey(64))

// Initialize export
func (a *App) Initialize(user, password, dbname string) {
	connectionString :=
		fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", user, password, dbname)

	var err error
	a.DB, err = sql.Open("postgres", connectionString)
	if err != nil {
		log.Fatal(err)
	}
	Store.MaxAge(21600)
	a.Router = mux.NewRouter()
	a.initializeRoutes()
}

func (a *App) initializeRoutes() {
	a.Router.HandleFunc("/api/sign_up", a.createUser).Methods("POST", "OPTIONS")
	a.Router.HandleFunc("/api/login", a.login).Methods("POST", "OPTIONS")
	a.Router.HandleFunc("/api/isLoggedIn", a.isLoggedIn).Methods("GET", "OPTIONS")
	a.Router.HandleFunc("/api/logout", a.logout).Methods("GET", "OPTIONS")
	a.Router.HandleFunc("/api/user/edit/username", a.updateUsername).Methods("PUT", "OPTIONS")
	a.Router.HandleFunc("/api/user/edit/email", a.updateEmail).Methods("PUT", "OPTIONS")
	a.Router.HandleFunc("/api/user/edit/password", a.updatePassword).Methods("PUT", "OPTIONS")
	a.Router.HandleFunc("/api/user", a.deleteUser).Methods("DELETE", "OPTIONS")
	a.Router.HandleFunc("/api/user/bookmark", a.createBookmark).Methods("POST", "OPTIONS")
	a.Router.HandleFunc("/api/user/bookmark", a.getBookmark).Methods("GET", "OPTIONS")
	a.Router.HandleFunc("/api/user/bookmark", a.updateBookmark).Methods("PUT", "OPTIONS")
	a.Router.HandleFunc("/api/user/bookmark", a.deleteBookmark).Methods("DELETE", "OPTIONS")
	a.Router.HandleFunc("/api/user/category", a.createCategory).Methods("POST", "OPTIONS")
	a.Router.HandleFunc("/api/user/category", a.updateCategory).Methods("PUT", "OPTIONS")
	a.Router.HandleFunc("/api/user/category", a.deleteCategory).Methods("DELETE", "OPTIONS")
	a.Router.HandleFunc("/api/user/categories", a.getUserCategories).Methods("GET", "OPTIONS")
	a.Router.HandleFunc("/api/user/bookmarks", a.getUserBookmarks).Methods("GET", "OPTIONS")
	a.Router.HandleFunc("/api/user/category/bookmarks", a.getCategoryBookmarks).Methods("GET", "OPTIONS")
	// a.Router.HandleFunc("/api/user/category/children", a.getChildrenCategories).Methods("GET", "OPTIONS")
	// a.Router.HandleFunc("/api/user/category", a.getCategory).Methods("GET", "OPTIONS")
}

// Run export
func (a *App) Run(addr string) {
	headersOk := handlers.AllowedHeaders([]string{"Content-Type"})
	originOk := handlers.AllowedOrigins([]string{"http://localhost:3000"})
	methodsOk := handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE"})
	credentialsOk := handlers.AllowCredentials()
	log.Fatal(http.ListenAndServe(":8080", handlers.CORS(headersOk, originOk, methodsOk, credentialsOk)(a.Router)))
}

func (a *App) createUser(w http.ResponseWriter, r *http.Request) {
	var u user
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()

	if err := u.hashPassword(); err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := u.createUser(a.DB); err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	session, err := Store.Get(r, "logged_in")
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Cookie not set")
		return
	}
	session.Values["id"] = u.ID
	session.Save(r, w)
	u.Password = "null"
	respondWithJSON(w, http.StatusCreated, u)
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	var uu user
	var u user
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&uu); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()
	if err := u.getUserID(a.DB, uu.Username); err != nil {
		respondWithError(w, http.StatusBadRequest, "No found user")
		return
	}
	if err := u.getUser(a.DB); err != nil {
		respondWithError(w, http.StatusBadRequest, "No found user")
		return
	}
	if checkPasswordHash(uu.Password, u.Password) == false {
		respondWithError(w, 403, "Wrong password")
		return
	}
	session, err := Store.Get(r, "logged_in")
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Cookie not set")
		return
	}
	session.Values["id"] = u.ID
	session.Save(r, w)
	u.Password = "null"
	respondWithJSON(w, http.StatusOK, u)
}

func (a *App) isLoggedIn(w http.ResponseWriter, r *http.Request) {
	session, err := Store.Get(r, "logged_in")
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Could not find session")
		return
	}
	if session.Values != nil {
		respondWithJSON(w, http.StatusOK, map[string]string{"result": "success"})
		return
	}
	respondWithError(w, http.StatusBadRequest, "Could not find a valid session")
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	session, err := Store.Get(r, "logged_in")
	if err != nil {
		respondWithError(w, 404, "Could not find session")
		return
	}
	if session.Values != nil {
		session.Options.MaxAge = -1
	} else {
		respondWithError(w, http.StatusBadRequest, "You're already logged out")
		return
	}
	err = session.Save(r, w)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Could not logout")
		return
	}
	respondWithJSON(w, http.StatusOK, map[string]string{"result": "success"})
}

func (a *App) updateUsername(w http.ResponseWriter, r *http.Request) {
	var u user
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()

	session, err := Store.Get(r, "logged_in")
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't store a session")
		return
	}
	if session.Values != nil {
		u.ID = session.Values["id"].(int)
		session.Save(r, w)
	} else {
		respondWithError(w, http.StatusInternalServerError, "Not logged in")
		return
	}

	if err := u.updateUsername(a.DB); err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJSON(w, http.StatusCreated, map[string]string{"result": "success"})
}

func (a *App) updateEmail(w http.ResponseWriter, r *http.Request) {
	var u user
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()

	session, err := Store.Get(r, "logged_in")
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Not logged in")
		return
	}
	if session.Values != nil {
		u.ID = session.Values["id"].(int)
		session.Save(r, w)
	} else {
		respondWithError(w, http.StatusInternalServerError, "Not logged in")
		return
	}

	if err := u.updateEmail(a.DB); err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJSON(w, http.StatusCreated, map[string]string{"result": "success"})
}

func (a *App) updatePassword(w http.ResponseWriter, r *http.Request) {
	var u user
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()

	if err := u.hashPassword(); err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	session, err := Store.Get(r, "logged_in")
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Not logged in")
		return
	}
	if session.Values != nil {
		u.ID = session.Values["id"].(int)
		session.Save(r, w)
	} else {
		respondWithError(w, http.StatusInternalServerError, "Not logged in")
		return
	}

	if err := u.updatePassword(a.DB); err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJSON(w, http.StatusCreated, map[string]string{"result": "success"})
}

func (a *App) deleteUser(w http.ResponseWriter, r *http.Request) {
	var u user
	var uu user
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&uu); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()

	session, err := Store.Get(r, "logged_in")
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not find session")
		return
	}
	u.ID = session.Values["id"].(int)
	session.Save(r, w)

	if err := u.getUser(a.DB); err != nil {
		respondWithError(w, http.StatusBadRequest, "Can't access user info")
		return
	}

	if checkPasswordHash(uu.Password, u.Password) == false {
		respondWithError(w, 403, "Incorrect password")
		return
	}
	if err := u.deleteUser(a.DB); err != nil {
		respondWithError(w, http.StatusInternalServerError, "Cannot delete user")
		return
	}
	respondWithJSON(w, http.StatusOK, map[string]string{"result": "success"})
}

func (a *App) getBookmark(w http.ResponseWriter, r *http.Request) {
	var b bookmark
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&b); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()
	if err := b.getBookmark(a.DB); err != nil {
		switch err {
		case sql.ErrNoRows:
			respondWithError(w, http.StatusNotFound, "Bookmark not found")
		default:
			respondWithError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	respondWithJSON(w, http.StatusOK, b)
}

func (a *App) getCategoryBookmarks(w http.ResponseWriter, r *http.Request) {
	var b bookmark
	session, err := Store.Get(r, "logged_in")
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not find authorised session")
		return
	}
	if session.Values != nil {
		b.UserID = session.Values["id"].(int)
		session.Save(r, w)
	} else {
		respondWithError(w, http.StatusInternalServerError, "No session found")
		return
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&b); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()
	bookmarks, err := b.getCategoryBookmarks(a.DB)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, bookmarks)
}

func (a *App) getUserBookmarks(w http.ResponseWriter, r *http.Request) {
	var b bookmark
	session, err := Store.Get(r, "logged_in")
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not find authorised session")
		return
	}
	if session.Values != nil {
		b.UserID = session.Values["id"].(int)
		session.Save(r, w)
	} else {
		respondWithError(w, http.StatusInternalServerError, "No session found")
		return
	}

	bookmarks, err := b.getUserBookmarks(a.DB)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, bookmarks)
}

func (a *App) createBookmark(w http.ResponseWriter, r *http.Request) {
	var u user
	var b bookmark
	session, err := Store.Get(r, "logged_in")
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not find authorised session")
		return
	}
	if session.Values != nil {
		u.ID = session.Values["id"].(int)
		session.Save(r, w)
	} else {
		respondWithError(w, http.StatusForbidden, "You are not logged in")
	}

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&b); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()
	b.UserID = u.ID
	if err := b.createBookmark(a.DB); err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJSON(w, http.StatusCreated, b)
}

func (a *App) createCategory(w http.ResponseWriter, r *http.Request) {
	var id int
	var c category
	session, err := Store.Get(r, "logged_in")
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not find authorised session")
		return
	}
	if session.Values != nil {
		id = session.Values["id"].(int)
		session.Save(r, w)
	} else {
		respondWithError(w, http.StatusForbidden, "You are not logged in")
	}

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&c); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		log.Fatal(err)
		return
	}
	defer r.Body.Close()
	c.UserID = id
	if err := c.createCategory(a.DB); err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondWithJSON(w, http.StatusCreated, c)
}

func (a *App) updateCategory(w http.ResponseWriter, r *http.Request) {
	var id int
	var c category
	session, err := Store.Get(r, "logged_in")
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not find authorised session")
		return
	}
	if session.Values != nil {
		id = session.Values["id"].(int)
		session.Save(r, w)
	} else {
		respondWithError(w, http.StatusForbidden, "You are not logged in")
	}

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&c); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()
	c.UserID = id
	if err := c.updateCategory(a.DB); err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		log.Fatal(err)
		return
	}
	respondWithJSON(w, http.StatusOK, c)
}

func (a *App) getChildrenCategories(w http.ResponseWriter, r *http.Request) {
	var c category
	session, err := Store.Get(r, "logged_in")
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not find authorised session")
		return
	}
	if session.Values != nil {
		c.UserID = session.Values["id"].(int)
		session.Save(r, w)
	} else {
		respondWithError(w, http.StatusInternalServerError, "No session found")
		return
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&c); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()
	categories, err := c.getChildrenCategories(a.DB)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, categories)
}

func (a *App) getUserCategories(w http.ResponseWriter, r *http.Request) {
	var c category
	session, err := Store.Get(r, "logged_in")
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not find authorised session")
		return
	}
	if session.Values != nil {
		c.UserID = session.Values["id"].(int)
		session.Save(r, w)
	} else {
		respondWithError(w, http.StatusInternalServerError, "No session found")
		return
	}
	categories, err := c.getUserCategories(a.DB)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		log.Fatal(err)
		return
	}

	respondWithJSON(w, http.StatusOK, categories)
}

func (a *App) getCategory(w http.ResponseWriter, r *http.Request) {
	var c category
	session, err := Store.Get(r, "logged_in")
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not find authorised session")
		return
	}
	if session.Values != nil {
		c.UserID = session.Values["id"].(int)
		session.Save(r, w)
	} else {
		respondWithError(w, http.StatusInternalServerError, "No session found")
		return
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&c); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()
	if err := c.getCategory(a.DB); err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not find order")
		return
	}
	respondWithJSON(w, http.StatusOK, c.Order)
}

func (a *App) updateBookmark(w http.ResponseWriter, r *http.Request) {
	var userid int
	result := make([]bookmark, 0)
	session, err := Store.Get(r, "logged_in")
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not find/start a session")
		return
	}
	if session.Values != nil {
		userid = session.Values["id"].(int)
		session.Save(r, w)
	} else {
		respondWithError(w, http.StatusInternalServerError, "Could not find a session ID")
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&result); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	defer r.Body.Close()
	if result[0].UserID != userid {
		respondWithError(w, http.StatusBadRequest, "You do not have permission to change this bookmark")
		return
	}

	if err := result[1].updateBookmark(a.DB); err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, result[1])
}

func (a *App) deleteBookmark(w http.ResponseWriter, r *http.Request) {
	var id int
	var b bookmark
	session, err := Store.Get(r, "logged_in")
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not find/start a session")
		return
	}
	if session.Values != nil {
		id = session.Values["id"].(int)
		session.Save(r, w)
	} else {
		respondWithError(w, http.StatusInternalServerError, "Could not find a session ID")
		return
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&b); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()
	if err := b.getBookmark(a.DB); err != nil {
		respondWithError(w, http.StatusBadRequest, "Could not find bookmark with this ID")
		return
	}
	if b.UserID != id {
		respondWithError(w, http.StatusBadRequest, "You do not have permission to change this bookmark")
		return
	}

	if err := b.deleteBookmark(a.DB); err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJSON(w, http.StatusOK, map[string]string{"result": "success"})
}

func (a *App) deleteCategory(w http.ResponseWriter, r *http.Request) {
	var id int
	var c category
	session, err := Store.Get(r, "logged_in")
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not find/start a session")
		return
	}
	if session.Values != nil {
		id = session.Values["id"].(int)
		session.Save(r, w)
	} else {
		respondWithError(w, http.StatusInternalServerError, "Could not find a session ID")
		return
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&c); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()
	if err := c.getCategory(a.DB); err != nil {
		respondWithError(w, http.StatusBadRequest, "Could not find category with this ID")
		return
	}
	if c.UserID != id {
		respondWithError(w, http.StatusBadRequest, "You do not have permission to change this category")
		return
	}
	if err := c.deleteCategoryChildren(a.DB); err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		log.Fatal(err)
		return
	}
	if err := c.deleteCategory(a.DB); err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJSON(w, http.StatusOK, map[string]string{"result": "success"})
}

func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, map[string]string{"error": message})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	fmt.Printf("%s\n", response)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

func checkPasswordHash(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
