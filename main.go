package main

import (
	"log"
	"medodstestapp/controllers"
	"medodstestapp/models"
	"net/http"
)

func main() {
	err := models.OpenDb()
	if err != nil {
		log.Fatal("No connection to db... ", err)
	}
	defer models.Db.Close()

	http.HandleFunc("/get-tokens", controllers.GetTokens)         // выдача пары Access, Refresh
	http.HandleFunc("/refresh-tokens", controllers.RefreshTokens) // Refresh операция токенов

	log.Fatal(http.ListenAndServe("localhost:8080", nil))
}
