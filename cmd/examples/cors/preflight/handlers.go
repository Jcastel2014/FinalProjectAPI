package main

import (
	"html/template"
	"log"
	"net/http"
)

func (a *appInstance) home(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("./cmd/examples/cors/preflight/home.html")
	if err != nil {
		http.Error(w, "Could not load template", http.StatusInternalServerError)
		log.Println("Error parsing template:", err)
		return
	}

	err = tmpl.Execute(w, nil)
	if err != nil {
		http.Error(w, "Error executing template", http.StatusInternalServerError)
		log.Println("Error executing template:", err)
	}
}
