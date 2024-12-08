package main

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
)

func (a *appInstance) routes() http.Handler {
	router := httprouter.New()

	router.HandlerFunc(http.MethodGet, "/", a.home)

	return router
}

// pg 162 for permissions
