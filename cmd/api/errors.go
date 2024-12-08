package main

import (
	"fmt"
	"log"
	"net/http"
)

func (a *appDependencies) logError(r *http.Request, err error) {
	method := r.Method
	uri := r.URL.RequestURI()
	a.logger.Error(err.Error(), "method", method, "uri", uri)
}

func (a *appDependencies) errResponseJSON(w http.ResponseWriter, r *http.Request, status int, message any) {
	errData := envelope{
		"error": message,
	}
	err := a.writeJSON(w, status, errData, nil)
	if err != nil {
		a.logError(r, err)
		w.WriteHeader(500)
	}
}

func (a *appDependencies) serverErrResponse(w http.ResponseWriter, r *http.Request, err error) {
	a.logError(r, err)
	message := "the server encountered a problem and could not process your request"
	a.errResponseJSON(w, r, http.StatusInternalServerError, message)
}

func (a *appDependencies) notFoundResponse(w http.ResponseWriter, r *http.Request) {
	message := "the requested resource could not be found"
	a.errResponseJSON(w, r, http.StatusNotFound, message)
}

func (a *appDependencies) notAllowedResponse(w http.ResponseWriter, r *http.Request) {
	message := fmt.Sprintf("the %s method is not supported for this resource", r.Method)
	a.errResponseJSON(w, r, http.StatusMethodNotAllowed, message)
}

func (a *appDependencies) badRequestResponse(w http.ResponseWriter, r *http.Request, err error) {
	a.errResponseJSON(w, r, http.StatusBadRequest, err.Error())
}

func (a *appDependencies) failedValidationResponse(w http.ResponseWriter, r *http.Request, errors map[string]string) {
	a.errResponseJSON(w, r, http.StatusUnprocessableEntity, errors)
}

func (a *appDependencies) rateLimitExceededResponse(w http.ResponseWriter, r *http.Request) {
	message := "rate limit exceeded XDDD"

	a.errResponseJSON(w, r, http.StatusTooManyRequests, message)
}

func (a *appDependencies) hello() {
	log.Println("hello")
}

func (a *appDependencies) bookNotFound(w http.ResponseWriter, r *http.Request, err error) {

	a.errResponseJSON(w, r, http.StatusBadRequest, err.Error())
}

func (a *appDependencies) editConflictResponse(w http.ResponseWriter, r *http.Request) {

	message := "unable to update the record due to an edit conflict, please try again"
	a.errResponseJSON(w, r, http.StatusConflict, message)

}

func (a *appDependencies) invalidCredentialsResponse(w http.ResponseWriter, r *http.Request) {
	message := "invalid authentication credentials"
	a.errResponseJSON(w, r, http.StatusUnauthorized, message)
}

func (a *appDependencies) invalidAuthenticationTokenResponse(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("WWW-Authenticate", "Bearer")

	message := "invalid or missing authentication token"
	a.errResponseJSON(w, r, http.StatusUnauthorized, message)

}

func (a *appDependencies) authenticationRequiredResponse(w http.ResponseWriter, r *http.Request) {
	message := "you must be authenticated to access this resource"
	a.errResponseJSON(w, r, http.StatusUnauthorized, message)
}

func (a *appDependencies) inactiveAccountResponse(w http.ResponseWriter, r *http.Request) {
	message := "your user account must be activated to access this resource"
	a.errResponseJSON(w, r, http.StatusForbidden, message)
}

func (a *appDependencies) notPermittedResponse(w http.ResponseWriter, r *http.Request) {
	message := "your user account doesn't have the necessary permissions to access this resource"

	a.errResponseJSON(w, r, http.StatusForbidden, message)
}
