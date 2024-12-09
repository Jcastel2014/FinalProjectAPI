package main

import (
	"errors"
	"net/http"
	"time"

	"github.com/Jcastel2014/test3/internal/data"
	"github.com/Jcastel2014/test3/internal/validator"
)

func (a *appDependencies) passwordReset(w http.ResponseWriter, r *http.Request) {
	var incomingData struct {
		Email string `json:"email"`
	}

	err := a.readJSON(w, r, &incomingData)
	if err != nil {
		a.badRequestResponse(w, r, err)
		return
	}

	v := validator.New()

	data.ValidateEmail(v, incomingData.Email)
	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)
		return
	}

	user, err := a.userModel.GetByEmail(incomingData.Email)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound):
			a.invalidCredentialsResponse(w, r)
		default:
			a.serverErrResponse(w, r, err)
		}
		return
	}

	if !user.Activated {
		a.inactiveAccountResponse(w, r)
		return
	}

	//new activation token to expire in 3 days time
	token, err := a.tokenModel.New(user.ID, 3*24*time.Hour, data.ScopeActivation)
	if err != nil {
		a.serverErrResponse(w, r, err)
		return
	}

	message := envelope{
		"message": "an email will be sent to you containing password reset instructions",
	}

	/*	Send the email as a Goroutine. We do this because it might take a long time
		and we don't want our handler to wait for that to finish. We will implement
		the background() function later
	*/
	a.background(func() {
		data := map[string]any{
			"activationToken": token.PlainText,
			"userID":          user.ID,
			"userEmail":       user.Email,
		}
		err = a.mailer.Send(user.Email, "password_reset.tmpl", data)
		if err != nil {
			a.logger.Error(err.Error())
		}

	})

	//status code 201 resource created
	err = a.writeJSON(w, http.StatusCreated, message, nil)
	if err != nil {
		a.serverErrResponse(w, r, err)
		return
	}

}

func (a *appDependencies) activatePasswordReset(w http.ResponseWriter, r *http.Request) {

	var incomingData struct {
		TokenPlainText string `json:"token"`
		Password       string `json:"password"`
	}

	err := a.readJSON(w, r, &incomingData)

	if err != nil {
		a.badRequestResponse(w, r, err)
		return
	}
	v := validator.New()
	data.ValidatetokenPlaintext(v, incomingData.TokenPlainText)
	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)
		return
	}

	user, err := a.userModel.GetForToken(data.ScopeActivation, incomingData.TokenPlainText)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound):
			v.AddError("token", "invalid or expired activation token")
			a.failedValidationResponse(w, r, v.Errors)
		default:
			a.serverErrResponse(w, r, err)
		}
		return
	}

	user.Activated = true

	err = user.Password.Set(incomingData.Password)
	if err != nil {
		a.serverErrResponse(w, r, err)
		return
	}
	err = a.userModel.Update(user)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrEditConflict):
			a.editConflictResponse(w, r)
		default:
			a.serverErrResponse(w, r, err)
		}
		return
	}

	err = a.tokenModel.DeleteAllForUser(data.ScopeActivation, user.ID)
	if err != nil {
		a.serverErrResponse(w, r, err)
		return
	}

	data := envelope{
		"message": "your password has been succesfully reseted",
	}
	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrResponse(w, r, err)
		return
	}
}
