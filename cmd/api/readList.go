package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/Jcastel2014/test3/internal/data"
	"github.com/Jcastel2014/test3/internal/validator"
)

func (a *appDependencies) postReadingList(w http.ResponseWriter, r *http.Request) {

	var incomingData struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Created_by  int64  `json:"created_by"`
	}

	err := a.readJSON(w, r, &incomingData)
	if err != nil {
		a.badRequestResponse(w, r, err)
		return
	}
	readList := &data.ReadListInt{
		Name:        incomingData.Name,
		Description: incomingData.Description,
		Created_by:  incomingData.Created_by,
	}

	v := validator.New()
	data.ValidateListInt(v, readList)

	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)
		return
	}

	err = a.bookclub.InsertList(readList)

	if err != nil {
		a.serverErrResponse(w, r, err)
		return
	}

	headers := make(http.Header)
	headers.Set("Location", fmt.Sprintf("/list/%d", readList.ID))

	data := envelope{
		"readList": readList,
	}

	err = a.writeJSON(w, http.StatusCreated, data, headers)

	if err != nil {
		a.serverErrResponse(w, r, err)
		return
	}

	fmt.Fprintf(w, "%+v\n", incomingData)

}

func (a *appDependencies) getAllLists(w http.ResponseWriter, r *http.Request) {
	var queryParametersData struct {
		// Product string
		data.Filters
	}

	queryParameters := r.URL.Query()

	queryParametersData.Filters.Sort = a.getSingleQueryParameters(queryParameters, "sort", "id")

	queryParametersData.Filters.SortSafeList = []string{"id", "-id"}

	v := validator.New()

	queryParametersData.Filters.Page = a.getSingleIntegerParameters(queryParameters, "page", 1, v)
	queryParametersData.Filters.PageSize = a.getSingleIntegerParameters(queryParameters, "page_size", 10, v)

	data.ValidateFilters(v, queryParametersData.Filters)
	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)
		return
	}

	readList, err := a.bookclub.GetAllLists(queryParametersData.Filters)

	if err != nil {
		a.serverErrResponse(w, r, err)
		return
	}

	data := envelope{
		"readList": readList,
	}

	err = a.writeJSON(w, http.StatusOK, data, nil)

	if err != nil {
		a.serverErrResponse(w, r, err)
	}
}

func (a *appDependencies) listAddBook(w http.ResponseWriter, r *http.Request) {
	id, err := a.readIDParam(r)

	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	var incomingData struct {
		BookId int64 `json:"bookid"`
	}

	err = a.readJSON(w, r, &incomingData)
	if err != nil {
		a.badRequestResponse(w, r, err)
		return
	}

	err = a.bookclub.ListAddBook(id, incomingData.BookId)

	if err != nil {
		a.serverErrResponse(w, r, err)
		return
	}

	headers := make(http.Header)
	headers.Set("Location", fmt.Sprintf("/BookId/%d", incomingData.BookId))

	data := envelope{
		"readList": incomingData,
	}

	err = a.writeJSON(w, http.StatusCreated, data, headers)

	if err != nil {
		a.serverErrResponse(w, r, err)
		return
	}

	fmt.Fprintf(w, "%+v\n", incomingData)

}

func (a *appDependencies) getList(w http.ResponseWriter, r *http.Request) {

	id, err := a.readIDParam(r)

	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	readList, err := a.bookclub.GetList(id)

	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound):
			a.notFoundResponse(w, r)
		default:
			a.serverErrResponse(w, r, err)
		}

		return
	}

	data := envelope{
		"readList": readList,
	}

	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrResponse(w, r, err)
		return
	}

}

func (a *appDependencies) putReadingList(w http.ResponseWriter, r *http.Request) {

	id, err := a.readIDParam(r)

	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	readList, err := a.bookclub.GetList(id)

	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound):
			a.notFoundResponse(w, r)
		default:
			a.serverErrResponse(w, r, err)
		}

		return
	}

	var incomingData struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		Created_by  *string `json:"created_by"` //takes an intiger
		Status      *string `json:"status"`
	}

	err = a.readJSON(w, r, &incomingData)

	if err != nil {
		a.badRequestResponse(w, r, err)
		return
	}

	if incomingData.Name != nil {
		readList.Name = *incomingData.Name
	}

	if incomingData.Description != nil {
		readList.Description = *incomingData.Description
	}

	var uid int64
	if incomingData.Created_by != nil {

		uid, err = toInt(*incomingData.Created_by)

		if err != nil {
			a.badRequestResponse(w, r, err)
		}

	} else {
		uid = 0
	}

	if incomingData.Status != nil {
		readList.Status = *incomingData.Status
	}

	var status int64

	log.Println(readList.Status)
	if readList.Status == "Completed" {
		status = 2
	} else if readList.Status == "Currently Reading" {
		status = 1
	} else {
		err := errors.New("unable to find Status")
		a.badRequestResponse(w, r, err)
	}

	v := validator.New()

	data.ValidateList(v, readList)
	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)

		return
	}

	err = a.bookclub.UpdateList(readList, id, uid, status)

	if err != nil {
		a.serverErrResponse(w, r, err)
		return
	}

	data := envelope{
		"readList": readList,
	}

	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrResponse(w, r, err)
		return
	}

}

func (a *appDependencies) deleteList(w http.ResponseWriter, r *http.Request) {

	id, err := a.readIDParam(r)

	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	err = a.bookclub.DeleteList(id)

	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound):
			a.notFoundResponse(w, r)
		default:
			a.serverErrResponse(w, r, err)
		}

		return
	}

	data := envelope{
		"message": "list successfully deleted",
	}

	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrResponse(w, r, err)
	}

}

func (a *appDependencies) deleteFromList(w http.ResponseWriter, r *http.Request) {

	var incomingData struct {
		List_id int64 `json:"list_id"`
	}
	err := a.readJSON(w, r, &incomingData)
	if err != nil {
		a.badRequestResponse(w, r, err)
		return
	}

	id, err := a.readIDParam(r)

	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	err = a.bookclub.DeleteFromList(id, incomingData.List_id)

	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound):
			a.notFoundResponse(w, r)
		default:
			a.serverErrResponse(w, r, err)
		}

		return
	}

	data := envelope{
		"message": "book successfully deleted from list",
	}

	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrResponse(w, r, err)
	}

}
