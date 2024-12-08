package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Jcastel2014/test3/internal/data"
	"github.com/Jcastel2014/test3/internal/validator"
)

func (a *appDependencies) postBook(w http.ResponseWriter, r *http.Request) {

	var incomingData struct {
		Title            string    `json:"title"`
		ISBN             string    `json:"isbn"`
		Author           string    `json:"author"`
		Genre            string    `json:"genre"`
		Description      string    `json:"description"`
		Publication_Date time.Time `json:"created_at"`
	}

	err := a.readJSON(w, r, &incomingData)
	if err != nil {
		a.badRequestResponse(w, r, err)
		return
	}
	book := &data.Book{
		Title:            incomingData.Title,
		ISBN:             incomingData.ISBN,
		Author:           incomingData.Author,
		Genre:            incomingData.Genre,
		Description:      incomingData.Description,
		Publication_Date: incomingData.Publication_Date,
	}

	v := validator.New()
	data.ValidateBook(v, book)

	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)
		return
	}

	err = a.bookclub.InsertBook(book)

	if err != nil {
		a.serverErrResponse(w, r, err)
		return
	}

	headers := make(http.Header)
	headers.Set("Location", fmt.Sprintf("/book/%d", book.ID))

	data := envelope{
		"book": book,
	}

	err = a.writeJSON(w, http.StatusCreated, data, headers)

	if err != nil {
		a.serverErrResponse(w, r, err)
		return
	}

	fmt.Fprintf(w, "%+v\n", incomingData)

}

func (a *appDependencies) getBook(w http.ResponseWriter, r *http.Request) {

	id, err := a.readIDParam(r)

	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	book, err := a.bookclub.GetBook(id)

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
		"book": book,
	}

	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrResponse(w, r, err)
		return
	}

}

func (a *appDependencies) PutBook(w http.ResponseWriter, r *http.Request) {

	id, err := a.readIDParam(r)

	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	book, err := a.bookclub.GetBook(id)

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
		Title            *string    `json:"title"`
		ISBN             *string    `json:"isbn"`
		Author           *string    `json:"author"`
		Genre            *string    `json:"genre"`
		Description      *string    `json:"description"`
		Publication_Date *time.Time `json:"created_at"`
	}

	err = a.readJSON(w, r, &incomingData)

	if err != nil {
		a.badRequestResponse(w, r, err)
		return
	}

	if incomingData.Title != nil {
		book.Title = *incomingData.Title
	}

	if incomingData.ISBN != nil {
		book.ISBN = *incomingData.ISBN
	}

	if incomingData.Author != nil {
		book.Author = *incomingData.Author
	}

	if incomingData.Genre != nil {
		book.Genre = *incomingData.Genre
	}

	if incomingData.Description != nil {
		book.Description = *incomingData.Description
	}

	if incomingData.Publication_Date != nil {
		book.Publication_Date = *incomingData.Publication_Date
	}

	log.Println(book.ISBN)

	v := validator.New()

	data.ValidateBook(v, book)
	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)

		return
	}

	err = a.bookclub.UpdateBook(book, id)

	if err != nil {
		a.serverErrResponse(w, r, err)
		return
	}

	data := envelope{
		"book": book,
	}

	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrResponse(w, r, err)
		return
	}

}

func (a *appDependencies) deleteBook(w http.ResponseWriter, r *http.Request) {

	id, err := a.readIDParam(r)

	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	err = a.bookclub.DeleteBook(id)

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
		"message": "comment successfully deleted",
	}

	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrResponse(w, r, err)
	}

}

func (a *appDependencies) GetAllBooks(w http.ResponseWriter, r *http.Request) {
	var queryParametersData struct {
		// Product string
		data.Filters
	}

	queryParameters := r.URL.Query()
	// queryParametersData.Product = a.getSingleQueryParameters(queryParameters, "product", "")

	queryParametersData.Filters.Sort = a.getSingleQueryParameters(queryParameters, "sort", "id")
	// queryParametersData.Filters.Sort = a.getSingleQueryParameters(queryParameters, "sort", "rating")
	// queryParametersData.Filters.Sort = a.getSingleQueryParameters(queryParameters, "sort", "helpful_count")
	// queryParametersData.Filters.Sort = a.getSingleQueryParameters(queryParameters, "sort", "created_at")
	// queryParametersData.Filters.Sort = a.getSingleQueryParameters(queryParameters, "sort", "updated_at")

	// queryParametersData.Filters.SortSafeList = []string{"id", "rating", "helpful_count", "created_at", "updated_at", "-id", "-rating", "-helpful_count", "-created_at", "-updated_at"}
	queryParametersData.Filters.SortSafeList = []string{"id", "-id"}

	v := validator.New()

	queryParametersData.Filters.Page = a.getSingleIntegerParameters(queryParameters, "page", 1, v)
	queryParametersData.Filters.PageSize = a.getSingleIntegerParameters(queryParameters, "page_size", 10, v)

	data.ValidateFilters(v, queryParametersData.Filters)
	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)
		return
	}

	// product_id, err := toInt(queryParametersData.Product)

	// if err != nil {
	// 	a.serverErrResponse(w, r, err)
	// 	return
	// }

	review, err := a.bookclub.GetAllBooks(queryParametersData.Filters)

	if err != nil {
		a.serverErrResponse(w, r, err)
		return
	}

	data := envelope{
		"review": review,
	}

	err = a.writeJSON(w, http.StatusOK, data, nil)

	if err != nil {
		a.serverErrResponse(w, r, err)
	}
}

func (a *appDependencies) searchBook(w http.ResponseWriter, r *http.Request) {
	var queryParametersData struct {
		Title  string
		Author string
		Genre  string
		data.Filters
	}

	queryParameters := r.URL.Query()
	queryParametersData.Title = a.getSingleQueryParameters(queryParameters, "title", "")
	queryParametersData.Author = a.getSingleQueryParameters(queryParameters, "author", "")
	queryParametersData.Genre = a.getSingleQueryParameters(queryParameters, "genre", "")

	v := validator.New()

	data.ValidateFilters(v, queryParametersData.Filters)
	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)
		return
	}

	review, err := a.bookclub.SearchBook(queryParametersData.Title, queryParametersData.Author, queryParametersData.Genre)

	if err != nil {
		a.serverErrResponse(w, r, err)
		return
	}

	data := envelope{
		"review": review,
	}

	err = a.writeJSON(w, http.StatusOK, data, nil)

	if err != nil {
		a.serverErrResponse(w, r, err)
	}
}

// func (a *appDependencies) SortReviews(w http.ResponseWriter, r *http.Request) {

// 	var queryParametersData struct {
// 		Name           string
// 		Description    string
// 		Category       string
// 		Average_rating string
// 		Price          string
// 		data.Filters
// 	}
// }
