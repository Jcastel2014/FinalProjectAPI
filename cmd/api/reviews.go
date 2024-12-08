package main

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Jcastel2014/test3/internal/data"
	"github.com/Jcastel2014/test3/internal/validator"
)

func (a *appDependencies) postReview(w http.ResponseWriter, r *http.Request) {

	id, err := a.readIDParam(r)

	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	_, err = a.bookclub.GetBook(id)

	if err != nil {
		a.bookNotFound(w, r, err)
	}

	var incomingData struct {
		User_id    int64   `json:"user_id"`
		Review     string  `json:"review"`
		Created_at string  `json:"created_at"`
		Rating     float64 `json:"rating"`
	}

	err = a.readJSON(w, r, &incomingData)
	if err != nil {
		a.badRequestResponse(w, r, err)
		return
	}
	review := &data.ReviewIn{
		Book_id:    id,
		User_id:    incomingData.User_id,
		Review:     incomingData.Review,
		Created_at: time.Now(),
		Rating:     incomingData.Rating,
	}

	v := validator.New()
	data.ValidateReview(v, review)

	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)
		return
	}

	err = a.bookclub.InsertReview(review)

	if err != nil {
		a.hello()
		a.serverErrResponse(w, r, err)
		return
	}

	headers := make(http.Header)
	headers.Set("Location", fmt.Sprintf("/review/%d", review.ID))

	data := envelope{
		"review": review,
	}

	err = a.writeJSON(w, http.StatusCreated, data, headers)

	if err != nil {
		a.serverErrResponse(w, r, err)
		return
	}

	fmt.Fprintf(w, "%+v\n", incomingData)

}

func (a *appDependencies) getReviews(w http.ResponseWriter, r *http.Request) {

	id, err := a.readIDParam(r)

	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	var queryParametersData struct {
		ID int64
		data.Filters
	}

	queryParametersData.ID = id

	queryParameters := r.URL.Query()

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

	review, err := a.bookclub.GetAllReviews(queryParametersData.Filters, queryParametersData.ID)

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

func (a *appDependencies) deleteReview(w http.ResponseWriter, r *http.Request) {

	id, err := a.readIDParam(r)

	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	err = a.bookclub.DeleteReview(id)

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
		"message": "review successfully deleted",
	}

	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrResponse(w, r, err)
	}

}

func (a *appDependencies) putReview(w http.ResponseWriter, r *http.Request) {

	id, err := a.readIDParam(r)

	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	review, err := a.bookclub.GetReview(id)

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
		Review *string  `json:"review"`
		Rating *float64 `json:"rating"`
	}

	err = a.readJSON(w, r, &incomingData)

	if err != nil {
		a.badRequestResponse(w, r, err)
		return
	}

	if incomingData.Review != nil {
		review.Review = *incomingData.Review
	}

	if incomingData.Rating != nil {
		review.Rating = *incomingData.Rating
	}

	v := validator.New()

	data.ValidateReview(v, review)
	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)

		return
	}

	err = a.bookclub.UpdateReview(review, id)

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
		return
	}

}
