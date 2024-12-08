package main

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
)

func (a *appDependencies) routes() http.Handler {
	router := httprouter.New()

	router.NotFound = http.HandlerFunc(a.notFoundResponse)
	router.MethodNotAllowed = http.HandlerFunc(a.notAllowedResponse)

	// GET    /api/v1/books              # List all books with pagination
	router.HandlerFunc(http.MethodGet, "/api/v1/books", a.requireActivatedUser(a.GetAllBooks))
	// GET    /api/v1/books/{id}         # Get book details
	router.HandlerFunc(http.MethodGet, "/api/v1/books/:id", a.requireActivatedUser(a.getBook))
	// POST   /api/v1/books              # Add new book
	router.HandlerFunc(http.MethodPost, "/api/v1/books", a.requireActivatedUser(a.postBook))
	// PUT    /api/v1/books/{id}         # Update book details
	router.HandlerFunc(http.MethodPut, "/api/v1/books/:id", a.requireActivatedUser(a.PutBook))
	// DELETE /api/v1/books/{id}         # Delete book
	router.HandlerFunc(http.MethodDelete, "/api/v1/books/:id", a.requireActivatedUser(a.deleteBook))
	// GET    /api/v1/books/search       # Search books by title/author/genre
	router.HandlerFunc(http.MethodGet, "/api/v1/book/search", a.requireActivatedUser(a.searchBook))

	// GET    /api/v1/lists              # Get all reading lists
	router.HandlerFunc(http.MethodGet, "/api/v1/lists", a.requireActivatedUser(a.getAllLists))
	// GET    /api/v1/lists/{id}         # Get specific reading list
	router.HandlerFunc(http.MethodGet, "/api/v1/lists/:id", a.requireActivatedUser(a.getList))
	// POST   /api/v1/lists              # Create new reading list
	router.HandlerFunc(http.MethodPost, "/api/v1/lists", a.requireActivatedUser(a.postReadingList))
	// PUT    /api/v1/lists/{id}         # Update reading list
	router.HandlerFunc(http.MethodPut, "/api/v1/lists/:id", a.requireActivatedUser(a.putReadingList))
	// DELETE /api/v1/lists/{id}         # Delete reading list
	router.HandlerFunc(http.MethodDelete, "/api/v1/lists/:id", a.requireActivatedUser(a.deleteList))
	// POST   /api/v1/lists/{id}/books   # Add book to reading list
	router.HandlerFunc(http.MethodPost, "/api/v1/lists/:id/books", a.requireActivatedUser(a.listAddBook))
	// DELETE /api/v1/lists/{id}/books   # Remove book from reading list
	router.HandlerFunc(http.MethodDelete, "/api/v1/lists/:id/books", a.requireActivatedUser(a.deleteFromList))

	// GET    /api/v1/books/{id}/reviews # Get all reviews for a book
	router.HandlerFunc(http.MethodGet, "/api/v1/books/:id/reviews", a.requireActivatedUser(a.getReviews))
	// POST   /api/v1/books/{id}/reviews # Add new review
	router.HandlerFunc(http.MethodPost, "/api/v1/books/:id/reviews", a.requireActivatedUser(a.postReview))
	// PUT    /api/v1/reviews/{id}       # Update review
	router.HandlerFunc(http.MethodPut, "/api/v1/reviews/:id", a.requireActivatedUser(a.putReview))
	// DELETE /api/v1/reviews/{id}       # Delete review
	router.HandlerFunc(http.MethodDelete, "/api/v1/reviews/:id", a.requireActivatedUser(a.deleteReview))

	router.HandlerFunc(http.MethodPost, "/v1/users", a.registerUserHandler)
	router.HandlerFunc(http.MethodPut, "/v1/users/activated", a.activateUserHandler)
	router.HandlerFunc(http.MethodPost, "/v1/tokens/authentication", a.createAuthenticationTokenHandler)

	// GET    /api/v1/users/{id}         # Get user profile
	router.HandlerFunc(http.MethodGet, "/api/v1/users/:id", a.requireActivatedUser(a.getUser))
	// GET    /api/v1/users/{id}/lists   # Get user's reading lists
	router.HandlerFunc(http.MethodGet, "/api/v1/users/:id/lists", a.requireActivatedUser(a.getUserLists))
	// GET    /api/v1/users/{id}/reviews # Get user's reviews
	router.HandlerFunc(http.MethodGet, "/api/v1/users/:id/reviews", a.requireActivatedUser(a.GetUserReviews))

	return a.recoverPanic(a.enableCORS(a.rateLimit(a.authenticate(router))))
}

// pg 162 for permissions
