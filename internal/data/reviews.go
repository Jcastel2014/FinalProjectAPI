package data

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"
)

type ReviewIn struct {
	ID         int64     `json:"id"`
	Book_id    int64     `json:"book_id"`
	User_id    int64     `json:"user_id"`
	Review     string    `json:"review"`
	Created_at time.Time `json:"created_at"`
	Rating     float64   `json:"rating"`
}

type Review struct {
	ID         int64     `json:"id"`
	Book       string    `json:"title"`
	User       string    `json:"user_name"`
	Review     string    `json:"review"`
	Created_at time.Time `json:"created_at"`
	Rating     float64   `json:"rating"`
}

func (b BookClub) InsertReview(review *ReviewIn) error {

	err := b.DoesBookExists(review.Book_id)

	if err != nil {
		return BookNotFound
	}

	err = b.DoesUserExists(review.User_id)

	if err != nil {
		return UserNotFound
	}

	// args := []any{book.Author}
	// ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	// defer cancel()

	// err = b.DB.QueryRowContext(ctx, query, args...).Scan(&idA)

	query := `
	
	INSERT INTO book_reviews (book_id, user_id, review, rating, created_at) 
	VALUES ($1, $2, $3, $4, $5) RETURNING id;
	
	`

	args := []any{review.Book_id, review.User_id, review.Review, review.Rating, review.Created_at}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err = b.DB.QueryRowContext(ctx, query, args...).Scan(&review.ID)

	if err != nil {

		return err
	}

	return b.UpdateAverage(review.Book_id)

}

func (b BookClub) GetAllReviews(filters Filters, id int64) ([]*Review, error) {
	query := fmt.Sprintf(`
	SELECT R.id, B.title, U.username, R.review, R.rating, R.created_at FROM book_reviews AS R
	INNER JOIN books AS B ON R.book_id = B.id 
	INNER JOIN users AS U ON R.user_id = U.id
	WHERE R.book_id = $3
	ORDER BY %s %s, B.id ASC
	LIMIT $1 OFFSET $2
	`, filters.sortColumn(), filters.sortDirection())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	rows, err := b.DB.QueryContext(ctx, query, filters.limit(), filters.offset(), id)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	reviews := []*Review{}

	for rows.Next() {
		var review Review
		err := rows.Scan(&review.ID, &review.Book, &review.User, &review.Review, &review.Rating, &review.Created_at)
		if err != nil {
			return nil, err
		}

		reviews = append(reviews, &review)
	}

	err = rows.Err()
	if err != nil {
		return nil, err
	}

	return reviews, nil
}

func (b BookClub) DeleteReview(id int64) error {

	query := `
	DELETE FROM book_reviews
	WHERE id = $1
	RETURNING book_id
	`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var bookID int64
	err := b.DB.QueryRowContext(ctx, query, id).Scan(&bookID)
	if err != nil {
		if err == sql.ErrNoRows {
			return ErrRecordNotFound
		}
		return err
	}

	log.Println(bookID)
	return b.UpdateAverage(bookID)
}

func (b BookClub) GetReview(id int64) (*ReviewIn, error) {
	if id < 1 {
		return nil, ErrRecordNotFound
	}
	query := `
	SELECT id, book_id, user_id, review, rating, created_at
	FROM book_reviews 
	WHERE id = $1

	`

	args := []any{id}

	var review ReviewIn

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := b.DB.QueryRowContext(ctx, query, args...).Scan(&review.ID, &review.Book_id, &review.User_id, &review.Review, &review.Rating, &review.Created_at)
	if err != nil {
		log.Println("hello")
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, ErrRecordNotFound
		default:
			return nil, err
		}
	}
	return &review, nil

}

func (b BookClub) UpdateReview(review *ReviewIn, id int64) error {

	query := `
	UPDATE book_reviews
	SET review = $2, rating = $3
	WHERE id = $1
	RETURNING book_id


	`

	args := []any{id, review.Review, review.Rating}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := b.DB.QueryRowContext(ctx, query, args...).Scan(&review.Book_id)

	if err != nil {
		return err
	}
	log.Println("swag")
	return b.UpdateAverage(review.Book_id)

}
