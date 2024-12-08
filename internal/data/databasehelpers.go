package data

import (
	"context"
	"log"
	"time"

	"github.com/Jcastel2014/test3/internal/validator"
)

func (b BookClub) GetAllById(id int64) ([]*Book, error) {

	query := `
	
	SELECT B.id, B.title, B.isbn, A.name AS author, B.publication_date, B.genre, B.description, B.average_rating
	FROM books AS B
	INNER JOIN book_authors AS BA 
	ON B.id = BA.book_id
	INNER JOIN authors AS A 
	ON A.id = BA.author_id
	INNER JOIN book_list AS BL
	ON BL.book_id = B.id
	WHERE BL.list_id = $1
	
	`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	rows, err := b.DB.QueryContext(ctx, query, id)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	books := []*Book{}

	for rows.Next() {
		var book Book
		err := rows.Scan(&book.ID, &book.Title, &book.ISBN, &book.Author, &book.Publication_Date, &book.Genre, &book.Description, &book.Average_rating)
		if err != nil {
			return nil, err
		}

		books = append(books, &book)
	}

	err = rows.Err()
	if err != nil {
		return nil, err
	}

	return books, nil

}

func (b BookClub) DoesAuthorExists(author string) (error, int) {
	query := `
		SELECT id
		FROM authors
		WHERE name = $1
	`
	args := []any{author}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var id int

	err := b.DB.QueryRowContext(ctx, query, args...).Scan(&id)

	log.Println(id)

	if err != nil {
		return err, -1
	}

	return nil, id
}

func (b BookClub) DoesBookExists(id int64) error {
	query := `
		SELECT id
		FROM books
		WHERE id = $1
	`
	args := []any{id}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return b.DB.QueryRowContext(ctx, query, args...).Scan(&id)

}

func (b BookClub) DoesListExists(id int64) error {
	query := `
		SELECT id
		FROM readList
		WHERE id = $1
	`
	args := []any{id}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return b.DB.QueryRowContext(ctx, query, args...).Scan(&id)

}

func (b BookClub) DoesUserExists(id int64) error {
	query := `
		SELECT id
		FROM users
		WHERE id = $1
	`
	args := []any{id}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return b.DB.QueryRowContext(ctx, query, args...).Scan(&id)

}

func (b BookClub) UpdateAverage(id int64) error {

	query := `
	UPDATE books
	SET average_rating = (select AVG(rating) from book_reviews WHERE book_id = $1)
	WHERE id = $1
`
	args := []any{id}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := b.DB.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	return nil
}

func ValidateBook(v *validator.Validator, book *Book) {

	v.Check(book.Title != "", "title", "must be provided")
	v.Check(len(book.Title) <= 255, "title", "must not be more than 100 byte long")

	v.Check(book.ISBN != "", "isbn", "must be provided")
	v.Check(len(book.ISBN) <= 255, "isbn", "must not be more than 100 byte long")

	v.Check(book.Author != "", "author", "must be provided")
	v.Check(len(book.Author) <= 100, "author", "must not be more than 100 characters long")

	v.Check(book.Genre != "", "genre", "must be provided")
	v.Check(len(book.Genre) <= 50, "genre", "must not be more than 50 characters long")

	v.Check(len(book.Description) <= 1000, "description", "must not be more than 1000 characters long")

	v.Check(!book.Publication_Date.IsZero(), "publication_date", "must be provided")
	v.Check(book.Publication_Date.Before(time.Now()), "publication_date", "must not be in the future")

	// v.Check(review.Rating > 0, "rating", "must be greater than 0")
	// v.Check(review.Rating <= 5, "rating", "must be less than 5")
	// v.Check(len(review.Comment) <= 100, "comment", "must not be more than 100 byte long")

}

func ValidateListInt(v *validator.Validator, list *ReadListInt) {

	v.Check(list.Name != "", "name", "must be provided")
	v.Check(len(list.Name) <= 255, "name", "must not be more than 100 byte long")

	v.Check(len(list.Description) <= 1000, "description", "must not be more than 1000 characters long")

	// v.Check(list.Status != "", "status", "must be provided")
	// v.Check(len(list.Status) <= 50, "status", "must not be more than 50 characters long")

	// v.Check(list.Status == "Completed" || list.Status == "Currently Reading", "status", "must be Completed or Currently Reading")

}

func ValidateList(v *validator.Validator, list *ReadList) {

	v.Check(list.Name != "", "name", "must be provided")
	v.Check(len(list.Name) <= 255, "name", "must not be more than 100 byte long")

	v.Check(len(list.Description) <= 1000, "description", "must not be more than 1000 characters long")

	v.Check(list.Status != "", "status", "must be provided")
	v.Check(len(list.Status) <= 50, "status", "must not be more than 50 characters long")

	// v.Check(list.Status == "Completed" || list.Status == "Currently Reading", "status", "must be Completed or Currently Reading")

}

func ValidateReview(v *validator.Validator, review *ReviewIn) {

	v.Check(review.Review != "", "name", "must be provided")
	v.Check(len(review.Review) <= 255, "name", "must not be more than 100 byte long")

	v.Check(review.Rating > 0, "rating", "rating must be greater than 0")
	v.Check(review.Rating <= 10, "rating", "rating must be less than 10")
}

func (u UserModel) GetAllById(id int64) ([]*Book, error) {

	query := `
	
	SELECT B.id, B.title, B.isbn, A.name AS author, B.publication_date, B.genre, B.description, B.average_rating
	FROM books AS B
	INNER JOIN book_authors AS BA 
	ON B.id = BA.book_id
	INNER JOIN authors AS A 
	ON A.id = BA.author_id
	INNER JOIN book_list AS BL
	ON BL.book_id = B.id
	WHERE BL.list_id = $1
	
	`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	rows, err := u.DB.QueryContext(ctx, query, id)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	books := []*Book{}

	for rows.Next() {
		var book Book
		err := rows.Scan(&book.ID, &book.Title, &book.ISBN, &book.Author, &book.Publication_Date, &book.Genre, &book.Description, &book.Average_rating)
		if err != nil {
			return nil, err
		}

		books = append(books, &book)
	}

	err = rows.Err()
	if err != nil {
		return nil, err
	}

	return books, nil

}
