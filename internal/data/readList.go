package data

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"
)

type ReadListInt struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Created_by  int64  `json:"created_by"`
	Status      string `json:"status"`
	Book        []*Book
}

type ReadList struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Created_by  string `json:"created_by"`
	Status      string `json:"status"`
	Book        []*Book
}

func (b BookClub) InsertList(readList *ReadListInt) error {

	err := b.DoesUserExists(readList.Created_by)

	if err != nil {
		return err
	}

	query := `
	INSERT INTO readList(name, description, created_by, status)
	VALUES ($1, $2, $3, 1)
	RETURNING id
	
	`

	args := []any{readList.Name, readList.Description, readList.Created_by}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return b.DB.QueryRowContext(ctx, query, args...).Scan(&readList.ID)

}

func (b BookClub) GetAllLists(filters Filters) ([]*ReadList, error) {
	query := fmt.Sprintf(`
	SELECT R.id, R.name, R.description, U.username AS created_by, S.name as status 
	FROM readList AS R 
	INNER JOIN users AS U 
	ON R.created_by = U.id 
	INNER JOIN status AS S 
	ON R.status = S.id
	ORDER BY %s %s, R.id ASC
	LIMIT $1 OFFSET $2
	`, filters.sortColumn(), filters.sortDirection())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	rows, err := b.DB.QueryContext(ctx, query, filters.limit(), filters.offset())
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	readLists := []*ReadList{}

	for rows.Next() {
		var readList ReadList
		err := rows.Scan(&readList.ID, &readList.Name, &readList.Description, &readList.Created_by, &readList.Status)
		if err != nil {
			return nil, err
		}
		readList.Book, err = b.GetAllById(readList.ID)
		if err != nil {
			return nil, err
		}

		readLists = append(readLists, &readList)
	}

	err = rows.Err()
	if err != nil {
		return nil, err
	}

	return readLists, nil
}

func (b BookClub) ListAddBook(id int64, bid int64) error {
	err := b.DoesBookExists(bid)

	if err != nil {
		return err
	}

	err = b.DoesListExists(id)

	if err != nil {
		return err
	}

	query := `
	INSERT INTO book_list (book_id, list_id)
	VALUES ($1, $2)
	RETURNING id
	
	`

	args := []any{bid, id}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return b.DB.QueryRowContext(ctx, query, args...).Scan(&id)

}

func (b BookClub) GetList(id int64) (*ReadList, error) {
	if id < 1 {
		return nil, ErrRecordNotFound
	}
	query := `
	SELECT R.id, R.name, R.description, U.username AS created_by, S.name as status 
	FROM readList AS R 
	INNER JOIN users AS U 
	ON R.created_by = U.id 
	INNER JOIN status AS S 
	ON R.status = S.id
	WHERE R.id = $1

	`

	args := []any{id}

	var readList ReadList

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := b.DB.QueryRowContext(ctx, query, args...).Scan(&readList.ID, &readList.Name, &readList.Description, &readList.Created_by, &readList.Status)

	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, ErrRecordNotFound
		default:
			return nil, err
		}
	}

	readList.Book, _ = b.GetAllById(id)

	return &readList, nil

}

func (b BookClub) UpdateList(readList *ReadList, id int64, uid int64, status int64) error {

	err := b.DoesUserExists(uid)

	if uid != 0 {
		if err != nil {

			return err
		}
	}

	if uid == 0 {

		query := `
		SELECT created_by FROM readList WHERE id=$1
		`

		args := []any{id}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		err := b.DB.QueryRowContext(ctx, query, args...).Scan(&uid)

		if err != nil {
			return err
		}
	}

	query := `
	UPDATE readList
	SET name=$1, description=$2, created_by=$3, status=$4
	WHERE id = $5
	RETURNING id


	`

	log.Println(status)

	args := []any{readList.Name, readList.Description, uid, status, id}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return b.DB.QueryRowContext(ctx, query, args...).Scan(&id)

}

func (b BookClub) DeleteList(id int64) error {

	query := `
	DELETE FROM readList
	WHERE id = $1
	`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	result, err := b.DB.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrRecordNotFound
	}

	return nil
}

func (b BookClub) DeleteFromList(id int64, lid int64) error {

	err := b.DoesListExists(lid)

	if err != nil {
		return err
	}

	query := `
	DELETE FROM book_list
	WHERE book_id = $1 AND list_id = $2
	`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	result, err := b.DB.ExecContext(ctx, query, id, lid)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrRecordNotFound
	}

	return nil
}
