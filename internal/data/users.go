package data

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"time"

	"github.com/Jcastel2014/test3/internal/validator"
	"golang.org/x/crypto/bcrypt"
)

var AnonymouseUser = &User{}

type User struct {
	ID         int64     `json:"id"`
	Created_At time.Time `json:"created_at"`
	Username   string    `json:"username"`
	Email      string    `json:"email"`
	Password   password  `json:"-"`
	Activated  bool      `json:"activated"`
	Version    int       `json:"-"`
}

type password struct {
	plaintext *string
	hash      []byte
}

type UserModel struct {
	DB *sql.DB
}

func (u *UserModel) Insert(user *User) error {
	query := `
	INSERT INTO users (username, email, password_hash, activated)
	VALUES ($1, $2, $3, $4)
	RETURNING id, created_at, version
	`

	args := []any{user.Username, user.Email, user.Password.hash, user.Activated}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	//if an email already exists, we will get a pq error message
	err := u.DB.QueryRowContext(ctx, query, args...).Scan(&user.ID, &user.Created_At, &user.Version)
	if err != nil {
		switch {
		case err.Error() == `pq: duplicate key value violates unique constraint "users_email_key"`:
			return ErrDuplicateEmail
		default:
			return err
		}
	}
	return nil
}

func (u *UserModel) GetByEmail(email string) (*User, error) {
	query := `
	SELECT id, created_at, username, email, password_hash, activated, version
	FROM users
	WHERE email = $1
	`
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var user User
	err := u.DB.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.Created_At,
		&user.Username,
		&user.Email,
		&user.Password.hash,
		&user.Activated,
		&user.Version,
	)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, ErrRecordNotFound
		default:
			return nil, err
		}
	}

	return &user, nil
}

func (u *UserModel) GetUserProfile(id int64) (*User, error) {
	query := `
	SELECT id, created_at, username, email, activated, version
	FROM users
	WHERE id = $1
	`
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var user User
	err := u.DB.QueryRowContext(ctx, query, id).Scan(
		&user.ID,
		&user.Created_At,
		&user.Username,
		&user.Email,
		&user.Activated,
		&user.Version,
	)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, ErrRecordNotFound
		default:
			return nil, err
		}
	}

	return &user, nil
}

func (u *UserModel) GetUserLists(id int64) ([]*ReadList, error) {

	query := `
	SELECT R.id, R.name, R.description, S.name
	FROM readlist AS R
	INNER JOIN status AS S ON R.status = S.id
	WHERE created_by = $1
	`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	rows, err := u.DB.QueryContext(ctx, query, id)

	readLists := []*ReadList{}

	defer cancel()

	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var readList ReadList
		err := rows.Scan(&readList.ID, &readList.Name, &readList.Description, &readList.Status)
		if err != nil {
			return nil, err
		}
		readList.Book, err = u.GetAllById(readList.ID)
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

func (u *UserModel) GetUserReviews(id int64) ([]*Review, error) {
	query := `
	SELECT R.id, B.title, U.username, R.review, R.rating, R.created_at FROM book_reviews AS R
	INNER JOIN books AS B ON R.book_id = B.id 
	INNER JOIN users AS U ON R.user_id = U.id
	WHERE R.user_id = $1
	`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	rows, err := u.DB.QueryContext(ctx, query, id)
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

func (u *UserModel) GetForToken(tokenScope, tokenPlainText string) (*User, error) {
	tokenHash := sha256.Sum256([]byte(tokenPlainText))

	query := `
	SELECT users.id, users.created_at, users.username, users.email, users.password_hash, users.activated, users.version
	FROM users
	INNER JOIN tokens
	ON users.id = tokens.user_id
	WHERE tokens.hash = $1
	AND tokens.scope = $2
	and tokens.expiry > $3
	`

	args := []any{tokenHash[:], tokenScope, time.Now()}

	var user User

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := u.DB.QueryRowContext(ctx, query, args...).Scan(
		&user.ID,
		&user.Created_At,
		&user.Username,
		&user.Email,
		&user.Password.hash,
		&user.Activated,
		&user.Version,
	)

	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, ErrRecordNotFound
		default:
			return nil, err
		}
	}
	//return the correct user
	return &user, nil
}

func (u *UserModel) Update(user *User) error {
	query := `
	UPDATE users
	SET username = $1, email =$2, password_hash = $3, activated = $4,
	version = version + 1
	WHERE id = $5 AND version = $6
	RETURNING version
	`

	args := []any{user.Username, user.Email, user.Password.hash, user.Activated, user.ID, user.Version}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := u.DB.QueryRowContext(ctx, query, args...).Scan(&user.Version)
	//check for errors during an update
	if err != nil {
		switch {
		case err.Error() == `pq: duplicate key value violates unique key constraints "users_email_key"`:
			return ErrDuplicateEmail
		case errors.Is(err, sql.ErrNoRows):
			return ErrEditConflict
		default:
			return err
		}
	}
	return nil
}

func (p *password) Set(plainTextPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(plainTextPassword), 12)
	if err != nil {
		return err
	}

	p.plaintext = &plainTextPassword
	p.hash = hash

	return nil
}

func (p *password) Matches(plaintextPassword string) (bool, error) {
	err := bcrypt.CompareHashAndPassword(p.hash, []byte(plaintextPassword))
	if err != nil {
		switch {
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
			return false, nil

		default:
			return false, nil
		}
	}
	return true, nil //when password is correct
}

func ValidateEmail(v *validator.Validator, email string) {
	v.Check(email != "", "email", "must be provided")
	v.Check(validator.Matches(email, validator.EmailRX), "email", "must be a valid email address")
}

func ValidatePassword(v *validator.Validator, password string) {
	v.Check(password != "", "password", "must be provided")
	v.Check(len(password) >= 7, "password", "must be at least 8 bytes long")
	v.Check(len(password) <= 72, "password", "mustnot be more than 72 bytes long")
}

func ValidateUser(v *validator.Validator, user *User) {
	v.Check(user.Username != "", "username", "must be provided")
	v.Check(len(user.Username) <= 200, "username", "must not be more than 200 bytes long")

	//validate user for email
	ValidateEmail(v, user.Email)
	//validate the plain text email
	if user.Password.plaintext != nil {
		ValidatePassword(v, *user.Password.plaintext)
	}

	//check if we messed up in our codebase
	if user.Password.hash == nil {
		panic("missing password hash for user")
	}
}

func (u *User) IsAnonymous() bool {
	return u == AnonymouseUser
}

func (u *UserModel) UserExist(id int64) error {
	query := `
	SELECT users.id
	FROM users
	WHERE id = $1
	`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var ID int64

	return u.DB.QueryRowContext(ctx, query, id).Scan(&ID)
}
