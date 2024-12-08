package data

import (
	"database/sql"
	"time"
)

type Product struct {
	ID             int64     `json:"id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	Price          float64   `json:"price"`
	Category       string    `json:"category"`
	Image_url      string    `json:"image_url"`
	Average_rating float64   `json:"average_rating"`
	Created_at     time.Time `json:"created_at"`
	Updated_at     time.Time `json:"updated_at"`
}

type BookClub struct {
	DB *sql.DB
}

// func (p ProductModel) Insert(product *Product) error {

// 	query := `
// 	INSERT INTO images (image_url)
// 	VALUES ($1)
// 	RETURNING id
// 	`

// 	args := []any{product.Image_url}

// 	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
// 	defer cancel()

// 	var id int

// 	err := p.DB.QueryRowContext(ctx, query, args...).Scan(&id)

// 	if err != nil {
// 		return err
// 	}

// 	query = `
// 	INSERT INTO products (name, description, category, image_id, average_rating, price)
// 	VALUES ($1, $2, $3, $4, $5, $6)
// 	RETURNING id, created_at, updated_at`

// 	//0 is default value for average_rating
// 	args = []any{product.Name, product.Description, product.Category, id, 0, product.Price}

// 	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
// 	defer cancel()

// 	return p.DB.QueryRowContext(ctx, query, args...).Scan(&product.ID, &product.Created_at, &product.Updated_at)
// }

// func (p ProductModel) Get(id int64) (*Product, error) {

// 	log.Println(id)
// 	if id < 1 {
// 		return nil, ErrRecordNotFound
// 	}

// 	query := `
// 	SELECT P.id, P.name, P.description, P.price, P.category, I.image_url, P.average_rating, P.created_at, P.updated_at
// 	FROM products AS P
// 	INNER JOIN images AS I ON P.image_id = I.id
// 	WHERE P.id = $1;
// 	`

// 	var product Product

// 	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
// 	defer cancel()

// 	err := p.DB.QueryRowContext(ctx, query, id).Scan(&product.ID, &product.Name, &product.Description, &product.Price, &product.Category, &product.Image_url, &product.Average_rating, &product.Created_at, &product.Updated_at)

// 	if err != nil {
// 		switch {
// 		case errors.Is(err, sql.ErrNoRows):
// 			return nil, ErrRecordNotFound
// 		default:
// 			return nil, err
// 		}
// 	}
// 	return &product, nil
// }

// func (p ProductModel) GetAll(name string, description string, category string, average_rating string, filters Filters) ([]*Product, Metadata, error) {
// 	query := fmt.Sprintf(`
// 	SELECT COUNT(*) OVER(), id, name, description, category, image_id, average_rating, created_at, updated_at
// 	FROM products
// 	WHERE (to_tsvector('simple', name) @@
// 		plainto_tsquery('simple', $1) OR $1 = '')
//     AND (to_tsvector('simple', description) @@
// 		plainto_tsquery('simple', $2) OR $2 = '')
// 	AND (to_tsvector('simple', category) @@
// 		plainto_tsquery('simple', $3) OR $3 = '')
// 	ORDER BY %s %s, id ASC
//         LIMIT $4 OFFSET $5`, filters.sortColumn(), filters.sortDirection())

// 	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
// 	defer cancel()

// 	rows, err := p.DB.QueryContext(ctx, query, name, description, category, filters.limit(), filters.offset())

// 	if err != nil {
// 		return nil, Metadata{}, err
// 	}

// 	defer rows.Close()
// 	totalRecords := 0

// 	products := []*Product{}

// 	for rows.Next() {
// 		var product Product
// 		err := rows.Scan(&totalRecords, &product.ID, &product.Name, &product.Description, &product.Category, &product.Image_url, &product.Average_rating, &product.Created_at, &product.Updated_at)

// 		if err != nil {
// 			return nil, Metadata{}, err
// 		}

// 		products = append(products, &product)
// 	}

// 	err = rows.Err()
// 	if err != nil {
// 		return nil, Metadata{}, err
// 	}

// 	metadata := calculateMetaData(totalRecords, filters.Page, filters.PageSize)

// 	return products, metadata, nil
// }

// func (p ProductModel) Update(product *Product) error {

// 	query := `
// 	UPDATE products
// 	SET name =$1, description =$2, category =$3, price =$4
// 	WHERE id = $5
// 	RETURNING id
// 	`

// 	args := []any{product.Name, product.Description, product.Category, product.Price, product.ID}
// 	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
// 	defer cancel()

// 	err := p.DB.QueryRowContext(ctx, query, args...).Scan(&product.ID)

// 	if err != nil {
// 		return err
// 	}

// 	query = `
// 	Update images
// 	SET image_url =$1
// 	WHERE id = (SELECT image_id FROM products WHERE id = $2)
// 	RETURNING id
// 	`
// 	args = []any{product.Image_url, product.ID}
// 	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
// 	defer cancel()

// 	return p.DB.QueryRowContext(ctx, query, args...).Scan(&product.ID)
// }

// func (p ProductModel) Delete(id int64) error {
// 	if id < 1 {
// 		return ErrRecordNotFound
// 	}

// 	query := `
// 	DELETE FROM images
// 	WHERE id = (select image_id from products where id = $1)
// 	`

// 	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
// 	defer cancel()

// 	result, err := p.DB.ExecContext(ctx, query, id)
// 	if err != nil {
// 		return err
// 	}

// 	rowsAffected, err := result.RowsAffected()
// 	if err != nil {
// 		return err
// 	}

// 	if rowsAffected == 0 {
// 		return ErrRecordNotFound
// 	}

// 	return nil
// }

// func ValidateProduct(v *validator.Validator, product *Product, handlerId int) {

// 	switch handlerId {
// 	case 1:
// 		v.Check(product.Name != "", "name", "must be provided")
// 		v.Check(product.Description != "", "description", "must be provided")
// 		v.Check(product.Category != "", "category", "must be provided")
// 		v.Check(product.Image_url != "", "image_url", "must be provided")

// 		v.Check(len(product.Name) <= 100, "name", "must not be more than 100 byte long")
// 		v.Check(len(product.Description) <= 100, "description", "must not be more than 100 byte long")
// 		v.Check(len(product.Category) <= 100, "category", "must not be more than 100 byte long")
// 	default:
// 		log.Println("Unable to locate handler ID: %s", handlerId)
// 		v.AddError("default", "Handler ID not provided")
// 	}
// }
