CREATE TABLE book_reviews (
    id SERIAL PRIMARY KEY,
    book_id INT REFERENCES books(id) ON DELETE CASCADE,
    user_id INT REFERENCES users(id),
    review text NOT NULL,
    rating DECIMAL(3,2),
    created_at DATE
);
