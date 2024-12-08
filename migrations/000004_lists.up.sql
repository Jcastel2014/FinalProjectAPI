DROP TABLE IF EXISTS status;
CREATE TABLE status (
    id SERIAL PRIMARY KEY,
    name VARCHAR (20) NOT NULL
);

insert into status(name) values ('Completed');
insert into status(name) values ('Currently Reading');



DROP TABLE IF EXISTS readList;
CREATE TABLE readList (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_by INT REFERENCES users(id),
    status INT REFERENCES status(id)

);



DROP TABLE IF EXISTS book_list;
CREATE TABLE book_list (
    id SERIAL PRIMARY KEY,
    book_id INT REFERENCES books(id) ON DELETE CASCADE,
    list_id INT REFERENCES readList(id) ON DELETE CASCADE
);
