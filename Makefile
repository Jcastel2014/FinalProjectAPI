include .envrc

.PHONY: run/cor
run/cor:
	@echo  'Running application…'
	@go run ./cmd/api \
	-port=3000 \
	-env=development \
	-db-dsn=${BOOKCLUB_DB_DSN} \
	-limiter-rps=2 \
	-limiter-burst=5 \
	-limiter-enabled=false \
	-cors-trusted-origins="http://localhost:9000 http://localhost:9001"


.PHONY: run/api
run/api:
	@echo 'Running BookClub API...'
	@go run ./cmd/api -port=3000 -env=production -db-dsn=${BOOKCLUB_DB_DSN}

.PHONY: db/psql
db/psql:
	psql ${BOOKCLUB_DB_DSN}

.PHONY: db/migrations/new
db/migrations/new:
	@echo 'Creating migration files for ${name}...'
	migrate create -seq -ext=.sql -dir=./migrations ${name}

.PHONY: db/migrations/up
db/migrations/up:
	@echo 'Running up migrations...'
	migrate -path=./migrations -database ${BOOKCLUB_DB_DSN} up

# Users---------------------------------------------------------------------------------------------------------
.PHONY: user/create
user/create:
	@echo 'Creating User'; \
	BODY1='{"username": "John Doe", "email": "john@example.com", "password": "mangotree"}'; \
	curl -i -d "$$BODY1" localhost:3000/v1/users; \

.PHONY: user/activate
user/activate:
	@echo 'Activating User'; \
	curl -X PUT -d '{"token": "VMPNBX2Q5S2GLMUF3CXSMIMUCE"}' localhost:3000/v1/users/activated; \
	

.PHONY: token/authenticate
token/authenticate:
	@echo 'Authenticating token'; \
	BODY='{"email": "john@example.com", "password": "mangotree"}'; \
	curl -d "$$BODY" localhost:3000/v1/tokens/authentication; \

.PHONY: user/get
user/get:
	@echo 'Getting User Profile'; \
	curl -i localhost:3000/api/v1/users/${id} -H "Authorization: Bearer ${token}" 

.PHONY: user/get/list
user/get/list:
	@echo 'Getting User Lists'; \
	curl -i localhost:3000/api/v1/users/${id}/lists -H "Authorization: Bearer ${token}" 

.PHONY: user/get/reviews
user/get/reviews:
	@echo 'Getting User Reviews'; \
	curl -i localhost:3000/api/v1/users/${id}/reviews -H "Authorization: Bearer ${token}" 



# Books----------------------------------------------------------------------------------------------------------
# FF65XZNVIR6FXVZLG4T5UZ6ZMA
.PHONY: books/add
books/add:
	@echo 'Adding Book'; \
	BODY='{"title":"To Kill a Mockingbird","isbn":"6","author":"swag Lee","genre":"Fiction","description":"A novel set in the American South during the 1930s, focusing on themes of racial injustice and moral growth.","created_at":"1960-07-11T00:00:00Z"}'; \
	curl -H "Authorization: Bearer ${token}" -X POST -d "$$BODY" localhost:3000/api/v1/books; \

.PHONY: books/get/all
books/get/all:
	@echo 'Displaying Reviews'; \
	curl -i localhost:3000/api/v1/books?${filter} -H "Authorization: Bearer ${token}" 

.PHONY: books/get
books/get:
	@echo 'Displaying Product'; \
	curl -i localhost:3000/api/v1/books/${id} -H "Authorization: Bearer ${token}" 

.PHONY: books/put
books/put:
	@echo 'Updating Product ${id}'; \
	curl -X PUT localhost:3000/api/v1/books/${id} -d '{"Description":"Updated Description", "genre":"Idk"}' -H "Authorization: Bearer ${token}" 

.PHONY: books/delete
books/delete:
	@echo 'Deleting Product'; \
	curl -X DELETE localhost:3000/api/v1/books/${id} -H "Authorization: Bearer ${token}" 

# Lists ----------------------------------------------------------------------------------------------------
.PHONY: list/create
list/create:
	@echo 'Creating List'; \
	BODY='{"name":"test2","description":"test3","created_by":1}'; \
	curl -H "Authorization: Bearer ${token}" -X POST -d "$$BODY" localhost:3000/api/v1/lists; \

.PHONY: list/get/all
list/get/all:
	@echo 'Displaying Lists'; \
	curl -i localhost:3000/api/v1/lists?${filter} -H "Authorization: Bearer ${token}"

.PHONY: list/book/add
list/book/add:
	@echo 'Adding book to list'; \
	BODY='{"bookid":5}'; \
	curl -H "Authorization: Bearer ${token}" -X POST -d "$$BODY" localhost:3000/api/v1/lists/${id}/books ; \

.PHONY: list/get
list/get:
	@echo 'Displaying List'; \
	curl -i localhost:3000/api/v1/lists/${id} -H "Authorization: Bearer ${token}"


.PHONY: list/update
list/update:
	@echo 'Updating List'; \
	curl -H "Authorization: Bearer ${token}" -X PUT localhost:3000/api/v1/lists/${id} -d '{"status":"Completed", "name":"updateTest2"}'

.PHONY: list/delete
list/delete:
	@echo 'Deleting List'; \
	curl -H "Authorization: Bearer ${token}" -X DELETE localhost:3000/api/v1/lists/${id} 

.PHONY: list/book/delete
list/book/delete:
	@echo 'Deleting Product'; \
	BODY='{"list_id":3}'; \
	curl -H "Authorization: Bearer ${token}" -X DELETE -d "$$BODY" localhost:3000/api/v1/lists/${id}/books


# Reviews------------------------------------------------------------------------------------------------------
.PHONY: books/review/add
books/review/add:
	@echo 'Adding book review'; \
	BODY='{"user_id":1, "review":"terrible", "rating":1}'; \
	curl -H "Authorization: Bearer ${token}" -X POST -d "$$BODY" localhost:3000/api/v1/books/${id}/reviews ; \

.PHONY: books/review/get/all
books/review/get/all:
	@echo 'Displaying Lists'; \
	curl -H "Authorization: Bearer ${token}" -i localhost:3000/api/v1/books/${id}/reviews?${filter}

.PHONY: books/review/delete
books/review/delete:
	@echo 'Deleting Review'; \
	curl -H "Authorization: Bearer ${token}" -X DELETE localhost:3000/api/v1/reviews/${id}


.PHONY: books/review/update
books/review/update:
	@echo 'Updating Review ${id}'; \
	curl -H "Authorization: Bearer ${token}" -X PUT localhost:3000/api/v1/reviews/${id} -d '{"rating":5.00}'

.PHONY: run/rateLimite/enabled
run/rateLimit,enabled:
	@echo 'Running Product API /w Rate Limit...'
	@go run ./cmd/api -port=3000 -env=development -limiter-burst=5 -limiter-rps=2 -limiter-enabled=true -db-dsn=${PRODUCTS_DB_DSN}

.PHONY: run/rateLimite/disabled
run/rateLimit/disabled:
	@echo 'Running Product API /w Rate Limit...'
	@go run ./cmd/api -port=3000 -env=development -limiter-burst=5 -limiter-rps=2 -limiter-enabled=false -db-dsn=${PRODUCTS_DB_DSN}

