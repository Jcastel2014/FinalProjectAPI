package data

import "errors"

var ErrRecordNotFound = errors.New("record not found")

var BookNotFound = errors.New("book not found")
var UserNotFound = errors.New("user not found")

var ErrDuplicateEmail = errors.New("duplicate email")
var ErrEditConflict = errors.New("edit conflict")
