package service

import "errors"

var (
	ErrUndefinedTargers = errors.New("err undefined targets")
	ErrCreateScanner    = errors.New("err create scanner")
	ErrRunScanner       = errors.New("err run scanner")
)
