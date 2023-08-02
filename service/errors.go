package service

import "errors"

var (
	// ErrUndefinedTargers возникает если в запросе нет целей
	ErrUndefinedTargers = errors.New("err undefined targets")

	// ErrCreateScanner возникает если не удалось создать сканнер
	ErrCreateScanner = errors.New("err create scanner")

	// ErrRunScanner возникает если произошла ошибка сканирования
	ErrRunScanner = errors.New("err run scanner")
)
