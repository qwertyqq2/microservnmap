package utils

import "strconv"

// StringToFloat конвертирует строку в число с плавающей точкой
func StringToFloat(str string) float32 {
	float, _ := strconv.ParseFloat(str, 32)
	return float32(float)
}

// IntToString конвертирует целое число в строку
func IntToString(val int32) string {
	return strconv.FormatInt(int64(val), 10)
}
