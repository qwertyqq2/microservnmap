package utils

import "strconv"

func StringToFloat(str string) float32 {
	float, _ := strconv.ParseFloat(str, 32)
	return float32(float)
}

func IntToString(val int32) string {
	return strconv.FormatInt(int64(val), 10)
}
