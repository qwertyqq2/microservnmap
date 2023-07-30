package utils

import "strconv"

func StringToFloat(str string) float32 {
	float, _ := strconv.ParseFloat(str, 32)
	return float32(float)
}

func IntsToStrings(vals []int32) []string {
	strs := make([]string, 0, len(vals))
	for _, v := range vals {
		strs = append(strs, strconv.FormatInt(int64(v), 10))
	}
	return strs
}
