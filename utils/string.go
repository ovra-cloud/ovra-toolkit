package utils

import (
	"strconv"
	"strings"
)

func StrAtoi(str string) int64 {
	atoi, _ := strconv.ParseInt(str, 10, 64)
	return atoi
}

func SplitToInt64(s, sep string) ([]int64, error) {
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, sep)
	res := make([]int64, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		v, err := strconv.ParseInt(p, 10, 64)
		if err != nil {
			return nil, err
		}
		res = append(res, v)
	}
	return res, nil
}
