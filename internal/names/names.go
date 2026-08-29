package names

import (
	"errors"
	"strings"
)

var reserved = map[string]struct{}{
	"admin": {}, "api": {}, "relay": {}, "status": {}, "tcp": {}, "www": {},
}

func Normalize(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) < 3 || len(value) > 63 {
		return "", errors.New("domain must contain between 3 and 63 characters")
	}
	if _, found := reserved[value]; found {
		return "", errors.New("domain is reserved")
	}
	if value[0] == '-' || value[len(value)-1] == '-' {
		return "", errors.New("domain cannot begin or end with a hyphen")
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
			return "", errors.New("domain may only contain lowercase letters, numbers, and hyphens")
		}
	}
	return value, nil
}
