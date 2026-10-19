package commandfilters

import (
	"fmt"
	"path"
	"regexp"
	"strings"
	"unicode"
)

const DirectoryTree = "tree"

func validDirectoryPath(value string) bool {
	return value != "" && len(value) <= 1024 && path.IsAbs(value) && path.Clean(value) == value && !strings.Contains(value, "\\") && strings.IndexFunc(value, unicode.IsControl) < 0
}

func compileDirectory(match, pattern string) (*regexp.Regexp, error) {
	if match == "" && pattern == "" {
		return nil, nil
	}
	if pattern == "" || len(pattern) > 256 || strings.IndexFunc(pattern, unicode.IsControl) >= 0 {
		return nil, fmt.Errorf("%w: invalid directory pattern", ErrInvalidInput)
	}
	if match == MatchExact || match == DirectoryTree {
		if validDirectoryPath(pattern) {
			return nil, nil
		}
	} else if match == MatchRegex {
		compiled, err := regexp.Compile("^(?:" + pattern + ")$")
		if err == nil {
			return compiled, nil
		}
	}
	return nil, fmt.Errorf("%w: invalid directory match", ErrInvalidInput)
}

func matchesDirectory(filter Filter, compiled *regexp.Regexp, directory string) bool {
	switch filter.DirectoryMatch {
	case MatchExact:
		return directory == filter.DirectoryPattern
	case DirectoryTree:
		return directory == filter.DirectoryPattern || strings.HasPrefix(directory, strings.TrimSuffix(filter.DirectoryPattern, "/")+"/")
	case MatchRegex:
		return compiled != nil && compiled.MatchString(directory)
	default:
		return false
	}
}
