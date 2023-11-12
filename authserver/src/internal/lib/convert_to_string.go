package lib

import (
	"strconv"

	"log/slog"
)

func ConvertToString(v interface{}) string {
	switch val := v.(type) {
	case int:
		return strconv.Itoa(val)
	case bool:
		return strconv.FormatBool(val)
	case string:
		return val
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	default:
		slog.Warn("ConvertToString: unsupported type", "type", val)
		return ""
	}
}
