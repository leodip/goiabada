// handlers/template_funcs.go

package handlers

import (
	"errors"
	"fmt"
	"html/template"
	"time"
)

var TemplateFuncs = template.FuncMap{
	"formatTime": func(v interface{}) string {
		if timestamp, ok := v.(float64); ok {
			t := time.Unix(int64(timestamp), 0)
			return t.Format(time.RFC1123Z)
		}
		return fmt.Sprintf("%v", v)
	},
	"dict": func(values ...interface{}) (map[string]interface{}, error) {
		if len(values)%2 != 0 {
			return nil, errors.New("invalid dict call")
		}
		dict := make(map[string]interface{}, len(values)/2)
		for i := 0; i < len(values); i += 2 {
			key, ok := values[i].(string)
			if !ok {
				return nil, errors.New("dict keys must be strings")
			}
			dict[key] = values[i+1]
		}
		return dict, nil
	},
}
