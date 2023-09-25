package lib

import (
	"fmt"
	"net/http"

	"github.com/mileusna/useragent"
)

func GetDeviceName(r *http.Request) string {
	ua := useragent.Parse(r.Header.Get("User-Agent"))
	if len(ua.Device) > 0 {
		return fmt.Sprintf("%v %v (%v)", ua.Name, ua.Version, ua.Device)
	}
	return fmt.Sprintf("%v %v", ua.Name, ua.Version)
}

func GetDeviceType(r *http.Request) string {
	ua := useragent.Parse(r.Header.Get("User-Agent"))
	t := "unknown"
	if ua.Mobile {
		t = "Mobile"
	} else if ua.Tablet {
		t = "Tablet"
	} else if ua.Desktop {
		t = "Desktop"
	} else if ua.Bot {
		t = "Bot"
	}
	return t
}

func GetDeviceOS(r *http.Request) string {
	ua := useragent.Parse(r.Header.Get("User-Agent"))
	return fmt.Sprintf("%v %v", ua.OS, ua.OSVersion)
}
