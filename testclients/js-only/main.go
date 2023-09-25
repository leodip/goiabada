package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	const host = "test-client.goiabada.local"
	const port = 3010
	fmt.Printf("Starting server at https://%v:%v\n", host, port)
	if err := http.ListenAndServeTLS(fmt.Sprintf("%v:%v", host, port), "/home/leodip/code/cert/localhost.crt", "/home/leodip/code/cert/localhost.key", nil); err != nil {
		log.Fatal(err)
	}
}
