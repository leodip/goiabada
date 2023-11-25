package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	const port = 8090
	fmt.Printf("starting server on port %v\n", port)
	if err := http.ListenAndServeTLS(fmt.Sprintf(":%v", port),
		"../../authserver/cert/self_signed_cert.pem",
		"../../authserver/cert/self_signed_key.pem", nil); err != nil {
		log.Fatal(err)
	}
}
