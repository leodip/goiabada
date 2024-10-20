package main

import (
	"GoServerWebApp/auth"
	"GoServerWebApp/config"
	"GoServerWebApp/handlers"
	"context"
	"encoding/gob"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
)

func main() {
	ctx := context.Background()

	// required to serialize claims to the session store
	gob.Register(map[string]interface{}{})
	gob.Register(jwt.MapClaims{})

	tempDir := os.TempDir()
	fsStore := sessions.NewFilesystemStore(tempDir, []byte(config.SessionAuthKey), []byte(config.SessionEncryptionKey))
	fsStore.MaxLength(1 << 20) // 1 MB

	authHelper, err := auth.NewAuthHelper(ctx)
	if err != nil {
		log.Fatalf("Failed to initialize AuthHelper: %v", err)
	}

	fmt.Println("Starting server on port", config.ListenPort)

	http.HandleFunc("/", handlers.IndexGet(fsStore, authHelper))

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handlers.LoginHandlerGet(fsStore).ServeHTTP(w, r)
		case http.MethodPost:
			handlers.LoginHandlerPost(fsStore, authHelper).ServeHTTP(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	http.HandleFunc("/callback", handlers.CallbackHandler(fsStore, authHelper))
	http.HandleFunc("/logout", handlers.LogoutHandler(fsStore))
	http.HandleFunc("/forbidden", handlers.ForbiddenGet(fsStore))
	http.HandleFunc("/refresh", handlers.RefreshHandler(fsStore, authHelper))

	// must be authenticated
	http.HandleFunc("/authenticated",
		handlers.RequiresAuthentication(handlers.ProtectedGet(fsStore, "authenticated"), fsStore, authHelper),
	)

	// must be authenticated and have the "testapp:manage" scope
	http.HandleFunc("/authenticated-plus-scope",
		handlers.RequiresAuthentication(
			handlers.RequiresScope(handlers.ProtectedGet(fsStore, "authenticated-plus-scope"), "testapp:manage", fsStore, authHelper),
			fsStore,
			authHelper,
		),
	)

	// must have the "testapp:manage" scope
	http.HandleFunc("/with-scope",
		handlers.RequiresScope(handlers.ProtectedGet(fsStore, "with-scope"), "testapp:manage", fsStore, authHelper),
	)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", config.ListenPort), nil))
}
