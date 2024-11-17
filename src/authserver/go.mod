module github.com/leodip/goiabada/authserver

go 1.23.3

require (
	github.com/PuerkitoBio/goquery v1.10.0
	github.com/brianvoe/gofakeit/v6 v6.28.0
	github.com/go-chi/chi/v5 v5.1.0
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/google/uuid v1.6.0
	github.com/gorilla/csrf v1.7.2
	github.com/gorilla/sessions v1.4.0
	github.com/leodip/goiabada/core v0.0.0
	github.com/pkg/errors v0.9.1
	github.com/pquerna/otp v1.4.0
	github.com/stretchr/testify v1.9.0
)

replace github.com/leodip/goiabada/core => ../core

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/andybalholm/cascadia v1.3.2 // indirect
	github.com/biter777/countries v1.7.5 // indirect
	github.com/boombuler/barcode v1.0.2 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-chi/cors v1.2.1 // indirect
	github.com/go-chi/httprate v0.14.1 // indirect
	github.com/go-sql-driver/mysql v1.8.1 // indirect
	github.com/golang-migrate/migrate/v4 v4.18.1 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/huandu/go-sqlbuilder v1.32.0 // indirect
	github.com/huandu/xstrings v1.5.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mileusna/useragent v1.3.5 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/toorop/go-dkim v0.0.0-20240103092955-90b7d1423f92 // indirect
	github.com/xhit/go-simple-mail/v2 v2.16.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/crypto v0.29.0 // indirect
	golang.org/x/exp v0.0.0-20241108190413-2d47ceb2692f // indirect
	golang.org/x/net v0.29.0 // indirect
	golang.org/x/sys v0.27.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	modernc.org/gc/v3 v3.0.0-20241004144649-1aea3fae8852 // indirect
	modernc.org/libc v1.61.1 // indirect
	modernc.org/mathutil v1.6.0 // indirect
	modernc.org/memory v1.8.0 // indirect
	modernc.org/sqlite v1.34.1 // indirect
	modernc.org/strutil v1.2.0 // indirect
	modernc.org/token v1.1.0 // indirect
)
