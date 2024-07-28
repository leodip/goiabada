package config

const ListenPort int = 8100
const ClientId string = "test-client-1"

// const ClientSecret string = "insert-secret-here"
const ClientSecret string = "aWUsJb.o8OG3YpCXsetall8A9MZbZrgpv17YQCsRpdcuct6z42Gp3ussoCm0"

var DefaultScopes = []string{"openid", "profile", "email", "testapp:manage"}

const OidcProvider string = "http://localhost:8080"
const RedirectURL string = "http://localhost:8100/callback"
const PostLogoutRedirectURL string = "http://localhost:8100"
const ResponseMode string = "form_post"                                // query or form_post
const SessionAuthKey string = "some-random-auth-key-00000000000"       // 32 bytes
const SessionEncryptionKey string = "some-random-encryption-key-00000" // 32 bytes
