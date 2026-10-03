package api

// The picture and logo answers: a user's profile picture, through both the account API and the
// admin API, and a client's logo. Their handlers wrote each one as a map[string]interface{}
// literal and the admin console decoded them into structs of its own, so nothing declared the
// shape both sides agreed on until #441. A DELETE on the same endpoints answers SuccessResponse.

// ProfilePictureInfoResponse answers GET on a profile picture. PictureUrl is the picture's public
// URL, and is absent rather than empty when the user has no picture.
type ProfilePictureInfoResponse struct {
	HasPicture bool   `json:"hasPicture"`
	PictureUrl string `json:"pictureUrl,omitempty"`
}

// ProfilePictureUploadResponse answers a profile picture upload with the URL it is now served at.
type ProfilePictureUploadResponse struct {
	Success    bool   `json:"success"`
	PictureUrl string `json:"pictureUrl"`
}

// ClientLogoInfoResponse answers GET on a client's logo. LogoUrl is the logo's public URL, and is
// absent rather than empty when the client has no logo.
type ClientLogoInfoResponse struct {
	HasLogo bool   `json:"hasLogo"`
	LogoUrl string `json:"logoUrl,omitempty"`
}

// ClientLogoUploadResponse answers a logo upload with the URL it is now served at. The key is
// pictureUrl, not logoUrl, because that is what the endpoint has always written and what
// openapi.yaml publishes.
type ClientLogoUploadResponse struct {
	Success    bool   `json:"success"`
	PictureUrl string `json:"pictureUrl"`
}
