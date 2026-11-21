package datatests

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/png"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
)

// createTestPNG creates a valid PNG image with the specified dimensions
func createTestPNG(width, height int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	// Fill with a solid color
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{R: 100, G: 150, B: 200, A: 255})
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

func TestCreateUserProfilePicture(t *testing.T) {
	user := createTestUser(t)
	profilePicture := createTestUserProfilePicture(t, user.ID)

	if profilePicture.ID == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !profilePicture.CreatedAt.Valid || profilePicture.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !profilePicture.UpdatedAt.Valid || profilePicture.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	retrieved, err := database.GetUserProfilePictureByUserID(context.Background(), nil, user.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve created profile picture: %v", err)
	}

	if retrieved.ID != profilePicture.ID {
		t.Errorf("Expected ID %d, got %d", profilePicture.ID, retrieved.ID)
	}
	if retrieved.UserID != profilePicture.UserID {
		t.Errorf("Expected UserID %d, got %d", profilePicture.UserID, retrieved.UserID)
	}
	if retrieved.ContentType != profilePicture.ContentType {
		t.Errorf("Expected ContentType %s, got %s", profilePicture.ContentType, retrieved.ContentType)
	}
	if !bytes.Equal(retrieved.Picture, profilePicture.Picture) {
		t.Error("Expected Picture data to match")
	}
}

func TestCreateUserProfilePicture_ZeroUserID(t *testing.T) {
	profilePicture := &record.UserProfilePicture{
		UserID:      0,
		Picture:     createTestPNG(100, 100),
		ContentType: "image/png",
	}

	err := database.CreateUserProfilePicture(context.Background(), nil, profilePicture)
	if err == nil {
		t.Error("Expected error when creating profile picture with zero UserID")
	}
}

func TestUpdateUserProfilePicture(t *testing.T) {
	user := createTestUser(t)
	profilePicture := createTestUserProfilePicture(t, user.ID)

	// Update the picture
	newPictureData := createTestPNG(200, 200)
	profilePicture.Picture = newPictureData
	profilePicture.ContentType = "image/jpeg"

	time.Sleep(timestampTick)

	err := database.UpdateUserProfilePicture(context.Background(), nil, profilePicture)
	if err != nil {
		t.Fatalf("Failed to update profile picture: %v", err)
	}

	updated, err := database.GetUserProfilePictureByUserID(context.Background(), nil, user.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve updated profile picture: %v", err)
	}

	if updated.ContentType != "image/jpeg" {
		t.Errorf("Expected ContentType 'image/jpeg', got %s", updated.ContentType)
	}
	if !bytes.Equal(updated.Picture, newPictureData) {
		t.Error("Expected Picture data to match updated data")
	}
	if !updated.UpdatedAt.Time.After(updated.CreatedAt.Time) {
		t.Error("Expected UpdatedAt to be after CreatedAt")
	}
}

func TestUpdateUserProfilePicture_ZeroID(t *testing.T) {
	profilePicture := &record.UserProfilePicture{
		ID:          0,
		UserID:      1,
		Picture:     createTestPNG(100, 100),
		ContentType: "image/png",
	}

	err := database.UpdateUserProfilePicture(context.Background(), nil, profilePicture)
	if err == nil {
		t.Error("Expected error when updating profile picture with zero ID")
	}
}

func TestGetUserProfilePictureByUserID(t *testing.T) {
	user := createTestUser(t)
	profilePicture := createTestUserProfilePicture(t, user.ID)

	retrieved, err := database.GetUserProfilePictureByUserID(context.Background(), nil, user.ID)
	if err != nil {
		t.Fatalf("Failed to get profile picture by user ID: %v", err)
	}

	if retrieved == nil {
		t.Fatal("Expected profile picture to be found")
	}
	if retrieved.ID != profilePicture.ID {
		t.Errorf("Expected ID %d, got %d", profilePicture.ID, retrieved.ID)
	}
	if retrieved.UserID != user.ID {
		t.Errorf("Expected UserID %d, got %d", user.ID, retrieved.UserID)
	}
}

func TestGetUserProfilePictureByUserID_NotFound(t *testing.T) {
	// Use a user ID that doesn't have a profile picture
	retrieved, err := database.GetUserProfilePictureByUserID(context.Background(), nil, 99999999)
	if err != nil {
		t.Errorf("Expected no error for non-existent profile picture, got: %v", err)
	}
	if retrieved != nil {
		t.Errorf("Expected nil for non-existent profile picture, got ID: %d", retrieved.ID)
	}
}

func TestDeleteUserProfilePicture(t *testing.T) {
	user := createTestUser(t)
	_ = createTestUserProfilePicture(t, user.ID)

	// Verify it exists
	exists, err := database.UserHasProfilePicture(context.Background(), nil, user.ID)
	if err != nil {
		t.Fatalf("Failed to check if user has profile picture: %v", err)
	}
	if !exists {
		t.Fatal("Expected profile picture to exist before deletion")
	}

	// Delete it
	err = database.DeleteUserProfilePicture(context.Background(), nil, user.ID)
	if err != nil {
		t.Fatalf("Failed to delete profile picture: %v", err)
	}

	// Verify it's gone
	deleted, err := database.GetUserProfilePictureByUserID(context.Background(), nil, user.ID)
	if err != nil {
		t.Fatalf("Error while checking for deleted profile picture: %v", err)
	}
	if deleted != nil {
		t.Error("Profile picture still exists after deletion")
	}
}

func TestDeleteUserProfilePicture_NotExist(t *testing.T) {
	// Deleting a non-existent profile picture should not return an error
	err := database.DeleteUserProfilePicture(context.Background(), nil, 99999999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent profile picture, got: %v", err)
	}
}

func TestUserHasProfilePicture_True(t *testing.T) {
	user := createTestUser(t)
	_ = createTestUserProfilePicture(t, user.ID)

	hasPicture, err := database.UserHasProfilePicture(context.Background(), nil, user.ID)
	if err != nil {
		t.Fatalf("Failed to check if user has profile picture: %v", err)
	}
	if !hasPicture {
		t.Error("Expected UserHasProfilePicture to return true")
	}
}

func TestUserHasProfilePicture_False(t *testing.T) {
	user := createTestUser(t)
	// Don't create a profile picture for this user

	hasPicture, err := database.UserHasProfilePicture(context.Background(), nil, user.ID)
	if err != nil {
		t.Fatalf("Failed to check if user has profile picture: %v", err)
	}
	if hasPicture {
		t.Error("Expected UserHasProfilePicture to return false")
	}
}

func TestUserHasProfilePicture_NonExistentUser(t *testing.T) {
	hasPicture, err := database.UserHasProfilePicture(context.Background(), nil, 99999999)
	if err != nil {
		t.Fatalf("Failed to check if user has profile picture: %v", err)
	}
	if hasPicture {
		t.Error("Expected UserHasProfilePicture to return false for non-existent user")
	}
}

func TestUserProfilePicture_MultipleUsers(t *testing.T) {
	// Create two users with profile pictures
	user1 := createTestUser(t)
	user2 := createTestUser(t)

	picture1Data := createTestPNG(50, 50)
	picture2Data := createTestPNG(100, 100)

	picture1 := &record.UserProfilePicture{
		UserID:      user1.ID,
		Picture:     picture1Data,
		ContentType: "image/png",
	}
	err := database.CreateUserProfilePicture(context.Background(), nil, picture1)
	if err != nil {
		t.Fatalf("Failed to create profile picture for user1: %v", err)
	}

	picture2 := &record.UserProfilePicture{
		UserID:      user2.ID,
		Picture:     picture2Data,
		ContentType: "image/png",
	}
	err = database.CreateUserProfilePicture(context.Background(), nil, picture2)
	if err != nil {
		t.Fatalf("Failed to create profile picture for user2: %v", err)
	}

	// Verify each user has their own picture
	retrieved1, err := database.GetUserProfilePictureByUserID(context.Background(), nil, user1.ID)
	if err != nil {
		t.Fatalf("Failed to get profile picture for user1: %v", err)
	}
	if !bytes.Equal(retrieved1.Picture, picture1Data) {
		t.Error("User1's picture data doesn't match")
	}

	retrieved2, err := database.GetUserProfilePictureByUserID(context.Background(), nil, user2.ID)
	if err != nil {
		t.Fatalf("Failed to get profile picture for user2: %v", err)
	}
	if !bytes.Equal(retrieved2.Picture, picture2Data) {
		t.Error("User2's picture data doesn't match")
	}

	// Deleting user1's picture shouldn't affect user2's picture
	err = database.DeleteUserProfilePicture(context.Background(), nil, user1.ID)
	if err != nil {
		t.Fatalf("Failed to delete user1's profile picture: %v", err)
	}

	user2StillHasPicture, err := database.UserHasProfilePicture(context.Background(), nil, user2.ID)
	if err != nil {
		t.Fatalf("Failed to check if user2 has profile picture: %v", err)
	}
	if !user2StillHasPicture {
		t.Error("User2's profile picture was deleted when user1's was deleted")
	}
}

func TestUserProfilePicture_LargePictureData(t *testing.T) {
	user := createTestUser(t)

	// Create a larger image (512x512)
	largePictureData := createTestPNG(512, 512)

	profilePicture := &record.UserProfilePicture{
		UserID:      user.ID,
		Picture:     largePictureData,
		ContentType: "image/png",
	}

	err := database.CreateUserProfilePicture(context.Background(), nil, profilePicture)
	if err != nil {
		t.Fatalf("Failed to create profile picture with large data: %v", err)
	}

	retrieved, err := database.GetUserProfilePictureByUserID(context.Background(), nil, user.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve large profile picture: %v", err)
	}

	if !bytes.Equal(retrieved.Picture, largePictureData) {
		t.Error("Large picture data doesn't match after retrieval")
	}
}

func createTestUserProfilePicture(t *testing.T, userID int64) *record.UserProfilePicture {
	pictureData := createTestPNG(100, 100)
	profilePicture := &record.UserProfilePicture{
		UserID:      userID,
		Picture:     pictureData,
		ContentType: "image/png",
	}
	err := database.CreateUserProfilePicture(context.Background(), nil, profilePicture)
	if err != nil {
		t.Fatalf("Failed to create test profile picture: %v", err)
	}
	return profilePicture
}
