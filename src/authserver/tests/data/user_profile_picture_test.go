package datatests

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/models"
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
	profilePicture := createTestUserProfilePicture(t, user.Id)

	if profilePicture.Id == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !profilePicture.CreatedAt.Valid || profilePicture.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !profilePicture.UpdatedAt.Valid || profilePicture.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	retrieved, err := database.GetUserProfilePictureByUserId(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve created profile picture: %v", err)
	}

	if retrieved.Id != profilePicture.Id {
		t.Errorf("Expected ID %d, got %d", profilePicture.Id, retrieved.Id)
	}
	if retrieved.UserId != profilePicture.UserId {
		t.Errorf("Expected UserId %d, got %d", profilePicture.UserId, retrieved.UserId)
	}
	if retrieved.ContentType != profilePicture.ContentType {
		t.Errorf("Expected ContentType %s, got %s", profilePicture.ContentType, retrieved.ContentType)
	}
	if !bytes.Equal(retrieved.Picture, profilePicture.Picture) {
		t.Error("Expected Picture data to match")
	}
}

func TestCreateUserProfilePicture_ZeroUserId(t *testing.T) {
	profilePicture := &models.UserProfilePicture{
		UserId:      0,
		Picture:     createTestPNG(100, 100),
		ContentType: "image/png",
	}

	err := database.CreateUserProfilePicture(nil, profilePicture)
	if err == nil {
		t.Error("Expected error when creating profile picture with zero UserId")
	}
}

func TestUpdateUserProfilePicture(t *testing.T) {
	user := createTestUser(t)
	profilePicture := createTestUserProfilePicture(t, user.Id)

	// Update the picture
	newPictureData := createTestPNG(200, 200)
	profilePicture.Picture = newPictureData
	profilePicture.ContentType = "image/jpeg"

	time.Sleep(time.Millisecond * 100)

	err := database.UpdateUserProfilePicture(nil, profilePicture)
	if err != nil {
		t.Fatalf("Failed to update profile picture: %v", err)
	}

	updated, err := database.GetUserProfilePictureByUserId(nil, user.Id)
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

func TestUpdateUserProfilePicture_ZeroId(t *testing.T) {
	profilePicture := &models.UserProfilePicture{
		Id:          0,
		UserId:      1,
		Picture:     createTestPNG(100, 100),
		ContentType: "image/png",
	}

	err := database.UpdateUserProfilePicture(nil, profilePicture)
	if err == nil {
		t.Error("Expected error when updating profile picture with zero ID")
	}
}

func TestGetUserProfilePictureByUserId(t *testing.T) {
	user := createTestUser(t)
	profilePicture := createTestUserProfilePicture(t, user.Id)

	retrieved, err := database.GetUserProfilePictureByUserId(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to get profile picture by user ID: %v", err)
	}

	if retrieved == nil {
		t.Fatal("Expected profile picture to be found")
	}
	if retrieved.Id != profilePicture.Id {
		t.Errorf("Expected ID %d, got %d", profilePicture.Id, retrieved.Id)
	}
	if retrieved.UserId != user.Id {
		t.Errorf("Expected UserId %d, got %d", user.Id, retrieved.UserId)
	}
}

func TestGetUserProfilePictureByUserId_NotFound(t *testing.T) {
	// Use a user ID that doesn't have a profile picture
	retrieved, err := database.GetUserProfilePictureByUserId(nil, 99999999)
	if err != nil {
		t.Errorf("Expected no error for non-existent profile picture, got: %v", err)
	}
	if retrieved != nil {
		t.Errorf("Expected nil for non-existent profile picture, got ID: %d", retrieved.Id)
	}
}

func TestDeleteUserProfilePicture(t *testing.T) {
	user := createTestUser(t)
	_ = createTestUserProfilePicture(t, user.Id)

	// Verify it exists
	exists, err := database.UserHasProfilePicture(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to check if user has profile picture: %v", err)
	}
	if !exists {
		t.Fatal("Expected profile picture to exist before deletion")
	}

	// Delete it
	err = database.DeleteUserProfilePicture(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to delete profile picture: %v", err)
	}

	// Verify it's gone
	deleted, err := database.GetUserProfilePictureByUserId(nil, user.Id)
	if err != nil {
		t.Fatalf("Error while checking for deleted profile picture: %v", err)
	}
	if deleted != nil {
		t.Error("Profile picture still exists after deletion")
	}
}

func TestDeleteUserProfilePicture_NotExist(t *testing.T) {
	// Deleting a non-existent profile picture should not return an error
	err := database.DeleteUserProfilePicture(nil, 99999999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent profile picture, got: %v", err)
	}
}

func TestUserHasProfilePicture_True(t *testing.T) {
	user := createTestUser(t)
	_ = createTestUserProfilePicture(t, user.Id)

	hasPicture, err := database.UserHasProfilePicture(nil, user.Id)
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

	hasPicture, err := database.UserHasProfilePicture(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to check if user has profile picture: %v", err)
	}
	if hasPicture {
		t.Error("Expected UserHasProfilePicture to return false")
	}
}

func TestUserHasProfilePicture_NonExistentUser(t *testing.T) {
	hasPicture, err := database.UserHasProfilePicture(nil, 99999999)
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

	picture1 := &models.UserProfilePicture{
		UserId:      user1.Id,
		Picture:     picture1Data,
		ContentType: "image/png",
	}
	err := database.CreateUserProfilePicture(nil, picture1)
	if err != nil {
		t.Fatalf("Failed to create profile picture for user1: %v", err)
	}

	picture2 := &models.UserProfilePicture{
		UserId:      user2.Id,
		Picture:     picture2Data,
		ContentType: "image/png",
	}
	err = database.CreateUserProfilePicture(nil, picture2)
	if err != nil {
		t.Fatalf("Failed to create profile picture for user2: %v", err)
	}

	// Verify each user has their own picture
	retrieved1, err := database.GetUserProfilePictureByUserId(nil, user1.Id)
	if err != nil {
		t.Fatalf("Failed to get profile picture for user1: %v", err)
	}
	if !bytes.Equal(retrieved1.Picture, picture1Data) {
		t.Error("User1's picture data doesn't match")
	}

	retrieved2, err := database.GetUserProfilePictureByUserId(nil, user2.Id)
	if err != nil {
		t.Fatalf("Failed to get profile picture for user2: %v", err)
	}
	if !bytes.Equal(retrieved2.Picture, picture2Data) {
		t.Error("User2's picture data doesn't match")
	}

	// Deleting user1's picture shouldn't affect user2's picture
	err = database.DeleteUserProfilePicture(nil, user1.Id)
	if err != nil {
		t.Fatalf("Failed to delete user1's profile picture: %v", err)
	}

	user2StillHasPicture, err := database.UserHasProfilePicture(nil, user2.Id)
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

	profilePicture := &models.UserProfilePicture{
		UserId:      user.Id,
		Picture:     largePictureData,
		ContentType: "image/png",
	}

	err := database.CreateUserProfilePicture(nil, profilePicture)
	if err != nil {
		t.Fatalf("Failed to create profile picture with large data: %v", err)
	}

	retrieved, err := database.GetUserProfilePictureByUserId(nil, user.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve large profile picture: %v", err)
	}

	if !bytes.Equal(retrieved.Picture, largePictureData) {
		t.Error("Large picture data doesn't match after retrieval")
	}
}

func createTestUserProfilePicture(t *testing.T, userId int64) *models.UserProfilePicture {
	pictureData := createTestPNG(100, 100)
	profilePicture := &models.UserProfilePicture{
		UserId:      userId,
		Picture:     pictureData,
		ContentType: "image/png",
	}
	err := database.CreateUserProfilePicture(nil, profilePicture)
	if err != nil {
		t.Fatalf("Failed to create test profile picture: %v", err)
	}
	return profilePicture
}
