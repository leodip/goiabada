// Profile Picture Upload with Cropper.js
// This script handles profile picture upload with client-side cropping

(function() {
    'use strict';

    let cropper = null;
    let currentFile = null;

    // Initialize when DOM is ready
    document.addEventListener('DOMContentLoaded', function() {
        initProfilePicture();
    });

    function initProfilePicture() {
        const fileInput = document.getElementById('profilePictureInput');
        const uploadBtn = document.getElementById('uploadPictureBtn');
        const deleteBtn = document.getElementById('deletePictureBtn');
        const cropModal = document.getElementById('cropModal');

        if (!fileInput) return; // Profile picture not on this page

        // File input change handler
        fileInput.addEventListener('change', handleFileSelect);

        // Upload button click handler
        if (uploadBtn) {
            uploadBtn.addEventListener('click', function() {
                fileInput.click();
            });
        }

        // Delete button click handler
        if (deleteBtn) {
            deleteBtn.addEventListener('click', handleDelete);
        }

        // Modal buttons
        const cancelCropBtn = document.getElementById('cancelCropBtn');
        const confirmCropBtn = document.getElementById('confirmCropBtn');

        if (cancelCropBtn) {
            cancelCropBtn.addEventListener('click', closeCropModal);
        }

        if (confirmCropBtn) {
            confirmCropBtn.addEventListener('click', handleCropConfirm);
        }

        // Close modal on backdrop click
        if (cropModal) {
            cropModal.addEventListener('click', function(e) {
                if (e.target === cropModal) {
                    closeCropModal();
                }
            });
        }
    }

    function handleFileSelect(event) {
        const file = event.target.files[0];
        if (!file) return;

        // Validate file type
        const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
        if (!allowedTypes.includes(file.type)) {
            showError('Please select a valid image file (JPEG, PNG, GIF, or WebP)');
            event.target.value = '';
            return;
        }

        // Validate file size (3MB default, but actual limit is server-side)
        const maxSize = 3 * 1024 * 1024;
        if (file.size > maxSize) {
            showError('File is too large. Maximum size is 3MB.');
            event.target.value = '';
            return;
        }

        currentFile = file;
        openCropModal(file);
    }

    function openCropModal(file) {
        const cropModal = document.getElementById('cropModal');
        const cropImage = document.getElementById('cropImage');

        if (!cropModal || !cropImage) return;

        // Read file and display in modal
        const reader = new FileReader();
        reader.onload = function(e) {
            cropImage.src = e.target.result;
            cropModal.classList.remove('hidden');
            cropModal.classList.add('flex');

            // Initialize Cropper.js after image loads
            cropImage.onload = function() {
                if (cropper) {
                    cropper.destroy();
                }

                cropper = new Cropper(cropImage, {
                    aspectRatio: 1, // Square
                    viewMode: 1,
                    minCropBoxWidth: 64,
                    minCropBoxHeight: 64,
                    maxCropBoxWidth: 512,
                    maxCropBoxHeight: 512,
                    responsive: true,
                    restore: false,
                    guides: true,
                    center: true,
                    highlight: false,
                    cropBoxMovable: true,
                    cropBoxResizable: true,
                    toggleDragModeOnDblclick: false,
                });
            };
        };
        reader.readAsDataURL(file);
    }

    function closeCropModal() {
        const cropModal = document.getElementById('cropModal');
        const fileInput = document.getElementById('profilePictureInput');

        if (cropModal) {
            cropModal.classList.add('hidden');
            cropModal.classList.remove('flex');
        }

        if (cropper) {
            cropper.destroy();
            cropper = null;
        }

        if (fileInput) {
            fileInput.value = '';
        }

        currentFile = null;
    }

    function handleCropConfirm() {
        if (!cropper) return;

        const confirmBtn = document.getElementById('confirmCropBtn');
        if (confirmBtn) {
            confirmBtn.disabled = true;
            confirmBtn.textContent = 'Uploading...';
        }

        // Get cropped canvas
        const canvas = cropper.getCroppedCanvas({
            width: 512,
            height: 512,
            imageSmoothingEnabled: true,
            imageSmoothingQuality: 'high',
        });

        // Convert to blob
        canvas.toBlob(function(blob) {
            uploadPicture(blob);
        }, 'image/jpeg', 0.9);
    }

    function uploadPicture(blob) {
        const formData = new FormData();
        formData.append('picture', blob, 'profile.jpg');

        // Get upload URL from data attribute
        const container = document.getElementById('profilePictureContainer');
        const uploadUrl = container ? container.dataset.uploadUrl : '';

        if (!uploadUrl) {
            showError('Upload URL not configured');
            resetUploadButton();
            return;
        }

        // Get CSRF token
        const csrfToken = document.querySelector('input[name="gorilla.csrf.Token"]');

        fetch(uploadUrl, {
            method: 'POST',
            body: formData,
            headers: csrfToken ? {
                'X-CSRF-Token': csrfToken.value
            } : {}
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.error || 'Upload failed');
                });
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                // Update the preview image
                updatePreviewImage(data.pictureUrl);
                showSuccess('Profile picture updated successfully');
                closeCropModal();

                // Show delete button
                const deleteBtn = document.getElementById('deletePictureBtn');
                if (deleteBtn) {
                    deleteBtn.classList.remove('hidden');
                }
            } else {
                throw new Error(data.error || 'Upload failed');
            }
        })
        .catch(error => {
            showError(error.message);
        })
        .finally(() => {
            resetUploadButton();
        });
    }

    function handleDelete() {
        if (!confirm('Are you sure you want to delete your profile picture?')) {
            return;
        }

        const deleteBtn = document.getElementById('deletePictureBtn');
        if (deleteBtn) {
            deleteBtn.disabled = true;
            deleteBtn.textContent = 'Deleting...';
        }

        // Get delete URL from data attribute
        const container = document.getElementById('profilePictureContainer');
        const deleteUrl = container ? container.dataset.deleteUrl : '';

        if (!deleteUrl) {
            showError('Delete URL not configured');
            resetDeleteButton();
            return;
        }

        // Get CSRF token
        const csrfToken = document.querySelector('input[name="gorilla.csrf.Token"]');

        fetch(deleteUrl, {
            method: 'DELETE',
            headers: csrfToken ? {
                'X-CSRF-Token': csrfToken.value
            } : {}
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.error || 'Delete failed');
                });
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                // Reset to default avatar
                resetToDefaultAvatar();
                showSuccess('Profile picture deleted successfully');

                // Hide delete button
                if (deleteBtn) {
                    deleteBtn.classList.add('hidden');
                }
            } else {
                throw new Error(data.error || 'Delete failed');
            }
        })
        .catch(error => {
            showError(error.message);
        })
        .finally(() => {
            resetDeleteButton();
        });
    }

    function updatePreviewImage(url) {
        const preview = document.getElementById('profilePicturePreview');
        const placeholder = document.getElementById('profilePicturePlaceholder');

        if (preview) {
            // Add cache-busting parameter
            preview.src = url + '?t=' + Date.now();
            preview.classList.remove('hidden');
        }

        if (placeholder) {
            placeholder.classList.add('hidden');
            placeholder.classList.remove('flex');
        }
    }

    function resetToDefaultAvatar() {
        const preview = document.getElementById('profilePicturePreview');
        const placeholder = document.getElementById('profilePicturePlaceholder');

        if (preview) {
            preview.src = '';
            preview.classList.add('hidden');
        }

        if (placeholder) {
            placeholder.classList.remove('hidden');
            placeholder.classList.add('flex');
        }
    }

    function resetUploadButton() {
        const confirmBtn = document.getElementById('confirmCropBtn');
        if (confirmBtn) {
            confirmBtn.disabled = false;
            confirmBtn.textContent = 'Upload';
        }
    }

    function resetDeleteButton() {
        const deleteBtn = document.getElementById('deletePictureBtn');
        if (deleteBtn) {
            deleteBtn.disabled = false;
            deleteBtn.textContent = 'Delete';
        }
    }

    function showError(message) {
        // Try to use existing error display mechanism
        const errorDiv = document.getElementById('profilePictureError');
        if (errorDiv) {
            errorDiv.textContent = message;
            errorDiv.classList.remove('hidden');
            setTimeout(() => {
                errorDiv.classList.add('hidden');
            }, 5000);
        } else {
            alert('Error: ' + message);
        }
    }

    function showSuccess(message) {
        const successDiv = document.getElementById('profilePictureSuccess');
        if (successDiv) {
            successDiv.textContent = message;
            successDiv.classList.remove('hidden');
            setTimeout(() => {
                successDiv.classList.add('hidden');
            }, 3000);
        }
    }
})();
