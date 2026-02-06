// Image Upload with Cropper.js
// Generic image upload with client-side cropping, configurable via data-* attributes on the container element.
//
// Required data attributes on #imageUploadContainer:
//   data-upload-url    - POST target URL
//   data-delete-url    - DELETE target URL
//
// Optional data attributes (with defaults for backwards compatibility):
//   data-field-name    - multipart form field name (default: "picture")
//   data-url-key       - JSON response key for the image URL (default: "pictureUrl")
//   data-entity-label  - label used in UI text, e.g. "profile picture" or "logo" (default: "profile picture")
//   data-crop-mode     - "square" (1:1 aspect ratio, 512x512) or "free" (any rectangle, longest side capped at 512) (default: "square")
//   data-output-format - "jpeg" (forced JPEG 0.9) or "preserve" (keep original format/transparency) (default: "jpeg")

(function() {
    'use strict';

    let cropper = null;
    let currentFile = null;
    let currentFileMimeType = null;

    // Initialize when DOM is ready
    document.addEventListener('DOMContentLoaded', function() {
        initImageUpload();
    });

    function getConfig() {
        const container = document.getElementById('imageUploadContainer');
        if (!container) return null;
        return {
            uploadUrl: container.dataset.uploadUrl || '',
            deleteUrl: container.dataset.deleteUrl || '',
            fieldName: container.dataset.fieldName || 'picture',
            urlKey: container.dataset.urlKey || 'pictureUrl',
            entityLabel: container.dataset.entityLabel || 'profile picture',
            cropMode: container.dataset.cropMode || 'square',
            outputFormat: container.dataset.outputFormat || 'jpeg',
        };
    }

    function initImageUpload() {
        const fileInput = document.getElementById('imageUploadInput');
        const uploadBtn = document.getElementById('uploadImageBtn');
        const deleteBtn = document.getElementById('deleteImageBtn');
        const cropModal = document.getElementById('cropModal');

        if (!fileInput) return; // Image upload not on this page

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
        currentFileMimeType = file.type;
        openCropModal(file);
    }

    function openCropModal(file) {
        const cropModal = document.getElementById('cropModal');
        const cropImage = document.getElementById('cropImage');
        const cfg = getConfig();

        if (!cropModal || !cropImage || !cfg) return;

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

                const isFree = cfg.cropMode === 'free';

                cropper = new Cropper(cropImage, {
                    aspectRatio: isFree ? NaN : 1,
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
        const fileInput = document.getElementById('imageUploadInput');

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
        currentFileMimeType = null;
    }

    function handleCropConfirm() {
        if (!cropper) return;

        const confirmBtn = document.getElementById('confirmCropBtn');
        if (confirmBtn) {
            confirmBtn.disabled = true;
            confirmBtn.textContent = 'Uploading...';
        }

        const cfg = getConfig();
        if (!cfg) return;

        // Build canvas options based on crop mode
        var canvasOpts = {
            imageSmoothingEnabled: true,
            imageSmoothingQuality: 'high',
        };

        if (cfg.cropMode === 'free') {
            // Use natural crop dimensions, cap longest side at 512
            var cropData = cropper.getData(true); // rounded
            var w = cropData.width;
            var h = cropData.height;
            if (w > 512 || h > 512) {
                if (w >= h) {
                    canvasOpts.width = 512;
                    canvasOpts.height = Math.round(512 * h / w);
                } else {
                    canvasOpts.height = 512;
                    canvasOpts.width = Math.round(512 * w / h);
                }
            } else {
                canvasOpts.width = w;
                canvasOpts.height = h;
            }
        } else {
            // Square: fixed 512x512
            canvasOpts.width = 512;
            canvasOpts.height = 512;
        }

        const canvas = cropper.getCroppedCanvas(canvasOpts);

        // Determine output format
        if (cfg.outputFormat === 'preserve') {
            var mime = currentFileMimeType || 'image/jpeg';
            var ext = 'image.jpg';
            var quality = undefined;

            if (mime === 'image/png') {
                // PNG: preserve transparency, no quality param
                ext = 'image.png';
            } else if (mime === 'image/webp') {
                ext = 'image.webp';
                quality = 0.9;
            } else if (mime === 'image/gif') {
                // GIF -> PNG fallback (canvas can't encode GIF reliably)
                mime = 'image/png';
                ext = 'image.png';
            } else {
                // JPEG or fallback
                mime = 'image/jpeg';
                ext = 'image.jpg';
                quality = 0.9;
            }

            if (quality !== undefined) {
                canvas.toBlob(function(blob) {
                    uploadImage(blob, ext);
                }, mime, quality);
            } else {
                canvas.toBlob(function(blob) {
                    uploadImage(blob, ext);
                }, mime);
            }
        } else {
            // Forced JPEG
            canvas.toBlob(function(blob) {
                uploadImage(blob, 'image.jpg');
            }, 'image/jpeg', 0.9);
        }
    }

    function uploadImage(blob, filename) {
        const cfg = getConfig();
        if (!cfg) return;

        const formData = new FormData();
        formData.append(cfg.fieldName, blob, filename);

        if (!cfg.uploadUrl) {
            showError('Upload URL not configured');
            resetUploadButton();
            return;
        }

        // Get CSRF token
        const csrfToken = document.querySelector('input[name="gorilla.csrf.Token"]');

        fetch(cfg.uploadUrl, {
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
                // Update the preview image using the configured URL key
                updatePreviewImage(data[cfg.urlKey]);
                showSuccess(capitalize(cfg.entityLabel) + ' updated successfully');
                closeCropModal();

                // Show delete button
                const deleteBtn = document.getElementById('deleteImageBtn');
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
        const cfg = getConfig();
        if (!cfg) return;

        if (!confirm('Are you sure you want to delete your ' + cfg.entityLabel + '?')) {
            return;
        }

        const deleteBtn = document.getElementById('deleteImageBtn');
        if (deleteBtn) {
            deleteBtn.disabled = true;
            deleteBtn.textContent = 'Deleting...';
        }

        if (!cfg.deleteUrl) {
            showError('Delete URL not configured');
            resetDeleteButton();
            return;
        }

        // Get CSRF token
        const csrfToken = document.querySelector('input[name="gorilla.csrf.Token"]');

        fetch(cfg.deleteUrl, {
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
                showSuccess(capitalize(cfg.entityLabel) + ' deleted successfully');

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
        const preview = document.getElementById('imagePreview');
        const placeholder = document.getElementById('imagePlaceholder');

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
        const preview = document.getElementById('imagePreview');
        const placeholder = document.getElementById('imagePlaceholder');

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
        const deleteBtn = document.getElementById('deleteImageBtn');
        if (deleteBtn) {
            deleteBtn.disabled = false;
            deleteBtn.textContent = 'Delete';
        }
    }

    function showError(message) {
        const errorDiv = document.getElementById('imageUploadError');
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
        const successDiv = document.getElementById('imageUploadSuccess');
        if (successDiv) {
            successDiv.textContent = message;
            successDiv.classList.remove('hidden');
            setTimeout(() => {
                successDiv.classList.add('hidden');
            }, 3000);
        }
    }

    function capitalize(str) {
        if (!str) return str;
        return str.charAt(0).toUpperCase() + str.slice(1);
    }
})();
