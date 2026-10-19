// image-upload.js is the image upload of the account picture, client logo and user picture pages:
// a file chosen, cropped in a dialog with Cropper.js, sent, and deleted after a confirmation. Each
// page draws the same widget and configures it on #imageUploadContainer:
//
//   data-upload-url    POST target
//   data-delete-url    DELETE target
//   data-field-name    the multipart field the image goes in
//   data-url-key       the key of the JSON answer holding the new image's URL
//   data-crop-mode     "square", 1:1 at 512 by 512, or "free", any rectangle, its longest side
//                      at most 512
//   data-output-format "jpeg", always JPEG at 0.9, or "preserve", the chosen file's format,
//                      transparency included, a GIF sent as PNG
//   data-alt, data-crop-alt
//                      the preview image's and the image being cropped's text alternatives
//   data-uploaded, data-deleted
//                      the sentences the status region says after each
//   data-delete-title, data-delete-confirm
//                      what the delete dialog, #deleteImage, asks
//
// The preview frame, #imagePreview, holds the image when there is one; ui.css hides the frame's
// placeholder then. What the widget says goes to its status region, #imageUploadStatus, a live
// region, through showNotice. The crop dialog is a <dialog>, so Escape cancels it and focus goes
// back to the button that opened it, and whichever way it closes it lets go of the chosen file.

(function () {
  const maxSize = 3 * 1024 * 1024;
  const allowedTypes = ["image/jpeg", "image/png", "image/gif", "image/webp"];
  let cropper = null;
  let fileType = null;

  const container = document.getElementById("imageUploadContainer");
  if (!container) {
    return;
  }
  const config = container.dataset;
  const fileInput = document.getElementById("imageUploadInput");
  const uploadButton = document.getElementById("uploadImageBtn");
  const deleteButton = document.getElementById("deleteImageBtn");
  const preview = document.getElementById("imagePreview");
  const status = document.getElementById("imageUploadStatus");
  const cropDialog = document.getElementById("cropDialog");
  const cropArea = document.getElementById("cropArea");
  const confirmButton = document.getElementById("confirmCropBtn");
  const confirmLabel = confirmButton.textContent;

  // The CSRF header, when the page carries the token.
  function csrfHeaders() {
    const token = document.querySelector('input[name="gorilla.csrf.Token"]');
    return token ? { "X-CSRF-Token": token.value } : {};
  }

  function chooseFile() {
    const file = fileInput.files[0];
    if (!file) {
      return;
    }
    if (!allowedTypes.includes(file.type)) {
      fileInput.value = "";
      showNotice(status, "danger", t("js.image_upload.invalid_format"));
      return;
    }
    // The server holds its own limit; this one spares sending a file it would refuse.
    if (file.size > maxSize) {
      fileInput.value = "";
      showNotice(status, "danger", t("js.image_upload.file_too_large"));
      return;
    }
    fileType = file.type;
    const reader = new FileReader();
    reader.addEventListener("load", function () {
      const image = document.createElement("img");
      image.alt = config.cropAlt;
      image.addEventListener("load", function () {
        cropper = new Cropper(image, {
          aspectRatio: config.cropMode === "free" ? NaN : 1,
          viewMode: 1,
          minCropBoxWidth: 64,
          minCropBoxHeight: 64,
          responsive: true,
          restore: false,
          guides: true,
          center: true,
          highlight: false,
          toggleDragModeOnDblclick: false
        });
      });
      image.src = reader.result;
      cropArea.replaceChildren(image);
      cropDialog.showModal();
    });
    reader.readAsDataURL(file);
  }

  // Whichever way the crop dialog closes, Cancel, Escape or a finished upload, the chosen file
  // and the cropper go with it.
  function releaseFile() {
    if (cropper) {
      cropper.destroy();
      cropper = null;
    }
    cropArea.replaceChildren();
    fileInput.value = "";
    fileType = null;
    confirmButton.disabled = false;
    confirmButton.textContent = confirmLabel;
  }

  // The canvas size the crop is drawn at: 512 by 512 when square, the crop's own size with its
  // longest side at most 512 when free.
  function canvasSize() {
    if (config.cropMode !== "free") {
      return { width: 512, height: 512 };
    }
    const crop = cropper.getData(true);
    const scale = Math.min(1, 512 / Math.max(crop.width, crop.height));
    return { width: Math.round(crop.width * scale), height: Math.round(crop.height * scale) };
  }

  // The format the crop is sent in: the file name, its type and the quality.
  function outputFormat() {
    if (config.outputFormat === "preserve") {
      if (fileType === "image/png" || fileType === "image/gif") {
        return { name: "image.png", type: "image/png" };
      }
      if (fileType === "image/webp") {
        return { name: "image.webp", type: "image/webp", quality: 0.9 };
      }
    }
    return { name: "image.jpg", type: "image/jpeg", quality: 0.9 };
  }

  function confirmCrop() {
    if (!cropper) {
      return;
    }
    confirmButton.disabled = true;
    confirmButton.textContent = t("js.image_upload.uploading");
    const size = canvasSize();
    const format = outputFormat();
    // JPEG has no transparency, and the cropper leaves a transparent area black, so a picture sent
    // as JPEG has it filled white.
    const canvas = cropper.getCroppedCanvas({
      width: size.width,
      height: size.height,
      fillColor: format.type === "image/jpeg" ? "#fff" : "transparent",
      imageSmoothingEnabled: true,
      imageSmoothingQuality: "high"
    });
    canvas.toBlob(function (blob) {
      upload(blob, format.name);
    }, format.type, format.quality);
  }

  function upload(blob, name) {
    const form = new FormData();
    form.append(config.fieldName, blob, name);
    fetch(withPageLanguage(config.uploadUrl), { method: "POST", body: form, headers: csrfHeaders() })
      .then((response) => response.json().then((data) => {
        // The admin API refused the access token: sign out at once, as the home page then says
        // why. The promise never settles, so nothing flashes while the page leaves.
        if (isSessionEnded(data)) {
          goToSessionEnded();
          return new Promise(() => {});
        }
        // The console's JSON writers put the code in error and the sentence in
        // error_description (#279).
        if (!response.ok || !data.success) {
          throw new Error(data.error_description || data.error || t("js.image_upload.upload_failed"));
        }
        return data;
      }))
      .then((data) => {
        cropDialog.close();
        showImage(data[config.urlKey]);
        showNotice(status, "positive", config.uploaded);
      })
      .catch((error) => {
        cropDialog.close();
        showNotice(status, "danger", error.message);
      });
  }

  function askToDelete() {
    showModalDialog("deleteImage", config.deleteTitle, config.deleteConfirm, null, deleteImage);
  }

  // deleteImage deletes the image. The Delete button is disabled while it does, which drops its
  // focus, the focus its dialog gave back to it, so where focus goes is decided from before: to the
  // Upload button once the image and its Delete button are gone, back to Delete when the deletion
  // fails.
  function deleteImage() {
    const hadFocus = document.activeElement === deleteButton;
    deleteButton.disabled = true;
    fetch(withPageLanguage(config.deleteUrl), { method: "DELETE", headers: csrfHeaders() })
      .then((response) => response.json().then((data) => {
        // As the upload does: a refused access token signs out at once.
        if (isSessionEnded(data)) {
          goToSessionEnded();
          return new Promise(() => {});
        }
        if (!response.ok || !data.success) {
          throw new Error(data.error_description || data.error || t("js.image_upload.delete_failed"));
        }
        return data;
      }))
      .then(() => {
        showImage(null);
        if (hadFocus) {
          uploadButton.focus();
        }
        showNotice(status, "positive", config.deleted);
      })
      .catch((error) => {
        showNotice(status, "danger", error.message);
      })
      .finally(() => {
        deleteButton.disabled = false;
        if (hadFocus && !deleteButton.hidden) {
          deleteButton.focus();
        }
      });
  }

  // showImage puts the image at url in the preview, a fresh request each time, or takes it away
  // when url is null. The Delete button is shown only beside an image.
  function showImage(url) {
    const current = preview.querySelector("img");
    if (current) {
      current.remove();
    }
    if (url) {
      const image = document.createElement("img");
      image.alt = config.alt;
      image.src = url + "?t=" + Date.now();
      preview.appendChild(image);
      deleteButton.hidden = false;
      return;
    }
    deleteButton.hidden = true;
  }

  uploadButton.addEventListener("click", function () {
    fileInput.click();
  });
  fileInput.addEventListener("change", chooseFile);
  deleteButton.addEventListener("click", askToDelete);
  document.getElementById("cancelCropBtn").addEventListener("click", function () {
    cropDialog.close();
  });
  confirmButton.addEventListener("click", confirmCrop);
  cropDialog.addEventListener("close", releaseFile);
})();
