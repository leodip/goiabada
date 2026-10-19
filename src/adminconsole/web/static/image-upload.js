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
// region, through showNotice.
//
// The crop dialog is the crop_dialog partial: the cropper's canvas in #cropArea, and sliders that
// do what dragging the crop does, for a keyboard or a single tap: #cropZoom, #cropX and #cropY, and
// for a free crop #cropWidth and #cropHeight. The crop is kept in the image's own pixels, so the
// sliders, the drawn selection and the image sent agree whatever size the dialog is drawn at, and
// it never leaves the image. The dialog is a <dialog>, so Escape cancels it and focus goes back to
// the button that opened it, and whichever way it closes it lets go of the chosen file. While the
// crop is being sent it stays open, Cancel disabled and Escape ignored, and the Upload button is
// disabled, so nothing starts another crop before the server answers.

(function () {
  const maxSize = 3 * 1024 * 1024;
  const allowedTypes = ["image/jpeg", "image/png", "image/gif", "image/webp"];
  // The least of the image a crop covers, as a share of its width or height.
  const minShare = 0.1;

  const container = document.getElementById("imageUploadContainer");
  if (!container) {
    return;
  }
  const config = container.dataset;
  const free = config.cropMode === "free";
  const fileInput = document.getElementById("imageUploadInput");
  const uploadButton = document.getElementById("uploadImageBtn");
  const deleteButton = document.getElementById("deleteImageBtn");
  const preview = document.getElementById("imagePreview");
  const status = document.getElementById("imageUploadStatus");
  const cropDialog = document.getElementById("cropDialog");
  const cropArea = document.getElementById("cropArea");
  const cancelButton = document.getElementById("cancelCropBtn");
  const confirmButton = document.getElementById("confirmCropBtn");
  const confirmLabel = confirmButton.textContent;
  const sliders = {
    zoom: document.getElementById("cropZoom"),
    x: document.getElementById("cropX"),
    y: document.getElementById("cropY"),
    width: document.getElementById("cropWidth"),
    height: document.getElementById("cropHeight")
  };

  // The open crop: the cropper, the chosen file's type, the image's own size, the crop in the
  // image's pixels, and where the image is drawn in the cropper's canvas, set once it is drawn.
  let cropper = null;
  let fileType = null;
  let natural = null;
  let crop = null;
  let drawn = null;
  let resizeObserver = null;
  let uploading = false;

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
    // The file is decoded before the dialog opens, so a file that is not the image its type
    // claims is refused here rather than opening a crop of nothing.
    const reader = new FileReader();
    reader.addEventListener("error", unreadable);
    reader.addEventListener("load", function () {
      const image = document.createElement("img");
      image.alt = config.cropAlt;
      image.src = reader.result;
      image.decode().then(function () {
        fileType = file.type;
        openCrop(image);
      }, unreadable);
    });
    reader.readAsDataURL(file);
  }

  function unreadable() {
    fileInput.value = "";
    showNotice(status, "danger", t("js.image_upload.unreadable"));
  }

  // The cropper's elements: the image, which the person neither moves nor scales, the selection,
  // square for a picture, and its handles. The selection, its guides and handles, and the shade
  // are drawn for a pointer and hidden from assistive technology, for which the sliders do the
  // same; the image keeps its text alternative.
  function cropTemplate() {
    const handles = ["n", "e", "s", "w", "ne", "nw", "se", "sw"].map(function (side) {
      return '<cropper-handle action="' + side + '-resize"></cropper-handle>';
    }).join("");
    return '<cropper-canvas background>'
      + '<cropper-image initial-fit="contain"></cropper-image>'
      + '<cropper-shade hidden aria-hidden="true"></cropper-shade>'
      + '<cropper-selection movable resizable precise aria-hidden="true"' + (free ? "" : ' aspect-ratio="1"') + '>'
      + '<cropper-grid bordered covered></cropper-grid>'
      + '<cropper-crosshair centered></cropper-crosshair>'
      + '<cropper-handle action="move" theme-color="rgba(255, 255, 255, 0.35)"></cropper-handle>'
      + handles
      + '</cropper-selection>'
      + '</cropper-canvas>';
  }

  // openCrop opens the dialog over image and, once the cropper has drawn it, starts the crop at
  // the whole image, the largest centered square of it for a picture.
  function openCrop(image) {
    natural = { width: image.naturalWidth, height: image.naturalHeight };
    cropArea.replaceChildren(image);
    cropDialog.showModal();
    // The bundle's global, Cropper, is its module: the class is its Cropper.
    const opened = new Cropper.Cropper(image, { container: cropArea, template: cropTemplate() });
    cropper = opened;
    opened.getCropperSelection().addEventListener("change", followSelection);
    opened.getCropperImage().$ready().then(function () {
      // A frame later the image has its fitted size.
      requestAnimationFrame(function () {
        if (cropper !== opened) {
          return;
        }
        const side = Math.min(natural.width, natural.height);
        crop = free ? { x: 0, y: 0, width: natural.width, height: natural.height }
          : { x: (natural.width - side) / 2, y: (natural.height - side) / 2, width: side, height: side };
        fit();
        resizeObserver = new ResizeObserver(refit);
        resizeObserver.observe(opened.getCropperCanvas());
        if (document.activeElement === cancelButton) {
          sliders.zoom.focus();
        }
      });
    }, function () {
      if (cropper === opened) {
        cropDialog.close();
        unreadable();
      }
    });
  }

  // fit measures where the image is drawn in the canvas and draws the crop there.
  function fit() {
    const canvasBox = cropper.getCropperCanvas().getBoundingClientRect();
    const imageBox = cropper.getCropperImage().getBoundingClientRect();
    drawn = {
      left: imageBox.left - canvasBox.left,
      top: imageBox.top - canvasBox.top,
      scale: imageBox.width / natural.width
    };
    show(crop);
  }

  // refit draws the image to fit the canvas again once the dialog changes size, and the crop with
  // it. The image takes no move or scale from the person, so it allows them for this call alone.
  function refit() {
    if (!drawn) {
      return;
    }
    const image = cropper.getCropperImage();
    image.translatable = true;
    image.scalable = true;
    image.$center("contain");
    image.translatable = false;
    image.scalable = false;
    fit();
  }

  // clamp keeps a crop to its shape, at least minShare of the image and at most all of it, and
  // within the image.
  function clamp(next) {
    let width;
    let height;
    if (free) {
      width = Math.min(Math.max(next.width, natural.width * minShare), natural.width);
      height = Math.min(Math.max(next.height, natural.height * minShare), natural.height);
    } else {
      const most = Math.min(natural.width, natural.height);
      width = Math.min(Math.max(next.width, most * minShare), most);
      height = width;
    }
    return {
      x: Math.min(Math.max(next.x, 0), natural.width - width),
      y: Math.min(Math.max(next.y, 0), natural.height - height),
      width: width,
      height: height
    };
  }

  // show makes next the crop and draws it.
  function show(next) {
    crop = clamp(next);
    cropper.getCropperSelection().$change(drawn.left + crop.x * drawn.scale, drawn.top + crop.y * drawn.scale,
      crop.width * drawn.scale, crop.height * drawn.scale);
    update();
  }

  // followSelection has the crop follow a dragged selection, and refuses a move or resize that
  // would take it off the image or below the least crop. Half a drawn pixel of slack allows for
  // the rounding of what is drawn.
  function followSelection(event) {
    const box = event.detail;
    if (!drawn || (box.width === 0 && box.height === 0)) {
      return;
    }
    const next = {
      x: (box.x - drawn.left) / drawn.scale,
      y: (box.y - drawn.top) / drawn.scale,
      width: box.width / drawn.scale,
      height: box.height / drawn.scale
    };
    const slack = 0.5 / drawn.scale;
    const least = clamp({ x: 0, y: 0, width: 0, height: 0 });
    if (next.x < -slack || next.y < -slack
      || next.x + next.width > natural.width + slack || next.y + next.height > natural.height + slack
      || next.width < least.width - slack || next.height < least.height - slack) {
      event.preventDefault();
      return;
    }
    crop = clamp(next);
    update();
  }

  // update sets the sliders from the crop, each a percentage and said as one, and which controls
  // may be used: none until the crop is drawn or while it is being sent, and a position slider
  // only while the crop has room to move that way.
  function update() {
    const usable = drawn !== null && !uploading;
    const roomX = crop ? natural.width - crop.width : 0;
    const roomY = crop ? natural.height - crop.height : 0;
    if (crop) {
      const share = Math.max(crop.width / natural.width, crop.height / natural.height);
      setSlider(sliders.zoom, (1 - share) / (1 - minShare) * 100);
      setSlider(sliders.x, roomX > 0 ? crop.x / roomX * 100 : 50);
      setSlider(sliders.y, roomY > 0 ? crop.y / roomY * 100 : 50);
      if (free) {
        setSlider(sliders.width, crop.width / natural.width * 100);
        setSlider(sliders.height, crop.height / natural.height * 100);
      }
    }
    sliders.zoom.disabled = !usable;
    sliders.x.disabled = !usable || roomX < 0.5;
    sliders.y.disabled = !usable || roomY < 0.5;
    if (free) {
      sliders.width.disabled = !usable;
      sliders.height.disabled = !usable;
    }
    confirmButton.disabled = !usable;
  }

  function setSlider(slider, value) {
    slider.value = String(Math.round(value));
    slider.setAttribute("aria-valuetext", slider.value + "%");
  }

  // Whichever way the crop dialog closes, Cancel, Escape or a finished upload, the chosen file
  // and the cropper go with it.
  function releaseFile() {
    if (resizeObserver) {
      resizeObserver.disconnect();
      resizeObserver = null;
    }
    if (cropper) {
      cropper.destroy();
      cropper = null;
    }
    cropArea.replaceChildren();
    fileInput.value = "";
    fileType = null;
    natural = null;
    crop = null;
    drawn = null;
    update();
  }

  // The size the crop is sent at: 512 by 512 when square, the crop's own size with its longest
  // side at most 512 when free.
  function outputSize() {
    if (!free) {
      return { width: 512, height: 512 };
    }
    const scale = Math.min(1, 512 / Math.max(crop.width, crop.height));
    return {
      width: Math.max(1, Math.round(crop.width * scale)),
      height: Math.max(1, Math.round(crop.height * scale))
    };
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

  // setUploading holds the dialog open, and every control that could start another crop or change
  // this one disabled, while the crop is being sent.
  function setUploading(on) {
    uploading = on;
    cancelButton.disabled = on;
    uploadButton.disabled = on;
    confirmButton.textContent = on ? t("js.image_upload.uploading") : confirmLabel;
    update();
  }

  function confirmCrop() {
    if (!drawn || uploading) {
      return;
    }
    const size = outputSize();
    const format = outputFormat();
    setUploading(true);
    cropper.getCropperSelection().$toCanvas({
      width: size.width,
      height: size.height,
      beforeDraw: function (context, canvas) {
        context.imageSmoothingEnabled = true;
        context.imageSmoothingQuality = "high";
        // JPEG has no transparency: what the image leaves transparent is sent white.
        if (format.type === "image/jpeg") {
          context.fillStyle = "#fff";
          context.fillRect(0, 0, canvas.width, canvas.height);
        }
      }
    }).then(function (canvas) {
      canvas.toBlob(function (blob) {
        if (blob) {
          upload(blob, format.name);
        } else {
          failUpload(t("js.image_upload.upload_failed"));
        }
      }, format.type, format.quality);
    }, function () {
      failUpload(t("js.image_upload.upload_failed"));
    });
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
        // The Upload button is enabled again before the dialog closes, so the focus the dialog
        // gives back to it is kept.
        setUploading(false);
        cropDialog.close();
        showImage(data[config.urlKey]);
        showNotice(status, "positive", config.uploaded);
      })
      .catch((error) => {
        failUpload(error.message);
      });
  }

  function failUpload(message) {
    setUploading(false);
    cropDialog.close();
    showNotice(status, "danger", message);
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
  cancelButton.addEventListener("click", function () {
    cropDialog.close();
  });
  confirmButton.addEventListener("click", confirmCrop);
  cropDialog.addEventListener("cancel", function (event) {
    if (uploading) {
      event.preventDefault();
    }
  });
  cropDialog.addEventListener("close", releaseFile);
  sliders.zoom.addEventListener("input", function () {
    const share = 1 - Number(sliders.zoom.value) / 100 * (1 - minShare);
    const scale = share / Math.max(crop.width / natural.width, crop.height / natural.height);
    const width = crop.width * scale;
    const height = crop.height * scale;
    show({ x: crop.x + (crop.width - width) / 2, y: crop.y + (crop.height - height) / 2, width: width, height: height });
  });
  sliders.x.addEventListener("input", function () {
    show(Object.assign({}, crop, { x: Number(sliders.x.value) / 100 * (natural.width - crop.width) }));
  });
  sliders.y.addEventListener("input", function () {
    show(Object.assign({}, crop, { y: Number(sliders.y.value) / 100 * (natural.height - crop.height) }));
  });
  if (free) {
    sliders.width.addEventListener("input", function () {
      const width = Number(sliders.width.value) / 100 * natural.width;
      show(Object.assign({}, crop, { x: crop.x + (crop.width - width) / 2, width: width }));
    });
    sliders.height.addEventListener("input", function () {
      const height = Number(sliders.height.value) / 100 * natural.height;
      show(Object.assign({}, crop, { y: crop.y + (crop.height - height) / 2, height: height }));
    });
  }
})();
