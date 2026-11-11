// brand-assets.js runs the brand editor's six upload fields (#813 decision 1): the logo, the dark logo,
// the favicon, the background image and the uploaded font's two files. Upload opens the file picker;
// a file picked is sent at once to the console's route of its kind (data-upload-url), which stores it
// as a brand asset and answers its id and URL. The slot's two hidden fields take them, so Save names
// the asset in the slot and brand-preview.js draws it in the sample at once, from the input event the
// fields are given. Remove empties both. Nothing reaches a real page until the brand is saved, which
// the field's status says.
//
// A file over the kind's byte limit is refused here, with the sentence the admin API refuses it with,
// so a file it would refuse is not sent. Any other refusal is the admin API's, about the file's type,
// pixels, shape or animation, said at the field, in the page's language. The admin API refusing the
// access token signs the administrator out, as every other request of the console's pages does.
//
// What a field shows is drawn from its two hidden fields alone, on load and on pageshow too, as a
// browser restoring the form on Back fills them and fires nothing: the image's thumbnail, the sentence
// saying whether the slot holds a file, and Remove while it does.

(function () {
  const form = document.querySelector(".brand-editor form");
  if (!form) {
    return;
  }
  const says = {
    uploading: form.dataset.assetUploading || "",
    uploaded: form.dataset.assetUploaded || "",
    removed: form.dataset.assetRemoved || "",
    failed: form.dataset.assetUploadFailed || "",
  };

  // The CSRF header, when the page carries the token.
  function csrfHeaders() {
    const token = document.querySelector('input[name="gorilla.csrf.Token"]');
    return token ? { "X-CSRF-Token": token.value } : {};
  }

  // A refusal the console answered, whose sentence is shown as it came.
  class Refusal extends Error {}

  function setUp(field) {
    const slot = field.dataset.brandAsset;
    const fileInput = document.getElementById(slot + "File");
    const upload = field.querySelector("[data-brand-asset-upload]");
    const remove = field.querySelector("[data-brand-asset-remove]");
    const status = document.getElementById(slot + "Status");
    const thumb = field.querySelector('[class~="brand-asset-thumb"]');
    const idField = form.querySelector('input[type="hidden"][name="' + slot + '"]');
    const urlField = form.querySelector('input[type="hidden"][name="' + slot + 'Url"]');
    if (!fileInput || !upload || !remove || !status || !idField || !urlField) {
      return;
    }
    let busy = false;

    // draw shows what the slot holds, from its hidden fields.
    function draw() {
      const url = idField.value ? urlField.value : "";
      for (const state of field.querySelectorAll("[data-brand-asset-state]")) {
        state.hidden = (state.dataset.brandAssetState === "filled") !== Boolean(url);
      }
      remove.hidden = !url;
      if (thumb) {
        let image = thumb.querySelector("img");
        if (url) {
          if (!image) {
            image = document.createElement("img");
            image.setAttribute("alt", "");
            thumb.appendChild(image);
          }
          if (image.getAttribute("src") !== url) {
            image.setAttribute("src", url);
          }
        } else if (image) {
          image.remove();
        }
        thumb.hidden = !url;
      }
    }

    // hold puts an asset in the slot, or empties it, and tells the preview.
    function hold(id, url) {
      idField.value = id;
      urlField.value = url;
      draw();
      idField.dispatchEvent(new Event("input", { bubbles: true }));
    }

    function setBusy(on) {
      busy = on;
      upload.disabled = on;
      remove.disabled = on;
    }

    // settle ends an upload, giving the focus back to Upload when the upload's disabling dropped it.
    function settle() {
      setBusy(false);
      const focused = document.activeElement;
      if (!focused || focused === document.body) {
        upload.focus();
      }
    }

    upload.addEventListener("click", function () {
      if (!busy) {
        fileInput.click();
      }
    });

    fileInput.addEventListener("change", function () {
      const file = fileInput.files && fileInput.files[0];
      fileInput.value = "";
      if (!file || busy) {
        return;
      }
      if (file.size > Number(field.dataset.maxBytes)) {
        showNotice(status, "danger", field.dataset.tooLarge || says.failed);
        return;
      }
      setBusy(true);
      showNotice(status, "note", says.uploading);
      const body = new FormData();
      body.append("file", file, file.name);
      fetch(withPageLanguage(field.dataset.uploadUrl), { method: "POST", body: body, headers: csrfHeaders() })
        .then(function (response) {
          return response.json().then(function (data) {
            // The admin API refused the access token: sign out at once, as the home page then says
            // why. The promise never settles, so nothing flashes while the page leaves.
            if (isSessionEnded(data)) {
              goToSessionEnded();
              return new Promise(function () {});
            }
            // The console's JSON writers put the code in error and the sentence in
            // error_description (#279).
            if (!response.ok || !data.brandAsset) {
              throw new Refusal(data.error_description || says.failed);
            }
            return data.brandAsset;
          });
        })
        .then(function (asset) {
          settle();
          hold(String(asset.id), asset.url);
          showNotice(status, "positive", says.uploaded);
        })
        .catch(function (error) {
          // A refusal's own sentence, or, for an answer that was not the console's JSON or no
          // answer at all, the general one.
          settle();
          showNotice(status, "danger", error instanceof Refusal ? error.message : says.failed);
        });
    });

    remove.addEventListener("click", function () {
      if (busy) {
        return;
      }
      hold("", "");
      showNotice(status, "note", says.removed);
      // Remove is hidden now: the focus goes to the field's Upload.
      upload.focus();
    });

    draw();
    window.addEventListener("pageshow", draw);
  }

  for (const field of document.querySelectorAll("[data-brand-asset]")) {
    setUp(field);
  }
})();
