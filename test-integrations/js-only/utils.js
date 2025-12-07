export function isEmpty(str) {
  return (!str || str.length === 0);
}

export function log(message, color) {
  const now = new Date();
  const timestamp = now.toLocaleTimeString('en-US', { hour12: false }) + '.' + String(now.getMilliseconds()).padStart(3, '0');
  const style = color ? `color: ${color}` : "";
  const msg = `<p style="${style}"><span style="color: #888">[${timestamp}]</span> ${message}</p>`;
  const logEl = document.getElementById("log");
  logEl.innerHTML += msg;
  logEl.scrollTop = logEl.scrollHeight;
}

export function logJson(obj) {
  const logEl = document.getElementById("log");
  logEl.innerHTML += "<pre>" + JSON.stringify(obj, null, 2) + "</pre>";
  logEl.scrollTop = logEl.scrollHeight;
}

export function logError(err) {
  // Extract clean error message from oauth4webapi errors
  let errorMsg = "";
  if (err.error && err.error_description) {
    errorMsg = err.error + ": " + err.error_description;
  } else if (err.message) {
    errorMsg = err.message;
  } else {
    errorMsg = String(err);
  }
  log("Error: " + errorMsg, "red");
}
