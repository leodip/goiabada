package adminsettingshandlers

// consoleBaseURL is the admin console base URL every handler in these tests is built with. It is
// not the configuration's default, http://localhost:9091, so a handler building a redirect from
// anything but the value it was given cannot pass a test that reads the redirect (#441).
const consoleBaseURL = "https://console.example.test"
