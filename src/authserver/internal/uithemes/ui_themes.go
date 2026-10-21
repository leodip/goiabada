package uithemes

// Get returns the themes an administrator can choose besides the automatic one, which the settings
// store as the empty value. Each is a data-theme value the layouts write and ui.css draws.
func Get() []string {
	return []string{
		"light",
		"dark",
	}
}
