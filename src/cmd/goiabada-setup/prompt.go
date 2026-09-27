package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/chzyer/readline"
)

func promptString(rl *readline.Instance, prompt, defaultValue string) string {
	var promptStr string
	if defaultValue != "" {
		promptStr = fmt.Sprintf("%s [%s]: ", prompt, defaultValue)
	} else {
		promptStr = fmt.Sprintf("%s: ", prompt)
	}
	rl.SetPrompt(promptStr)
	input, err := rl.Readline()
	if err != nil {
		if err == io.EOF || err == readline.ErrInterrupt {
			fmt.Println("\nAborted.")
			os.Exit(0)
		}
		return defaultValue
	}
	input = strings.TrimSpace(input)
	if input == "" {
		return defaultValue
	}
	return input
}

func promptChoice(rl *readline.Instance, prompt string, validChoices []string, defaultValue string) string {
	for {
		promptStr := fmt.Sprintf("%s [%s]: ", prompt, defaultValue)
		rl.SetPrompt(promptStr)
		input, err := rl.Readline()
		if err != nil {
			if err == io.EOF || err == readline.ErrInterrupt {
				fmt.Println("\nAborted.")
				os.Exit(0)
			}
			return defaultValue
		}
		input = strings.TrimSpace(input)
		if input == "" {
			return defaultValue
		}
		for _, valid := range validChoices {
			if input == valid {
				return input
			}
		}
		fmt.Println("Invalid choice. Please try again.")
	}
}

func promptYesNo(rl *readline.Instance, prompt string, defaultYes bool) bool {
	defaultStr := "Y/n"
	if !defaultYes {
		defaultStr = "y/N"
	}
	for {
		promptStr := fmt.Sprintf("%s [%s]: ", prompt, defaultStr)
		rl.SetPrompt(promptStr)
		input, err := rl.Readline()
		if err != nil {
			if err == io.EOF || err == readline.ErrInterrupt {
				fmt.Println("\nAborted.")
				os.Exit(0)
			}
			return defaultYes
		}
		input = strings.TrimSpace(strings.ToLower(input))
		if input == "" {
			return defaultYes
		}
		if input == "y" || input == "yes" {
			return true
		}
		if input == "n" || input == "no" {
			return false
		}
		fmt.Println("Please enter 'y' or 'n'.")
	}
}

func promptURL(rl *readline.Instance, prompt, defaultValue string) string {
	for {
		value := promptString(rl, prompt, defaultValue)
		if err := validateURL(value); err != nil {
			fmt.Printf("Invalid URL: %s. Please try again.\n", err)
			continue
		}
		return value
	}
}

func promptEmail(rl *readline.Instance, prompt, defaultValue string) string {
	for {
		value := promptString(rl, prompt, defaultValue)
		if err := validateEmail(value); err != nil {
			fmt.Printf("Invalid email: %s. Please try again.\n", err)
			continue
		}
		return value
	}
}

func promptHostname(rl *readline.Instance, prompt, defaultValue string) string {
	for {
		value := promptString(rl, prompt, defaultValue)
		if err := validateHostname(value); err != nil {
			fmt.Printf("Invalid hostname: %s. Please try again.\n", err)
			continue
		}
		return value
	}
}

func promptPort(rl *readline.Instance, prompt, defaultValue string) string {
	for {
		value := promptString(rl, prompt, defaultValue)
		if err := validatePort(value); err != nil {
			fmt.Printf("Invalid port: %s. Please try again.\n", err)
			continue
		}
		return value
	}
}

func promptNonEmpty(rl *readline.Instance, prompt, defaultValue string) string {
	for {
		value := promptString(rl, prompt, defaultValue)
		if value == "" {
			fmt.Println("This field cannot be empty. Please try again.")
			continue
		}
		return value
	}
}

func promptNamespace(rl *readline.Instance, prompt, defaultValue string) string {
	for {
		value := promptString(rl, prompt, defaultValue)
		if err := validateNamespace(value); err != nil {
			fmt.Printf("Invalid namespace: %s. Please try again.\n", err)
			continue
		}
		return value
	}
}

func promptDatabaseName(rl *readline.Instance, prompt, defaultValue string) string {
	for {
		value := promptString(rl, prompt, defaultValue)
		if err := validateDatabaseName(value); err != nil {
			fmt.Printf("Invalid database name: %s. Please try again.\n", err)
			continue
		}
		return value
	}
}

func promptPassword(rl *readline.Instance, prompt, defaultValue string) string {
	for {
		value := promptString(rl, prompt, defaultValue)
		if value == "" {
			fmt.Println("Password cannot be empty. Please try again.")
			continue
		}
		// Check password strength
		issues := checkPasswordStrength(value)
		if len(issues) > 0 {
			printWarning("Weak password: %s", strings.Join(issues, ", "))
			if !promptYesNo(rl, "Use this password anyway?", false) {
				continue
			}
		}
		return value
	}
}
