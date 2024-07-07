package lib

import (
	"bufio"
	"os"
	"strings"
)

// IsRunningInDocker checks if the application is running in a Docker container.
func IsRunningInDocker() bool {
	// Check for the .dockerenv file
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	// Check for Docker in cgroup
	file, err := os.Open("/proc/self/cgroup")
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "docker") {
			return true
		}
	}

	return false
}
