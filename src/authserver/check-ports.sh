#!/bin/bash

# Script to check what's running on ports 9090 and 9091, with optional kill functionality
# Usage: ./check-ports.sh [kill]

PORTS=(9090 9091)

# Function to check processes on ports
check_ports() {
    echo "Checking processes on ports ${PORTS[*]}..."
    echo "========================================="
    
    local found_processes=false
    
    for port in "${PORTS[@]}"; do
        echo
        echo "Port $port:"
        echo "----------"
        
        # Using netstat to find processes
        local netstat_output=$(netstat -tulnp 2>/dev/null | grep ":$port ")
        
        if [ -n "$netstat_output" ]; then
            echo "$netstat_output"
            
            # Extract PIDs from netstat output
            local pids=$(echo "$netstat_output" | awk '{print $7}' | cut -d'/' -f1 | grep -v '^-$' | sort -u)
            
            if [ -n "$pids" ]; then
                echo "Process details:"
                for pid in $pids; do
                    if [ "$pid" != "-" ] && [ -n "$pid" ]; then
                        local process_info=$(ps -p "$pid" -o pid,ppid,cmd --no-headers 2>/dev/null)
                        if [ -n "$process_info" ]; then
                            echo "  PID $pid: $process_info"
                            found_processes=true
                        fi
                    fi
                done
            fi
        else
            # Try lsof as alternative
            local lsof_output=$(lsof -i ":$port" 2>/dev/null)
            
            if [ -n "$lsof_output" ]; then
                echo "$lsof_output"
                found_processes=true
            else
                echo "No processes found on port $port"
            fi
        fi
    done
    
    if [ "$found_processes" = false ]; then
        echo
        echo "No processes found on any of the specified ports."
    fi
}

# Function to kill processes on ports
kill_processes() {
    echo "Killing processes on ports ${PORTS[*]}..."
    echo "=========================================="
    
    for port in "${PORTS[@]}"; do
        echo
        echo "Checking port $port for processes to kill..."
        
        # Get PIDs from netstat
        local pids=$(netstat -tulnp 2>/dev/null | grep ":$port " | awk '{print $7}' | cut -d'/' -f1 | grep -v '^-$' | sort -u)
        
        # Also try lsof if netstat didn't find anything
        if [ -z "$pids" ]; then
            pids=$(lsof -t -i ":$port" 2>/dev/null | sort -u)
        fi
        
        if [ -n "$pids" ]; then
            echo "Found processes on port $port: $pids"
            
            for pid in $pids; do
                if [ "$pid" != "-" ] && [ -n "$pid" ]; then
                    local process_info=$(ps -p "$pid" -o cmd --no-headers 2>/dev/null)
                    if [ -n "$process_info" ]; then
                        echo "Killing PID $pid: $process_info"
                        
                        # Try graceful kill first
                        if kill "$pid" 2>/dev/null; then
                            echo "  Sent SIGTERM to PID $pid"
                            sleep 2
                            
                            # Check if process is still running
                            if kill -0 "$pid" 2>/dev/null; then
                                echo "  Process $pid still running, sending SIGKILL"
                                kill -9 "$pid" 2>/dev/null || echo "  Failed to kill PID $pid"
                            else
                                echo "  Process $pid terminated gracefully"
                            fi
                        else
                            echo "  Failed to send signal to PID $pid (may already be dead)"
                        fi
                    else
                        echo "Process $pid no longer exists"
                    fi
                fi
            done
        else
            echo "No processes found on port $port"
        fi
    done
    
    # Wait a moment for cleanup
    echo
    echo "Waiting 3 seconds for cleanup..."
    sleep 3
    
    # Verify ports are now free
    echo
    echo "Verification - checking ports again:"
    echo "===================================="
    check_ports
}

# Main script logic
case "${1:-}" in
    "kill"|"-k"|"--kill")
        check_ports
        echo
        echo
        kill_processes
        ;;
    "help"|"-h"|"--help")
        echo "Usage: $0 [kill]"
        echo
        echo "Options:"
        echo "  (no args)     Check what processes are using ports 9090 and 9091"
        echo "  kill          Kill processes using ports 9090 and 9091"
        echo "  help          Show this help message"
        echo
        echo "Examples:"
        echo "  $0            # Just check ports"
        echo "  $0 kill       # Check ports and kill processes"
        ;;
    *)
        check_ports
        ;;
esac