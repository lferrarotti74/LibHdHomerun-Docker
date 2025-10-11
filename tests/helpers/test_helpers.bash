#!/usr/bin/env bash

# Test helpers for LibHdHomerun-Docker BATS testing framework
# This file contains reusable helper functions for testing the LibHdHomerun-Docker container

# Global variables
export CONTAINER_NAME="libhdhomerun-test-$$"
export IMAGE_NAME="libhdhomerun-docker:test"
export CONTAINER_TIMEOUT=30

# Color codes for output
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[1;33m'
export NC='\033[0m' # No Color

# Print colored output
print_success() {
    echo -e "${GREEN}✅ $1${NC}" >&3
}

print_error() {
    echo -e "${RED}❌ $1${NC}" >&3
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}" >&3
}

print_info() {
    echo -e "ℹ️  $1" >&3
}

# Build the test image (only if it doesn't exist)
build_test_image() {
    # Check if image already exists
    if docker images --format '{{.Repository}}:{{.Tag}}' | grep -q "^${IMAGE_NAME}$"; then
        print_success "Test image already exists: $IMAGE_NAME (skipping build)"
        return 0
    fi
    
    print_info "Building test image: $IMAGE_NAME"
    docker build -t "$IMAGE_NAME" . >&3 2>&3
    local exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        print_success "Test image built successfully: $IMAGE_NAME"
    else
        print_error "Failed to build test image: $IMAGE_NAME"
    fi
    
    return $exit_code
}

# Start a container for testing
start_test_container() {
    local network_mode="${1:-bridge}"
    
    # Ensure any existing container is cleaned up first
    cleanup_test_container
    
    print_info "Starting test container: $CONTAINER_NAME with network mode: $network_mode"
    
    if [ "$network_mode" = "host" ]; then
        docker run -d --name "$CONTAINER_NAME" --network host "$IMAGE_NAME" >&3 2>&3
    else
        docker run -d --name "$CONTAINER_NAME" "$IMAGE_NAME" >&3 2>&3
    fi
    
    local exit_code=$?
    if [ $exit_code -eq 0 ]; then
        # Wait for container to be ready
        sleep 2
        print_success "Container started successfully"
    else
        print_error "Failed to start container"
    fi
    
    return $exit_code
}

# Stop and remove test container
cleanup_test_container() {
    if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        print_info "Cleaning up test container: $CONTAINER_NAME"
        docker stop "$CONTAINER_NAME" >&3 2>&3
        docker rm "$CONTAINER_NAME" >&3 2>&3
        print_success "Container cleaned up"
    fi
}

# Remove test image (with safety check)
cleanup_test_image() {
    # Only cleanup if explicitly requested via environment variable
    if [ "$CLEANUP_TEST_IMAGE" = "true" ]; then
        if docker images --format '{{.Repository}}:{{.Tag}}' | grep -q "^${IMAGE_NAME}$"; then
            print_info "Cleaning up test image: $IMAGE_NAME"
            docker rmi "$IMAGE_NAME" >&3 2>&3
            print_success "Image cleaned up"
        fi
    else
        print_info "Preserving test image: $IMAGE_NAME (set CLEANUP_TEST_IMAGE=true to force cleanup)"
    fi
}

# Execute hdhomerun_config command in container
run_hdhomerun_command() {
    local cmd_args="$*"
    print_info "Running: hdhomerun_config $cmd_args"
    docker exec "$CONTAINER_NAME" ./hdhomerun_config $cmd_args
}

# Execute hdhomerun_config command and capture output
run_hdhomerun_command_with_output() {
    local cmd_args="$*"
    print_info "Running with output capture: hdhomerun_config $cmd_args"
    docker exec "$CONTAINER_NAME" ./hdhomerun_config $cmd_args 2>&1
}

# Execute shell command in container
run_shell_command() {
    local cmd="$*"
    print_info "Running shell command: $cmd"
    docker exec "$CONTAINER_NAME" sh -c "$cmd"
}

# Check if container is running
is_container_running() {
    docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"
}

# Check if container exists (running or stopped)
container_exists() {
    docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"
}

# Wait for container to be ready
wait_for_container() {
    local timeout="${1:-$CONTAINER_TIMEOUT}"
    local count=0
    
    print_info "Waiting for container to be ready (timeout: ${timeout}s)"
    
    while [ $count -lt $timeout ]; do
        if is_container_running; then
            # Test if we can execute commands
            if docker exec "$CONTAINER_NAME" echo "test" >/dev/null 2>&1; then
                print_success "Container is ready"
                return 0
            fi
        fi
        sleep 1
        count=$((count + 1))
    done
    
    print_error "Container failed to become ready within ${timeout} seconds"
    return 1
}

# Get container logs
get_container_logs() {
    if container_exists; then
        print_info "Getting container logs"
        docker logs "$CONTAINER_NAME" 2>&1
    else
        print_error "Container does not exist"
        return 1
    fi
}

# Check if hdhomerun_config binary exists and is executable
check_hdhomerun_binary() {
    print_info "Checking hdhomerun_config binary"
    docker exec "$CONTAINER_NAME" test -x ./hdhomerun_config
}

# Check if libhdhomerun.so library exists
check_hdhomerun_library() {
    print_info "Checking libhdhomerun.so library"
    docker exec "$CONTAINER_NAME" test -f ./libhdhomerun.so
}

# Validate hdhomerun_config help output
validate_help_output() {
    local output="$1"
    
    # Check for expected usage patterns
    if echo "$output" | grep -q "Usage:"; then
        if echo "$output" | grep -q "hdhomerun_config discover"; then
            if echo "$output" | grep -q "hdhomerun_config <id> get"; then
                return 0
            fi
        fi
    fi
    
    return 1
}

# Validate discover command output
validate_discover_output() {
    local output="$1"
    
    # Valid outputs: "no devices found" or device information
    if echo "$output" | grep -q "no devices found"; then
        return 0
    elif echo "$output" | grep -q "device"; then
        return 0
    elif echo "$output" | grep -q "hdhomerun device"; then
        return 0
    else
        # Empty output is also valid when no devices are present
        if [ -z "$output" ] || echo "$output" | grep -q "^[[:space:]]*$"; then
            return 0
        fi
    fi
    
    return 1
}

# Validate error output for invalid commands
validate_error_output() {
    local output="$1"
    local expected_error="$2"
    
    if echo "$output" | grep -q "$expected_error"; then
        return 0
    fi
    
    return 1
}

# Test network connectivity within container
test_container_network() {
    print_info "Testing container network connectivity"
    # Test basic network functionality
    docker exec "$CONTAINER_NAME" sh -c "ping -c 1 8.8.8.8 >/dev/null 2>&1"
}

# Get container information
get_container_info() {
    if container_exists; then
        print_info "Container information:"
        docker inspect "$CONTAINER_NAME" --format '{{.State.Status}}' 2>/dev/null
    fi
}

# Setup function - called before each test
setup_test_environment() {
    # Ensure clean state
    cleanup_test_container
    
    # Build image if it doesn't exist
    if ! docker images --format '{{.Repository}}:{{.Tag}}' | grep -q "^${IMAGE_NAME}$"; then
        build_test_image || return 1
    fi
    
    return 0
}

# Teardown function - called after each test
teardown_test_environment() {
    cleanup_test_container
}

# Complete cleanup - removes everything
complete_cleanup() {
    cleanup_test_container
    cleanup_test_image
}

# Validate container security settings
check_container_security() {
    print_info "Checking container security settings"
    
    # Check if running as non-root user
    local user_id
    user_id=$(docker exec "$CONTAINER_NAME" id -u 2>/dev/null)
    
    if [ "$user_id" = "1001" ]; then
        print_success "Container running as non-root user (UID: $user_id)"
        return 0
    else
        print_error "Container not running as expected non-root user (UID: $user_id)"
        return 1
    fi
}

# Run hdhomerun_config command with output capture
run_hdhomerun_command_with_output() {
    local args="$*"
    print_info "Running with output capture: hdhomerun_config $args"
    
    if [ -z "$args" ]; then
        # No arguments - show help
        docker exec "$CONTAINER_NAME" ./hdhomerun_config
    else
        # With arguments
        docker exec "$CONTAINER_NAME" ./hdhomerun_config "$@"
    fi
}

# Check file permissions
check_file_permissions() {
    print_info "Checking file permissions"
    
    # Check hdhomerun_config permissions (should be 555)
    local binary_perms
    binary_perms=$(docker exec "$CONTAINER_NAME" stat -c "%a" ./hdhomerun_config 2>/dev/null)
    
    if [ "$binary_perms" = "555" ]; then
        print_success "Binary has correct permissions (555)"
    else
        print_error "Binary has incorrect permissions ($binary_perms, expected 555)"
        return 1
    fi
    
    # Check library permissions (should be 444)
    local lib_perms
    lib_perms=$(docker exec "$CONTAINER_NAME" stat -c "%a" ./libhdhomerun.so 2>/dev/null)
    
    if [ "$lib_perms" = "444" ]; then
        print_success "Library has correct permissions (444)"
        return 0
    else
        print_error "Library has incorrect permissions ($lib_perms, expected 444)"
        return 1
    fi
}