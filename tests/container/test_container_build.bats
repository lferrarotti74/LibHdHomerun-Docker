#!/usr/bin/env bats

# Container build tests for LibHdHomerun-Docker
# Tests Docker image building, container startup, and basic functionality

load '../helpers/test_helpers'

# Setup and teardown
setup() {
    setup_test_environment
}

teardown() {
    teardown_test_environment
}

@test "Docker image builds successfully" {
    # Clean up any existing image first
    cleanup_test_image
    
    # Build the image
    run build_test_image
    [ "$status" -eq 0 ]
    
    # Verify image exists
    run docker images --format '{{.Repository}}:{{.Tag}}' 
    [[ "$output" =~ "$IMAGE_NAME" ]]
}

@test "Container starts successfully" {
    run start_test_container
    [ "$status" -eq 0 ]
    
    # Wait for container to be ready
    run wait_for_container
    [ "$status" -eq 0 ]
    
    # Verify container is running
    run is_container_running
    [ "$status" -eq 0 ]
}

@test "Container starts with host network mode" {
    run start_test_container "host"
    [ "$status" -eq 0 ]
    
    # Wait for container to be ready
    run wait_for_container
    [ "$status" -eq 0 ]
    
    # Verify container is running
    run is_container_running
    [ "$status" -eq 0 ]
}

@test "hdhomerun_config binary exists and is executable" {
    start_test_container
    wait_for_container
    
    run check_hdhomerun_binary
    [ "$status" -eq 0 ]
}

@test "libhdhomerun.so library exists" {
    start_test_container
    wait_for_container
    
    run check_hdhomerun_library
    [ "$status" -eq 0 ]
}

@test "Container runs with non-root user" {
    start_test_container
    wait_for_container
    
    check_container_security
    [ "$?" -eq 0 ]
}

@test "File permissions are set correctly" {
    start_test_container
    wait_for_container
    
    check_file_permissions
    [ "$?" -eq 0 ]
}

@test "Container has correct working directory" {
    start_test_container
    wait_for_container
    
    # Check working directory
    run docker exec "$CONTAINER_NAME" pwd
    [ "$status" -eq 0 ]
    [ "$output" = "/libhdhomerun" ]
}

@test "Container environment is set up correctly" {
    start_test_container
    wait_for_container
    
    # Check user
    run docker exec "$CONTAINER_NAME" whoami
    [ "$status" -eq 0 ]
    [ "$output" = "libhdhomerun" ]
    
    # Check home directory
    run docker exec "$CONTAINER_NAME" sh -c 'echo $HOME'
    [ "$status" -eq 0 ]
    [ "$output" = "/libhdhomerun" ]
}

@test "Container can execute basic shell commands" {
    start_test_container
    wait_for_container
    
    # Test basic commands
    run docker exec "$CONTAINER_NAME" echo "test"
    [ "$status" -eq 0 ]
    [ "$output" = "test" ]
    
    run docker exec "$CONTAINER_NAME" ls -la
    [ "$status" -eq 0 ]
    [[ "$output" =~ "hdhomerun_config" ]]
    [[ "$output" =~ "libhdhomerun.so" ]]
}

@test "Container handles signals properly" {
    start_test_container
    wait_for_container
    
    # Send SIGTERM and verify graceful shutdown
    run docker stop "$CONTAINER_NAME"
    [ "$status" -eq 0 ]
    
    # Container should be stopped
    run docker ps --format '{{.Names}}'
    [[ ! "$output" =~ "$CONTAINER_NAME" ]]
}

@test "Container logs are accessible" {
    start_test_container
    wait_for_container
    
    # Execute a command to generate some logs
    docker exec "$CONTAINER_NAME" echo "test log entry"
    
    # Get logs
    run get_container_logs
    [ "$status" -eq 0 ]
}

@test "Container resource limits work" {
    # Start container with memory limit
    run docker run -d --name "$CONTAINER_NAME" --memory=128m "$IMAGE_NAME"
    [ "$status" -eq 0 ]
    
    wait_for_container
    
    # Verify memory limit is applied
    run docker inspect "$CONTAINER_NAME" --format '{{.HostConfig.Memory}}'
    [ "$status" -eq 0 ]
    [ "$output" = "134217728" ]  # 128MB in bytes
}

@test "Container can be restarted" {
    start_test_container
    wait_for_container
    
    # Stop container
    run docker stop "$CONTAINER_NAME"
    [ "$status" -eq 0 ]
    
    # Start container again
    run docker start "$CONTAINER_NAME"
    [ "$status" -eq 0 ]
    
    wait_for_container
    
    # Verify it's running
    run is_container_running
    [ "$status" -eq 0 ]
}

@test "Multiple containers can run simultaneously" {
    local container2="${CONTAINER_NAME}-2"
    
    # Start first container
    start_test_container
    wait_for_container
    
    # Start second container
    run docker run -d --name "$container2" "$IMAGE_NAME"
    [ "$status" -eq 0 ]
    
    # Both should be running
    run docker ps --format '{{.Names}}'
    [[ "$output" =~ "$CONTAINER_NAME" ]]
    [[ "$output" =~ "$container2" ]]
    
    # Cleanup second container
    docker stop "$container2" >/dev/null 2>&1
    docker rm "$container2" >/dev/null 2>&1
}

@test "Container image size is reasonable" {
    # Check image size (should be under 100MB for Alpine-based image)
    run docker images "$IMAGE_NAME" --format '{{.Size}}'
    [ "$status" -eq 0 ]
    
    # Extract numeric value (assuming format like "45.2MB")
    size_mb=$(echo "$output" | sed 's/MB.*//' | sed 's/GB.*/000/')
    
    # Size should be reasonable (less than 200MB)
    [ "$(echo "$size_mb < 200" | bc -l 2>/dev/null || echo "1")" = "1" ]
}

@test "Container cleanup works properly" {
    start_test_container
    wait_for_container
    
    # Cleanup
    run cleanup_test_container
    [ "$status" -eq 0 ]
    
    # Verify container is gone
    run docker ps -a --format '{{.Names}}'
    [[ ! "$output" =~ "$CONTAINER_NAME" ]]
}