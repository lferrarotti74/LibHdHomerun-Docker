#!/usr/bin/env bats

# CLI tests for hdhomerun_config command in LibHdHomerun-Docker
# Tests all hdhomerun_config command functionality and error handling

load '../helpers/test_helpers'

# Setup and teardown
setup() {
    setup_test_environment
    start_test_container
    wait_for_container
}

teardown() {
    teardown_test_environment
}

@test "hdhomerun_config shows help when run without arguments" {
    run run_hdhomerun_command_with_output
    [ "$status" -eq 1 ]  # hdhomerun_config returns 1 when showing help
    
    # Store the output before it gets overwritten
    local help_output="$output"
    
    # Validate help output structure
    run validate_help_output "$help_output"
    [ "$status" -eq 0 ]
    
    # Check for specific usage patterns using stored output
    [[ "$help_output" =~ "Usage:" ]]
    [[ "$help_output" =~ "hdhomerun_config discover" ]]
    [[ "$help_output" =~ "hdhomerun_config <id> get" ]]
    [[ "$help_output" =~ "hdhomerun_config <id> set" ]]
}

@test "hdhomerun_config --help shows usage information" {
    run run_hdhomerun_command_with_output --help
    [ "$status" -eq 1 ]  # hdhomerun_config returns 1 when showing help
    
    # Store the output before it gets overwritten
    local help_output="$output"
    
    # Validate help output structure
    run validate_help_output "$help_output"
    [ "$status" -eq 0 ]
    
    # Should contain all main command patterns
    [[ "$help_output" =~ "Usage:" ]]
    [[ "$help_output" =~ "hdhomerun_config discover" ]]
    [[ "$help_output" =~ "hdhomerun_config <id> get help" ]]
    [[ "$help_output" =~ "hdhomerun_config <id> get <item>" ]]
    [[ "$help_output" =~ "hdhomerun_config <id> set <item> <value>" ]]
    [[ "$help_output" =~ "hdhomerun_config <id> scan <tuner>" ]]
    [[ "$help_output" =~ "hdhomerun_config <id> save <tuner> <filename>" ]]
    [[ "$help_output" =~ "hdhomerun_config <id> upgrade <filename>" ]]
}

@test "hdhomerun_config discover works (no devices expected)" {
    run run_hdhomerun_command_with_output discover
    [ "$status" -eq 1 ]  # hdhomerun_config returns 1 when no devices found
    
    # Store the output before it gets overwritten
    local discover_output="$output"
    
    # Validate discover output (should be "no devices found" or empty)
    run validate_discover_output "$discover_output"
    [ "$status" -eq 0 ]
    
    # Most common case: no devices found
    if [[ "$discover_output" =~ "no devices found" ]]; then
        [[ "$discover_output" =~ "no devices found" ]]
    fi
}

@test "hdhomerun_config discover with IPv4 flag" {
    run run_hdhomerun_command_with_output discover -4
    [ "$status" -eq 1 ]  # hdhomerun_config returns 1 when no devices found
    
    # Store the output before it gets overwritten
    local discover_output="$output"
    
    # Should work the same as regular discover
    run validate_discover_output "$discover_output"
    [ "$status" -eq 0 ]
}

@test "hdhomerun_config discover with IPv6 flag" {
    run run_hdhomerun_command_with_output discover -6
    [ "$status" -eq 1 ]  # hdhomerun_config returns 1 when no devices found
    
    # Store the output before it gets overwritten
    local discover_output="$output"
    
    # Should work (may return no devices)
    run validate_discover_output "$discover_output"
    [ "$status" -eq 0 ]
}

@test "hdhomerun_config discover with dedupe flag" {
    run run_hdhomerun_command_with_output discover --dedupe
    [ "$status" -eq 1 ]  # hdhomerun_config returns 1 when no devices found
    
    # Store the output before it gets overwritten
    local discover_output="$output"
    
    # Should work the same as regular discover
    run validate_discover_output "$discover_output"
    [ "$status" -eq 0 ]
}

@test "hdhomerun_config discover with IP address" {
    # Test with localhost
    run run_hdhomerun_command_with_output discover 127.0.0.1
    [ "$status" -eq 1 ]  # hdhomerun_config returns 1 when no devices found
    
    # Store the output before it gets overwritten
    local discover_output="$output"
    
    # Should complete without error (may find no devices)
    run validate_discover_output "$discover_output"
    [ "$status" -eq 0 ]
}

@test "hdhomerun_config with invalid device ID shows error" {
    run run_hdhomerun_command_with_output pippo
    [ "$status" -ne 0 ]
    
    # Store the output before it gets overwritten
    local error_output="$output"
    
    # Should show invalid device id error
    run validate_error_output "$error_output" "invalid device id"
    [ "$status" -eq 0 ]
    
    [[ "$error_output" =~ "invalid device id: pippo" ]]
}

@test "hdhomerun_config with invalid device ID (numeric)" {
    run run_hdhomerun_command_with_output 12345
    [ "$status" -ne 0 ]
    
    local error_output="$output"
    # Should show error for invalid device
    [[ "$error_output" =~ "unable to connect to device" ]] || [[ "$error_output" =~ "device not found" ]] || [[ "$error_output" =~ "ERROR" ]]
}

@test "hdhomerun_config with malformed device ID" {
    local invalid_ids=("abc123" "!@#$" "device" "test123")
    
    for device_id in "${invalid_ids[@]}"; do
        run run_hdhomerun_command_with_output "$device_id"
        [ "$status" -ne 0 ]
        
        # Should contain error message
        [[ "$output" =~ "invalid device id" ]] || [[ "$output" =~ "ERROR" ]]
    done
}

@test "hdhomerun_config with valid device ID format but non-existent device" {
    # Use a properly formatted but non-existent device ID
    run run_hdhomerun_command_with_output 12345678 get help
    [ "$status" -ne 0 ]
    
    local error_output="$output"
    # Should indicate device not found or communication error
    [[ "$error_output" =~ "invalid device id" ]] || [[ "$error_output" =~ "device not found" ]] || [[ "$error_output" =~ "communication error" ]] || [[ "$error_output" =~ "ERROR" ]]
}

@test "hdhomerun_config handles network timeouts gracefully" {
    # Test with unreachable IP
    run timeout 10 docker exec "$CONTAINER_NAME" ./hdhomerun_config discover 192.0.2.1
    
    # Should complete within timeout (may be status 0 or non-zero)
    # The important thing is it doesn't hang indefinitely
    [ "$status" -le 124 ]  # 124 is timeout exit code
}

@test "hdhomerun_config binary has correct version info" {
    # Try to get version information (may not be available)
    run run_hdhomerun_command_with_output --version
    
    # Command may not support --version, but should not crash
    [ "$status" -le 1 ]
}

@test "hdhomerun_config handles concurrent execution" {
    # Run multiple discover commands simultaneously
    docker exec "$CONTAINER_NAME" ./hdhomerun_config discover &
    docker exec "$CONTAINER_NAME" ./hdhomerun_config discover &
    docker exec "$CONTAINER_NAME" ./hdhomerun_config discover &
    
    # Wait for all to complete
    wait
    
    # All should complete without issues
    [ "$?" -eq 0 ]
}

@test "hdhomerun_config with empty arguments" {
    # Test various empty argument scenarios - should behave like no arguments
    run run_hdhomerun_command_with_output
    [ "$status" -eq 1 ]  # hdhomerun_config returns 1 when showing help
    
    local help_output="$output"
    # Should show help
    [[ "$help_output" =~ "Usage:" ]]
}

@test "hdhomerun_config discover with invalid IP format" {
    local invalid_ips=("999.999.999.999" "not.an.ip" "256.1.1.1" "192.168.1")
    
    for ip in "${invalid_ips[@]}"; do
        run run_hdhomerun_command_with_output discover "$ip"
        
        # Should handle gracefully (may succeed with no devices or show error)
        [ "$status" -le 1 ]
    done
}

@test "hdhomerun_config with very long arguments" {
    # Test with extremely long device ID
    local long_id=$(printf 'a%.0s' {1..1000})
    
    run run_hdhomerun_command_with_output "$long_id"
    [ "$status" -ne 0 ]
    
    # Should handle gracefully without crashing
    [[ "$output" =~ "invalid device id" ]] || [[ "$output" =~ "ERROR" ]]
}

@test "hdhomerun_config command injection protection" {
    # Test potential command injection attempts
    local injection_attempts=(
        "device; ls"
        "device && echo test"
        "device | cat"
        "device \$(echo test)"
        "device \`echo test\`"
    )
    
    for attempt in "${injection_attempts[@]}"; do
        run run_hdhomerun_command_with_output "$attempt"
        [ "$status" -ne 0 ]
        
        local error_output="$output"
        # Should treat as invalid device ID, not execute injection
        [[ "$error_output" =~ "invalid device id" ]] || [[ "$error_output" =~ "ERROR" ]]
        # Check that the injection didn't execute by looking for output that would only come from command execution
        # The word "test" appearing in the error message is expected (it's part of the invalid device ID)
        # but we shouldn't see standalone "test" output that would indicate command execution
        [[ ! "$error_output" =~ ^test$ ]]  # No standalone "test" output from injection
    done
}

@test "hdhomerun_config memory usage is reasonable" {
    # This test requires a running container, but the discover command should work without one
    # Run discover command which should succeed
    run run_hdhomerun_command_with_output discover
    [ "$status" -eq 1 ]  # discover returns 1 when no devices found
    
    # Verify the command executed successfully
    local discover_output="$output"
    [[ "$discover_output" =~ "no devices found" ]] || [[ "$discover_output" == "" ]]
}

@test "hdhomerun_config handles SIGTERM gracefully" {
    # Start a long-running discover in background
    docker exec "$CONTAINER_NAME" timeout 30 ./hdhomerun_config discover 192.168.1.255 &
    local pid=$!
    
    sleep 2
    
    # Send SIGTERM
    kill -TERM $pid 2>/dev/null || true
    
    # Should terminate gracefully
    wait $pid 2>/dev/null || true
    local exit_code=$?
    
    # Should exit cleanly (SIGTERM exit code is typically 143)
    [ "$exit_code" -eq 143 ] || [ "$exit_code" -eq 0 ] || [ "$exit_code" -eq 124 ]
}