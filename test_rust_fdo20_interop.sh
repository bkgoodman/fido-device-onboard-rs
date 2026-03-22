#!/bin/bash
#
# Copyright (c) 2026, Dell Technologies, Inc.
# SPDX-License-Identifier: BSD-3-Clause
#
# FDO 2.0 Rust Client Interoperability Test Script
# Tests Rust FDO 2.0 client against Go FDO server
#
# Usage: ./test_rust_fdo20_interop.sh [test_name]
#   test_name: di-fdo20, full-fdo20, delegate, all (default: all)
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
EPHEMERAL_DIR="ephemeral-test-files"
DB_FILE="$EPHEMERAL_DIR/test.db"
CRED_FILE="$EPHEMERAL_DIR/cred.bin"
DI_SIGN_KEY="$EPHEMERAL_DIR/di_sign_key.der"
DI_SIGN_KEY_384="$EPHEMERAL_DIR/di_sign_key_384.der"
DI_HMAC_KEY="$EPHEMERAL_DIR/di_hmac_key.bin"
SERVER_ADDR="127.0.0.1:9999"
SERVER_URL="http://${SERVER_ADDR}"
GO_FDO_DIR="../go-fdo"
SERVER_PID=""

# Cleanup function
cleanup() {
	echo ""
	log_step "Cleaning up..."
	if [ -n "$SERVER_PID" ]; then
		echo "  Stopping server (PID: $SERVER_PID)..."
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	pkill -f "go-build.*server" 2>/dev/null || true
	pkill -f "examples/cmd server" 2>/dev/null || true
	sleep 1
	pkill -9 -f "go-build.*server" 2>/dev/null || true
	pkill -9 -f "examples/cmd server" 2>/dev/null || true
	log_success "Cleanup complete"
}

trap cleanup EXIT

# Logging helpers
log_section() { echo -e "\n${BLUE}========================================${NC}"; echo -e "${BLUE}$1${NC}"; echo -e "${BLUE}========================================${NC}"; }
log_step() { echo -e "${YELLOW}>>> $1${NC}"; }
log_success() { echo -e "${GREEN}✓ $1${NC}"; }
log_error() { echo -e "${RED}✗ $1${NC}"; }
log_info() { echo -e "${CYAN}    $1${NC}"; }

run_cmd() {
	echo -e "${YELLOW}\$ $*${NC}"
	timeout 30 "$@" || { log_error "Command failed (or timed out): $*"; return 1; }
}

# Start Go FDO server
start_go_server() {
	local flags="$1"
	log_step "Starting Go FDO server"
	log_info "Flags: $flags"
	log_info "Address: $SERVER_ADDR"
	log_info "Database: $DB_FILE"

	# Kill anything lingering on port 9999
	kill_port_9999

	# Wait for port to be available
	log_info "Waiting for port 9999 to be available..."
	for i in $(seq 1 5); do
		if ! nc -z 127.0.0.1 9999 2>/dev/null; then break; fi
		sleep 1
	done

	log_info "Starting server process..."
	# shellcheck disable=SC2086
	(cd "$GO_FDO_DIR/examples" && go run ./cmd server -http "$SERVER_ADDR" -ext-http "$SERVER_ADDR" -db "../../fido-device-onboard-rs/$DB_FILE" $flags >/tmp/fdo_server.log 2>&1) &
	SERVER_PID=$!

	log_info "Waiting for server to start (PID: $SERVER_PID)..."
	local retries=15
	while [ $retries -gt 0 ]; do
		if grep -q "Listening" /tmp/fdo_server.log 2>/dev/null; then
			sleep 0.5
			if nc -z 127.0.0.1 9999 2>/dev/null || (echo >/dev/tcp/127.0.0.1/9999) 2>/dev/null; then
				log_success "Server started and listening on $SERVER_ADDR"
				return 0
			fi
		fi
		if ! kill -0 "$SERVER_PID" 2>/dev/null; then
			log_error "Server process died"
			cat /tmp/fdo_server.log 2>/dev/null || true
			return 1
		fi
		sleep 1
		retries=$((retries - 1))
	done
	log_error "Server failed to start within timeout"
	cat /tmp/fdo_server.log 2>/dev/null || true
	return 1
}

# Kill anything on port 9999
kill_port_9999() {
	local pids
	pids=$(lsof -ti :9999 2>/dev/null) || true
	if [ -n "$pids" ]; then
		echo "  Killing PIDs on port 9999: $pids"
		kill -9 $pids 2>/dev/null || true
		sleep 1
	fi
}

stop_server() {
	if [ -n "$SERVER_PID" ]; then
		log_step "Stopping server (PID: $SERVER_PID)"
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
		SERVER_PID=""
	fi
	kill_port_9999
	log_success "Server stopped"
}

# Build Rust manufacturing client and onboarding client
build_rust_client() {
	log_section "Building Rust Clients"
	log_info "Building release binaries..."
	run_cmd cargo build --release -p fdo-manufacturing-client -p fdo-client-linuxapp
	log_success "Build complete"
}

# Generate DI keys
generate_di_keys() {
	log_step "Generating DI keys"
	mkdir -p "$EPHEMERAL_DIR"

	log_info "Generating ECDSA P-256 signing key..."
	openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null | \
		openssl pkcs8 -topk8 -nocrypt -outform DER -out "$DI_SIGN_KEY" 2>/dev/null

	log_info "Generating ECDSA P-384 signing key..."
	openssl ecparam -name secp384r1 -genkey -noout 2>/dev/null | \
		openssl pkcs8 -topk8 -nocrypt -outform DER -out "$DI_SIGN_KEY_384" 2>/dev/null

	log_info "Generating HMAC key (256-bit random)..."
	openssl rand -out "$DI_HMAC_KEY" 32

	log_success "DI keys generated"
}

# ============================================================
# Test: DI with FDO 2.0
# ============================================================
test_di_fdo20() {
	log_section "TEST: FDO 2.0 Device Initialization (DI)"

	rm -f "$DB_FILE" "$CRED_FILE"
	generate_di_keys
	start_go_server "-reuse-cred" || return 1

	log_step "Running DI with FDO 2.0"
	DEVICE_CREDENTIAL_FILENAME="$CRED_FILE" \
	DI_SIGN_KEY_PATH="$DI_SIGN_KEY" \
	DI_HMAC_KEY_PATH="$DI_HMAC_KEY" \
	MANUFACTURING_INFO="test-device-fdo20" \
	run_cmd ./target/release/fdo-manufacturing-client plain-di \
		--manufacturing-server-url "$SERVER_URL" \
		--mfg-string-type SerialNumber \
		--key-ref filesystem \
		--fdo-version 200 || return 1

	log_info "Checking credential file..."
	if [ -f "$CRED_FILE" ]; then
		log_success "Credential created: $(ls -lh "$CRED_FILE" | awk '{print $5}')"
	else
		log_error "Credential not found at $CRED_FILE"
		return 1
	fi

	stop_server
	log_success "FDO 2.0 DI test PASSED"
}

# ============================================================
# Test: Full FDO 2.0 flow (DI + TO1 + TO2) with Rust client
# ============================================================
test_full_fdo20() {
	log_section "TEST: Full FDO 2.0 Flow (DI + TO1 + TO2)"
	log_info "Rust client performs DI, TO1, and TO2 against Go server"

	rm -f "$DB_FILE" "$CRED_FILE" /tmp/fdo_onboard_marker_test
	generate_di_keys
	start_go_server "-reuse-cred" || return 1

	log_step "Step 1: DI with FDO 2.0"
	DEVICE_CREDENTIAL_FILENAME="$CRED_FILE" \
	DI_SIGN_KEY_PATH="$DI_SIGN_KEY" \
	DI_HMAC_KEY_PATH="$DI_HMAC_KEY" \
	MANUFACTURING_INFO="test-full-fdo20" \
	run_cmd ./target/release/fdo-manufacturing-client plain-di \
		--manufacturing-server-url "$SERVER_URL" \
		--mfg-string-type SerialNumber \
		--key-ref filesystem \
		--fdo-version 200 || return 1
	log_success "DI completed"

	log_step "Step 2: TO1 + TO2 with Rust client"
	DEVICE_CREDENTIAL="$CRED_FILE" \
	DEVICE_ONBOARDING_EXECUTED_MARKER_FILE_PATH=/tmp/fdo_onboard_marker_test \
	ALLOW_NONINTEROPERABLE_KDF=1 \
	run_cmd ./target/release/fdo-client-linuxapp || return 1
	log_success "TO1 + TO2 completed"

	stop_server
	log_success "Full FDO 2.0 flow test PASSED"
}

# ============================================================
# Test: Delegate certificate support
# ============================================================
test_delegate() {
	log_section "TEST: Delegate Certificate Support"
	log_info "Tests TO2 with delegate-signed ProveOVHdr20"

	rm -f "$DB_FILE" "$CRED_FILE" /tmp/fdo_onboard_marker_delegate
	generate_di_keys

	log_step "Step 1: Initialize server with owner certs"
	(cd "$GO_FDO_DIR/examples" && go run ./cmd server -http "$SERVER_ADDR" -ext-http "$SERVER_ADDR" -db "../../fido-device-onboard-rs/$DB_FILE" -owner-certs -initOnly) 2>&1 || true

	log_step "Step 2: Create delegate chain"
	(cd "$GO_FDO_DIR/examples" && go run ./cmd delegate -db "../../fido-device-onboard-rs/$DB_FILE" create myDelegate onboard,redirect SECP384R1 ec384 ec384) 2>&1 || return 1
	log_success "Delegate chain created"

	log_step "Step 3: Start server with delegate"
	start_go_server "-reuse-cred -owner-certs -onboardDelegate myDelegate" || return 1

	log_step "Step 4: DI with P-384 key (matches delegate chain)"
	DEVICE_CREDENTIAL_FILENAME="$CRED_FILE" \
	DI_SIGN_KEY_PATH="$DI_SIGN_KEY_384" \
	DI_HMAC_KEY_PATH="$DI_HMAC_KEY" \
	MANUFACTURING_INFO="test-delegate" \
	run_cmd ./target/release/fdo-manufacturing-client plain-di \
		--manufacturing-server-url "$SERVER_URL" \
		--mfg-string-type SerialNumber \
		--key-ref filesystem \
		--fdo-version 200 || return 1
	log_success "DI completed"

	log_step "Step 5: TO1 + TO2 with delegate"
	DEVICE_CREDENTIAL="$CRED_FILE" \
	DEVICE_ONBOARDING_EXECUTED_MARKER_FILE_PATH=/tmp/fdo_onboard_marker_delegate \
	ALLOW_NONINTEROPERABLE_KDF=1 \
	RUST_LOG=info \
	run_cmd ./target/release/fdo-client-linuxapp || return 1
	log_success "TO1 + TO2 with delegate completed"

	stop_server
	log_success "Delegate certificate test PASSED"
}

# ============================================================
# Test: BMO (Bare Metal Onboarding) image transfer
# ============================================================
test_bmo() {
	log_section "TEST: BMO Image Transfer"
	log_info "Tests fdo.bmo FSIM: inline image delivery + BIOS parameters"

	rm -f "$DB_FILE" "$CRED_FILE" /tmp/fdo_onboard_marker_bmo
	rm -rf /tmp/fdo-bmo
	generate_di_keys

	log_step "Step 1: Create test image file"
	mkdir -p "$EPHEMERAL_DIR"
	dd if=/dev/urandom of="$EPHEMERAL_DIR/test-image.bin" bs=1024 count=64 2>/dev/null
	BMO_IMAGE_PATH="$(cd "$EPHEMERAL_DIR" && pwd)/test-image.bin"
	log_success "Test image created (64 KB): $BMO_IMAGE_PATH"

	log_step "Step 2: Start server with BMO"
	start_go_server "-reuse-cred -bmo-file $BMO_IMAGE_PATH -bmo-type application/x-iso9660-image -bmo-set secure-boot=true -bmo-set bios-password=TestKey123" || return 1

	log_step "Step 3: DI with FDO 2.0"
	DEVICE_CREDENTIAL_FILENAME="$CRED_FILE" \
	DI_SIGN_KEY_PATH="$DI_SIGN_KEY" \
	DI_HMAC_KEY_PATH="$DI_HMAC_KEY" \
	MANUFACTURING_INFO="test-bmo" \
	run_cmd ./target/release/fdo-manufacturing-client plain-di \
		--manufacturing-server-url "$SERVER_URL" \
		--mfg-string-type SerialNumber \
		--key-ref filesystem \
		--fdo-version 200 || return 1
	log_success "DI completed"

	log_step "Step 4: TO1 + TO2 with BMO"
	BMO_OUTPUT_DIR=/tmp/fdo-bmo \
	DEVICE_CREDENTIAL="$CRED_FILE" \
	DEVICE_ONBOARDING_EXECUTED_MARKER_FILE_PATH=/tmp/fdo_onboard_marker_bmo \
	ALLOW_NONINTEROPERABLE_KDF=1 \
	RUST_LOG=info \
	run_cmd ./target/release/fdo-client-linuxapp || return 1
	log_success "TO1 + TO2 with BMO completed"

	log_step "Step 5: Verify BMO output"
	if [ -f /tmp/fdo-bmo/test-image.bin ]; then
		local orig_size recv_size
		orig_size=$(stat --format='%s' "$EPHEMERAL_DIR/test-image.bin")
		recv_size=$(stat --format='%s' /tmp/fdo-bmo/test-image.bin)
		log_success "Image received: $recv_size bytes (original: $orig_size bytes)"
		if [ "$orig_size" = "$recv_size" ]; then
			if cmp -s "$EPHEMERAL_DIR/test-image.bin" /tmp/fdo-bmo/test-image.bin; then
				log_success "Image content matches original"
			else
				log_error "Image content MISMATCH"
				return 1
			fi
		else
			log_error "Image size mismatch: expected $orig_size, got $recv_size"
			return 1
		fi
	else
		log_error "BMO image not found at /tmp/fdo-bmo/test-image.bin"
		ls -la /tmp/fdo-bmo/ 2>/dev/null || true
		return 1
	fi

	if [ -f /tmp/fdo-bmo/bios_params ]; then
		log_success "BIOS parameters received:"
		cat /tmp/fdo-bmo/bios_params
	else
		log_info "No BIOS parameters file (may not be sent with -bmo-file mode)"
	fi

	stop_server
	log_success "BMO test PASSED"
}

# ============================================================
# Main test runner
# ============================================================
main() {
	local test_name="${1:-all}"

	echo ""
	echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
	echo -e "${CYAN}║  FDO 2.0 Rust Client Interoperability Test Suite             ║${NC}"
	echo -e "${CYAN}║  Testing Rust FDO 2.0 client against Go FDO server           ║${NC}"
	echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
	echo ""

	if [ ! -d "$GO_FDO_DIR" ]; then
		log_error "Go FDO directory not found at $GO_FDO_DIR"
		exit 1
	fi
	log_success "Found Go FDO at $GO_FDO_DIR"

	build_rust_client

	case "$test_name" in
		di-fdo20)
			test_di_fdo20
			;;
		full-fdo20)
			test_full_fdo20
			;;
		delegate)
			test_delegate
			;;
		bmo)
			test_bmo
			;;
		all)
			local failed=0
			test_di_fdo20 || failed=1
			test_full_fdo20 || failed=1
			test_delegate || failed=1
			test_bmo || failed=1

			echo ""
			log_section "Test Suite Summary"
			if [ $failed -eq 0 ]; then
				log_success "All tests PASSED"
			else
				log_error "Some tests FAILED"
				exit 1
			fi
			;;
		*)
			echo "Usage: $0 [di-fdo20|full-fdo20|delegate|bmo|all]"
			exit 1
			;;
	esac
}

main "$@"
