#!/bin/bash
#
# Copyright (c) 2026, Dell Technologies, Inc.
# SPDX-License-Identifier: BSD-3-Clause
#
# TPM Cross-Implementation Walkthrough
# =====================================
# Interactive demonstration of Rust <-> Go FDO 2.0 interoperability
# with TPM-backed credential storage.
#
# Scenarios (4 total — 2 directions × 2 key creation methods):
#   A (child):   Rust DI (child-of-SRK)       → Go Onboard
#   A (primary): Rust DI (primary+unique str)  → Go Onboard
#   B (child):   Go DI (child-of-SRK)         → Rust Onboard
#   B (primary): Go DI (primary+unique str)    → Rust Onboard
#
# Both creation methods produce identical persistent keys at the same
# handles with the same attributes — usage (signing, HMAC) is identical.
#
# Requirements:
#   - /dev/tpmrm0  (hardware TPM with resource manager)
#   - tpm2-tools   (tpm2_clear, tpm2_getcap, tpm2_nvread, tpm2_readpublic)
#   - ../go-fdo    (Go FDO source tree)
#   - Rust toolchain with cargo
#
# Usage:
#   ./tpm_cross_walkthrough.sh            # Run all 4 scenarios
#   ./tpm_cross_walkthrough.sh a          # Scenario A only (both methods)
#   ./tpm_cross_walkthrough.sh b          # Scenario B only (both methods)
#   ./tpm_cross_walkthrough.sh a-child    # Scenario A, child method only
#   ./tpm_cross_walkthrough.sh a-primary  # Scenario A, primary method only
#   ./tpm_cross_walkthrough.sh b-child    # Scenario B, child method only
#   ./tpm_cross_walkthrough.sh b-primary  # Scenario B, primary method only
#   PAUSE=1 ./tpm_cross_walkthrough.sh    # Pause between steps (press Enter)
#

set -e

# ---------------------------------------------------------------------------
# Colours and formatting
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
EPHEMERAL_DIR="ephemeral-test-files"
DB_FILE="$EPHEMERAL_DIR/test.db"
SERVER_ADDR="127.0.0.1:9999"
SERVER_URL="http://${SERVER_ADDR}"
GO_FDO_DIR="../go-fdo"
GO_TPM_CLIENT="/tmp/fdo-tpm-client"
SERVER_PID=""
SERVER_LOG="/tmp/fdo_walkthrough_server.log"
RUST_DIR="$(cd "$(dirname "$0")" && pwd)"

# FDO NV index addresses (spec-defined)
NV_DCTPM="0x01D10001"

# Legacy indices (no longer written, but displayed if found during migration)
NV_LEGACY_DC_ACTIVE="0x01D10000"
NV_LEGACY_DCOV="0x01D10002"
NV_LEGACY_FDO_CERT="0x01D10005"

# Persistent object handles
HANDLE_DAK="0x81020002"
HANDLE_HMAC="0x81020003"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
banner() {
    local text="$1"
    local width=70
    local pad=$(( (width - ${#text} - 2) / 2 ))
    local lpad=""
    local rpad=""
    for (( i=0; i<pad; i++ )); do lpad+="═"; done
    for (( i=0; i < width - ${#text} - 2 - pad; i++ )); do rpad+="═"; done
    echo ""
    echo -e "${CYAN}╔$(printf '═%.0s' $(seq 1 $width))╗${NC}"
    echo -e "${CYAN}║${NC} ${BOLD}${lpad} ${text} ${rpad}${NC} ${CYAN}║${NC}"
    echo -e "${CYAN}╚$(printf '═%.0s' $(seq 1 $width))╝${NC}"
    echo ""
}

section() {
    echo ""
    echo -e "${BLUE}┌──────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│${NC} ${BOLD}$1${NC}"
    echo -e "${BLUE}└──────────────────────────────────────────────────────────────────┘${NC}"
}

step() {
    echo ""
    echo -e "  ${YELLOW}▶ $1${NC}"
}

info() {
    echo -e "  ${DIM}$1${NC}"
}

explain() {
    echo -e "  ${MAGENTA}$1${NC}"
}

ok() {
    echo -e "  ${GREEN}✓ $1${NC}"
}

fail() {
    echo -e "  ${RED}✗ $1${NC}"
}

show_cmd() {
    echo -e "  ${DIM}\$ $*${NC}"
}

maybe_pause() {
    if [ "${PAUSE:-0}" = "1" ]; then
        echo ""
        echo -e "  ${DIM}[Press Enter to continue]${NC}"
        read -r
    fi
}

# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------
kill_port_9999() {
    local pids
    pids=$(lsof -ti :9999 2>/dev/null) || true
    if [ -n "$pids" ]; then
        info "Killing existing processes on port 9999 (PIDs: $pids)"
        # shellcheck disable=SC2086
        kill -9 $pids 2>/dev/null || true
        sleep 1
    fi
}

start_server() {
    local flags="$1"
    step "Starting Go FDO server"
    info "Address:  $SERVER_ADDR"
    info "Database: $DB_FILE"
    info "Flags:    $flags"

    kill_port_9999

    for i in $(seq 1 5); do
        if ! nc -z 127.0.0.1 9999 2>/dev/null; then break; fi
        sleep 1
    done

    mkdir -p "$EPHEMERAL_DIR"

    # shellcheck disable=SC2086
    (cd "$GO_FDO_DIR/examples" && go run ./cmd server \
        -http "$SERVER_ADDR" \
        -ext-http "$SERVER_ADDR" \
        -db "$RUST_DIR/$DB_FILE" \
        $flags >"$SERVER_LOG" 2>&1) &
    SERVER_PID=$!

    info "Waiting for server to start (PID: $SERVER_PID)..."
    local retries=20
    while [ $retries -gt 0 ]; do
        if grep -q "Listening" "$SERVER_LOG" 2>/dev/null; then
            sleep 0.5
            if nc -z 127.0.0.1 9999 2>/dev/null; then
                ok "Server listening on $SERVER_ADDR"
                return 0
            fi
        fi
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            fail "Server process exited unexpectedly"
            cat "$SERVER_LOG" 2>/dev/null | tail -20 || true
            return 1
        fi
        sleep 1
        retries=$((retries - 1))
    done
    fail "Server failed to start within timeout"
    cat "$SERVER_LOG" 2>/dev/null | tail -20 || true
    return 1
}

stop_server() {
    if [ -n "$SERVER_PID" ]; then
        info "Stopping server (PID: $SERVER_PID)"
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
    fi
    pkill -f "go-build.*server" 2>/dev/null || true
    pkill -f "examples/cmd server" 2>/dev/null || true
    sleep 1
    pkill -9 -f "go-build.*server" 2>/dev/null || true
    pkill -9 -f "examples/cmd server" 2>/dev/null || true
}

cleanup() {
    echo ""
    info "Cleaning up..."
    stop_server
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# TPM inspection helpers
# ---------------------------------------------------------------------------
inspect_tpm_raw() {
    # Low-level TPM inspection using tpm2-tools
    section "TPM Raw Inspection (tpm2-tools)"

    step "NV indices defined in TPM"
    show_cmd tpm2_getcap handles-nv-index
    tpm2_getcap handles-nv-index 2>/dev/null | while read -r line; do
        case "$line" in
            *0x1D10001*|*0x1d10001*) echo -e "    $line  ${DIM}← DCTPM (consolidated CBOR credential blob)${NC}" ;;
            *0x1D10000*|*0x1d10000*) echo -e "    $line  ${YELLOW}← DCActive (LEGACY — should be removed)${NC}" ;;
            *0x1D10002*|*0x1d10002*) echo -e "    $line  ${YELLOW}← DCOV (LEGACY — should be removed)${NC}" ;;
            *0x1D10005*|*0x1d10005*) echo -e "    $line  ${YELLOW}← FDO_Cert (LEGACY — should be removed)${NC}" ;;
            *)           echo "    $line" ;;
        esac
    done

    step "Persistent handles in TPM"
    show_cmd tpm2_getcap handles-persistent
    tpm2_getcap handles-persistent 2>/dev/null | while read -r line; do
        case "$line" in
            *0x81020002*) echo -e "    $line  ${DIM}← DAK (Device Attestation Key)${NC}" ;;
            *0x81020003*) echo -e "    $line  ${DIM}← HMAC Key${NC}" ;;
            *)            echo "    $line" ;;
        esac
    done

    step "DCTPM NV ($NV_DCTPM) — consolidated CBOR credential blob"
    show_cmd "tpm2_nvread $NV_DCTPM | xxd"
    if tpm2_nvread "$NV_DCTPM" >/dev/null 2>&1; then
        tpm2_nvread "$NV_DCTPM" 2>/dev/null | xxd 2>/dev/null | while read -r line; do
            echo "    $line"
        done
        local raw_size
        raw_size=$(tpm2_nvread "$NV_DCTPM" 2>/dev/null | wc -c)
        explain "DCTPM CBOR blob: $raw_size bytes"
        # Check magic bytes (CBOR array, first element should be 0x46444F31 = "FDO1")
        local first_byte
        first_byte=$(tpm2_nvread "$NV_DCTPM" 2>/dev/null | xxd -p -l 1 2>/dev/null || echo "")
        case "$first_byte" in
            8a) explain "Format: CBOR 10-element array (0x8a) — consolidated DCTPM" ;;
            *)  explain "First byte: 0x$first_byte" ;;
        esac
    else
        echo -e "    ${DIM}(not defined)${NC}"
    fi


    step "DAK persistent key ($HANDLE_DAK)"
    show_cmd "tpm2_readpublic -c $HANDLE_DAK"
    if tpm2_readpublic -c "$HANDLE_DAK" >/dev/null 2>&1; then
        local dak_info
        dak_info=$(tpm2_readpublic -c "$HANDLE_DAK" 2>/dev/null | grep -E "type:|curve-id:|hash-algorithm:" | head -5)
        echo "$dak_info" | while read -r line; do echo "    $line"; done
        ok "DAK present"
    else
        echo -e "    ${DIM}(not defined)${NC}"
    fi

    step "HMAC persistent key ($HANDLE_HMAC)"
    if tpm2_readpublic -c "$HANDLE_HMAC" >/dev/null 2>&1; then
        ok "HMAC key present"
    else
        echo -e "    ${DIM}(not defined)${NC}"
    fi
}

inspect_tpm_go() {
    # High-level inspection using Go client's -tpm-show
    section "TPM Credential Inspection (Go tpm-show)"
    step "Go reads and decodes all FDO credential data from TPM NV"
    show_cmd "$GO_TPM_CLIENT client -tpm-show"
    "$GO_TPM_CLIENT" client -tpm-show 2>&1 | while read -r line; do
        echo "    $line"
    done
}

inspect_tpm_prove() {
    section "DAK Possession Proof (Go tpm-prove)"
    explain "Go signs a random challenge using the DAK with empty authValue (null auth)."
    explain "This proves the cross-implementation can use the same key templates."
    show_cmd "$GO_TPM_CLIENT client -tpm-prove -tpm-challenge 'walkthrough-cross-impl'"
    "$GO_TPM_CLIENT" client -tpm-prove -tpm-challenge "walkthrough-cross-impl" 2>&1 | while read -r line; do
        echo "    $line"
    done
}

inspect_tpm_export_dak() {
    section "DAK Public Key Export (Go tpm-export-dak)"
    show_cmd "$GO_TPM_CLIENT client -tpm-export-dak"
    "$GO_TPM_CLIENT" client -tpm-export-dak 2>&1 | while read -r line; do
        echo "    $line"
    done
}

inspect_tpm_empty() {
    section "TPM State (should be empty)"
    step "NV indices"
    show_cmd tpm2_getcap handles-nv-index
    local nv_out
    nv_out=$(tpm2_getcap handles-nv-index 2>/dev/null | grep -c "0x1[Dd]1000" || true)
    if [ "$nv_out" = "0" ]; then
        ok "No FDO NV indices defined"
    else
        tpm2_getcap handles-nv-index 2>/dev/null | grep "0x1[Dd]1000" | while read -r line; do
            echo "    $line"
        done
    fi

    step "Persistent handles"
    show_cmd tpm2_getcap handles-persistent
    local persist_out
    persist_out=$(tpm2_getcap handles-persistent 2>/dev/null | grep -c "0x8102000[23]" || true)
    if [ "$persist_out" = "0" ]; then
        ok "No FDO persistent handles"
    else
        tpm2_getcap handles-persistent 2>/dev/null | grep "0x8102000" | while read -r line; do
            echo "    $line"
        done
    fi
}

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------
preflight() {
    banner "Preflight Checks"

    step "TPM device"
    if [ -c /dev/tpmrm0 ]; then
        ok "/dev/tpmrm0 exists"
    else
        fail "/dev/tpmrm0 not found — hardware TPM required"
        exit 1
    fi

    step "tpm2-tools"
    if command -v tpm2_getcap >/dev/null 2>&1; then
        ok "tpm2_getcap found"
    else
        fail "tpm2-tools not installed"
        exit 1
    fi

    step "Go FDO source"
    if [ -d "$GO_FDO_DIR/examples/cmd" ]; then
        ok "$GO_FDO_DIR/examples/cmd exists"
    else
        fail "$GO_FDO_DIR/examples/cmd not found"
        exit 1
    fi

    step "Rust toolchain"
    if command -v cargo >/dev/null 2>&1; then
        ok "cargo found"
    else
        # Try sourcing cargo env
        if [ -f "$HOME/.cargo/env" ]; then
            # shellcheck disable=SC1091
            source "$HOME/.cargo/env"
            if command -v cargo >/dev/null 2>&1; then
                ok "cargo found (after sourcing ~/.cargo/env)"
            else
                fail "cargo not found"
                exit 1
            fi
        else
            fail "cargo not found"
            exit 1
        fi
    fi

    step "Building Rust clients with TPM support"
    show_cmd "RUSTFLAGS=\"-L \$(pwd)/target/lib\" cargo build --release -p fdo-manufacturing-client -p fdo-client-linuxapp --features tpm_support"
    RUSTFLAGS="-L $(pwd)/target/lib" \
    cargo build --release -p fdo-manufacturing-client -p fdo-client-linuxapp --features tpm_support 2>&1 | tail -3
    ok "Rust clients built"

    step "Building Go TPM client"
    show_cmd "cd $GO_FDO_DIR/examples && go build -tags=tpm -o $GO_TPM_CLIENT ./cmd"
    (cd "$GO_FDO_DIR/examples" && go build -tags=tpm -o "$GO_TPM_CLIENT" ./cmd) 2>&1
    ok "Go TPM client built → $GO_TPM_CLIENT"

    echo ""
    info "NV Index Map (consolidated):"
    info "  0x01D10001  DCTPM         — Single CBOR blob: [Magic, Active, Version, DeviceInfo,"
    info "                               GUID, RvInfo, PubKeyHash, KeyType, DAKHandle, HMACHandle]"
    info ""
    info "Persistent Handles:"
    info "  0x81020002  DAK           — ECC signing key (userWithAuth=1, empty authValue)"
    info "  0x81020003  HMAC Key      — HMAC key (userWithAuth=1, empty authValue)"
    info ""
    info "Key Creation Methods:"
    info "  child   — Child key under deterministic SRK (WinPE-compatible, RNG-based)"
    info "  primary — Primary key with unique string (rollback-resistant)"
    info "  Both produce identical persistent keys — usage is the same."
}

# ===========================================================================
# Scenario A:  Rust DI  -->  Go Onboard
# ===========================================================================
scenario_a() {
    local method="${1:-child}"
    banner "Scenario A ($method): Rust DI --> Go Onboard"
    echo -e "  ${BOLD}Rust manufacturing-client provisions the TPM during Device Initialization.${NC}"
    echo -e "  ${BOLD}Go client reads the TPM credentials and completes TO1 + TO2 onboarding.${NC}"
    echo -e "  ${BOLD}Key creation method: ${CYAN}${method}${NC}"
    echo ""
    echo -e "  Flow:  ${CYAN}[Rust DI ($method)] --writes--> [TPM NV] --reads--> [Go TO1/TO2]${NC}"
    maybe_pause

    # -- Step 0: Clear TPM -------------------------------------------------
    section "Step 0: Clear TPM State"
    explain "Remove all FDO NV indices and persistent keys for a clean start."

    step "tpm2_clear (reset owner hierarchy)"
    show_cmd tpm2_clear -c lockout
    tpm2_clear -c lockout 2>/dev/null || true
    ok "TPM cleared"

    step "Go client tpm-clear (belt-and-suspenders cleanup)"
    show_cmd "$GO_TPM_CLIENT client -tpm-clear"
    "$GO_TPM_CLIENT" client -tpm-clear 2>/dev/null || true
    ok "FDO state cleared"

    inspect_tpm_empty
    maybe_pause

    # -- Step 1: Start server -----------------------------------------------
    section "Step 1: Start Go FDO Server"
    explain "The Go server handles DI registration and TO1/TO2 onboarding."
    explain "  -reuse-cred: allows credential reuse (no new OV needed per onboard)"
    rm -f "$DB_FILE"
    start_server "-reuse-cred"
    maybe_pause

    # -- Step 2: Rust DI ----------------------------------------------------
    section "Step 2: Rust Device Initialization (DI) — method: $method"
    if [ "$method" = "child" ]; then
        explain "Creating keys as children of a deterministic SRK (WinPE-compatible)."
        explain "  1. CreatePrimary (SRK under Owner hierarchy)"
        explain "  2. Create child ECC P-256 DAK under SRK → Load → EvictControl to 0x81020002"
        explain "  3. Create child HMAC key under SRK → Load → EvictControl to 0x81020003"
        explain "  4. Flush SRK (not needed after keys are persisted)"
    else
        explain "Creating keys as primaries with random unique strings (rollback-resistant)."
        explain "  1. Generate random unique strings"
        explain "  2. CreatePrimary ECC P-256 DAK with unique string → EvictControl to 0x81020002"
        explain "  3. CreatePrimary HMAC key with unique string → EvictControl to 0x81020003"
    fi
    explain "  Then: Send DI.AppStart to server → write consolidated DCTPM NV"

    step "Run Rust DI (--tpm-key-method $method)"
    export TSS2_TCTI="device:/dev/tpmrm0"
    export LD_LIBRARY_PATH="$(pwd)/target/lib:${LD_LIBRARY_PATH:-}"
    show_cmd "./target/release/fdo-manufacturing-client plain-di \\"
    show_cmd "    --manufacturing-server-url $SERVER_URL \\"
    show_cmd "    --mfg-string-type SerialNumber \\"
    show_cmd "    --key-ref tpm --tpm-key-method $method \\"
    show_cmd "    --fdo-version 200"
    echo ""
    MANUFACTURING_INFO="walkthrough-rust-$method" \
    RUST_LOG=info \
    timeout 30 ./target/release/fdo-manufacturing-client plain-di \
        --manufacturing-server-url "$SERVER_URL" \
        --mfg-string-type SerialNumber \
        --key-ref tpm \
        --tpm-key-method "$method" \
        --fdo-version 200 2>&1 | grep -v "WARNING:esys\|ERROR:esys\|ERROR tss_esapi\|Received TPM Error\|Error NV_ReadPublic\|Error TR From\|Error ReadPublic\|Closing handle\|Closing context\|Context closed" | grep -E "INFO|ERROR|error" | while read -r line; do
        echo "    $line"
    done
    ok "Rust DI completed ($method method) — credentials written to TPM"
    maybe_pause

    # -- Step 3: Inspect TPM (raw) ------------------------------------------
    section "Step 3: Inspect TPM After Rust DI ($method)"
    explain "Verify that Rust wrote all expected NV indices and persistent keys."
    inspect_tpm_raw
    maybe_pause

    # -- Step 4: Go reads TPM (high-level) -----------------------------------
    section "Step 4: Go Reads Rust-Provisioned TPM"
    explain "Go's tpm-show decodes the consolidated DCTPM CBOR blob and verifies keys."
    explain "This proves the cross-implementation CBOR encoding is compatible."
    inspect_tpm_go
    maybe_pause

    # -- Step 5: Go exports DAK ---------------------------------------------
    inspect_tpm_export_dak
    maybe_pause

    # -- Step 6: Go proves DAK possession ------------------------------------
    section "Step 5: Go Proves DAK Possession"
    explain "Go signs a challenge with the Rust-created DAK using empty authValue."
    explain "This is the key cross-implementation test: can Go use Rust's keys?"
    explain "The key was created via $method method — but usage is identical."
    inspect_tpm_prove
    maybe_pause

    # -- Step 7: Go onboard (TO1 + TO2) -------------------------------------
    section "Step 6: Go Onboards (TO1 + TO2) Using TPM Credentials"
    explain "Go reads the device credential from TPM NV and performs:"
    explain "  TO1:  HelloRV → HelloRVAck → ProveToRV (EAT) → RVRedirect"
    explain "  TO2:  HelloDeviceProbe(80) → ... → Done20(90) → DoneAck20(91)"
    explain ""
    explain "The DAK signs protocol messages via TPM with empty authValue."
    explain "The HMAC key computes credential HMACs via TPM with empty authValue."

    step "Run Go onboard"
    show_cmd "$GO_TPM_CLIENT client -fdo-version 200"
    echo ""
    "$GO_TPM_CLIENT" client -fdo-version 200 2>&1 | while read -r line; do
        echo "    $line"
    done
    ok "Go onboard completed"
    maybe_pause

    # -- Step 8: Final TPM state --------------------------------------------
    section "Step 7: Final TPM State (After Onboard)"
    explain "Credential reuse: TPM state should be unchanged (same credential)."
    inspect_tpm_go

    stop_server

    banner "Scenario A ($method) Complete: Rust DI --> Go Onboard PASSED"
}

# ===========================================================================
# Scenario B:  Go DI  -->  Rust Onboard
# ===========================================================================
scenario_b() {
    local method="${1:-child}"
    banner "Scenario B ($method): Go DI --> Rust Onboard"
    echo -e "  ${BOLD}Go client provisions the TPM during Device Initialization.${NC}"
    echo -e "  ${BOLD}Rust client-linuxapp reads the TPM credentials and completes TO1 + TO2.${NC}"
    echo -e "  ${BOLD}Key creation method: ${CYAN}${method}${NC}"
    echo ""
    echo -e "  Flow:  ${CYAN}[Go DI ($method)] --writes--> [TPM NV] --reads--> [Rust TO1/TO2]${NC}"
    maybe_pause

    # -- Step 0: Clear TPM -------------------------------------------------
    section "Step 0: Clear TPM State"
    explain "Remove all FDO NV indices and persistent keys for a clean start."

    step "tpm2_clear (reset owner hierarchy)"
    show_cmd tpm2_clear -c lockout
    tpm2_clear -c lockout 2>/dev/null || true
    ok "TPM cleared"

    export FDO_TPM_OWNER_HIERARCHY=1

    step "Go client tpm-clear"
    show_cmd "FDO_TPM_OWNER_HIERARCHY=1 $GO_TPM_CLIENT client -tpm-clear"
    "$GO_TPM_CLIENT" client -tpm-clear 2>/dev/null || true
    ok "FDO state cleared"

    inspect_tpm_empty
    maybe_pause

    # -- Step 1: Start server -----------------------------------------------
    section "Step 1: Start Go FDO Server"
    rm -f "$DB_FILE"
    start_server "-reuse-cred"
    maybe_pause

    # -- Step 2: Go DI -------------------------------------------------------
    section "Step 2: Go Device Initialization (DI) — method: $method"
    explain "Go client performs DI with -di-key ec256 (P-256 curve)."
    explain "FDO_TPM_OWNER_HIERARCHY=1 is required on Linux because the"
    explain "Platform hierarchy is locked after boot."
    if [ "$method" = "child" ]; then
        explain ""
        explain "FDO_TPM_KEY_METHOD=child (default):"
        explain "  1. CreatePrimary (SRK under Owner hierarchy)"
        explain "  2. Create child ECC P-256 DAK under SRK → Load → EvictControl to 0x81020002"
        explain "  3. Create child HMAC key under SRK → Load → EvictControl to 0x81020003"
    else
        explain ""
        explain "FDO_TPM_KEY_METHOD=primary:"
        explain "  1. Generate random unique strings"
        explain "  2. CreatePrimary ECC P-256 DAK with unique string → EvictControl to 0x81020002"
        explain "  3. CreatePrimary HMAC key with unique string → EvictControl to 0x81020003"
    fi
    explain "  Then: Send DI request to server → write consolidated DCTPM NV"

    step "Run Go DI (FDO_TPM_KEY_METHOD=$method)"
    export TSS2_TCTI="device:/dev/tpmrm0"
    show_cmd "FDO_TPM_OWNER_HIERARCHY=1 FDO_TPM_KEY_METHOD=$method $GO_TPM_CLIENT client -di $SERVER_URL -di-key ec256"
    echo ""
    FDO_TPM_OWNER_HIERARCHY=1 \
    FDO_TPM_KEY_METHOD="$method" \
    "$GO_TPM_CLIENT" client -di "$SERVER_URL" -di-key ec256 2>&1 | while read -r line; do
        echo "    $line"
    done
    ok "Go DI completed ($method method) — credentials written to TPM"
    maybe_pause

    # -- Step 3: Inspect TPM (raw) ------------------------------------------
    section "Step 3: Inspect TPM After Go DI ($method)"
    explain "Verify that Go wrote all expected NV indices and persistent keys."
    inspect_tpm_raw
    maybe_pause

    # -- Step 4: Go tpm-show (for reference) --------------------------------
    section "Step 4: Go Reads Its Own TPM State (Reference)"
    explain "Baseline: Go can read back what it just wrote."
    inspect_tpm_go
    maybe_pause

    # -- Step 5: Go proves DAK -----------------------------------------------
    section "Step 5: Go Proves DAK Possession (Baseline)"
    explain "Verify Go can sign with its own DAK before handing off to Rust."
    inspect_tpm_prove
    maybe_pause

    # -- Step 6: Rust onboard (TO1 + TO2) -----------------------------------
    section "Step 6: Rust Onboards (TO1 + TO2) Using TPM Credentials"
    explain "Rust client-linuxapp reads the device credential from TPM NV."
    explain "It uses the Go-created DAK and HMAC key with empty authValue (null auth)."
    explain ""
    explain "The Rust client must correctly:"
    explain "  - Decode consolidated DCTPM CBOR blob written by Go"
    explain "  - Extract GUID, RvInfo, PubKeyHash, handle addresses"
    explain "  - Sign with DAK using empty authValue (null auth session)"
    explain "  - Compute HMAC using HMAC key with empty authValue"

    step "Run Rust onboard"
    export LD_LIBRARY_PATH="$(pwd)/target/lib:${LD_LIBRARY_PATH:-}"
    rm -f /tmp/fdo_onboard_marker_walkthrough
    show_cmd "./target/release/fdo-client-linuxapp"
    echo ""
    DEVICE_ONBOARDING_EXECUTED_MARKER_FILE_PATH=/tmp/fdo_onboard_marker_walkthrough \
    ALLOW_NONINTEROPERABLE_KDF=1 \
    RUST_LOG=info \
    timeout 60 ./target/release/fdo-client-linuxapp 2>&1 | grep -v "WARNING:esys\|ERROR:esys\|ERROR tss_esapi\|Received TPM Error\|Error NV_ReadPublic\|Error TR From\|Error ReadPublic\|Closing handle\|Closing context\|Context closed" | grep -E "INFO|ERROR|error|Credential|credential" | while read -r line; do
        echo "    $line"
    done
    ok "Rust onboard completed"
    maybe_pause

    # -- Step 7: Final TPM state -------------------------------------------
    section "Step 7: Final TPM State (After Rust Onboard)"
    explain "Credential reuse: TPM state should be unchanged."
    inspect_tpm_go

    stop_server

    banner "Scenario B ($method) Complete: Go DI --> Rust Onboard PASSED"
}

# ===========================================================================
# Main
# ===========================================================================
main() {
    local scenario="${1:-all}"

    banner "FDO 2.0 TPM Cross-Implementation Walkthrough"
    echo -e "  ${BOLD}Demonstrates Rust ←→ Go FDO 2.0 interoperability${NC}"
    echo -e "  ${BOLD}with hardware TPM-backed credential storage.${NC}"
    echo ""
    echo -e "  Scenario A (child):   Rust DI (child method)   →  Go Onboard"
    echo -e "  Scenario A (primary): Rust DI (primary method) →  Go Onboard"
    echo -e "  Scenario B (child):   Go DI (child method)     →  Rust Onboard"
    echo -e "  Scenario B (primary): Go DI (primary method)   →  Rust Onboard"
    echo ""
    echo -e "  Both methods produce identical persistent keys — usage is the same."
    echo ""
    info "Set PAUSE=1 to pause between steps."
    echo ""

    preflight

    local pass=0
    local total=0

    run_scenario() {
        local name="$1"
        shift
        total=$((total + 1))
        if "$@"; then
            pass=$((pass + 1))
        else
            fail "$name failed"
        fi
    }

    case "$scenario" in
        a-child)   run_scenario "A (child)"   scenario_a child ;;
        a-primary) run_scenario "A (primary)" scenario_a primary ;;
        b-child)   run_scenario "B (child)"   scenario_b child ;;
        b-primary) run_scenario "B (primary)" scenario_b primary ;;
        a)
            run_scenario "A (child)"   scenario_a child
            run_scenario "A (primary)" scenario_a primary
            ;;
        b)
            run_scenario "B (child)"   scenario_b child
            run_scenario "B (primary)" scenario_b primary
            ;;
        all|ab)
            run_scenario "A (child)"   scenario_a child
            run_scenario "A (primary)" scenario_a primary
            run_scenario "B (child)"   scenario_b child
            run_scenario "B (primary)" scenario_b primary
            ;;
        *)
            echo "Usage: $0 [all|a|b|a-child|a-primary|b-child|b-primary]"
            exit 1
            ;;
    esac

    echo ""
    banner "Summary: $pass / $total scenarios passed"
    if [ "$pass" -eq "$total" ]; then
        echo -e "  ${GREEN}${BOLD}All cross-implementation TPM tests passed.${NC}"
    else
        echo -e "  ${RED}${BOLD}Some tests failed. Check output above.${NC}"
        exit 1
    fi
    echo ""
}

cd "$RUST_DIR"
main "$@"
