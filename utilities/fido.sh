#!/bin/bash

# =============================================================================
# Load Utilities and Environment
# =============================================================================
# Dynamically load all utility scripts and environment variables
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/utilities/loader.sh"

################################################################################
#####                           FIDO Config                                #####
################################################################################

# Generate FIDO2 SSH Key Pair on YubiKey (Resident or Non-Resident)
generate_fido2_ssh_key() {
    local resident_flag=""
    mkdir -p "$KEY_DIR"

    echo ""
        echo "--------------------------------------"
        echo "     🔑 FIDO2 SSH Key Generation       "
        echo "--------------------------------------"
        echo "1) Generate Non-Resident FIDO2 SSH Key (Default)"
        echo "2) Generate Resident FIDO2 SSH Key (Stored on YubiKey, Recoverable)"
        echo "3) Return to Previous Menu"
        echo ""

        read -rp "Select an option [1-3]: " fido_choice

        case $fido_choice in
            1)
                log "INFO" "🔐 Generating Non-Resident FIDO2 SSH key..."
                # Add key generation logic here
                ;;
            2)
                log "INFO" "🔐 Generating Resident FIDO2 SSH key (stored on YubiKey)..."
                resident_flag="-O resident"
                # Add key generation logic here
                ;;
            3)
                log "INFO" "🔙 Returning to previous menu..."
                return
                ;;
            *)
                log "WARN" "⚠️ Invalid option. Please select 1, 2, or 3."
                echo "Invalid option. Please try again."
                ;;
        esac

    # Delete existing FIDO2 SSH key if it exists
    if [ -f "$SSH_KEY" ]; then
        log "WARN" "⚠️ Existing FIDO2 SSH key detected. Removing old key to ensure consistency."
        rm -f "$SSH_KEY" "$SSH_KEY_PUB"
        log "INFO" "🧹 Old FIDO2 SSH key removed."
    fi

    # Generate a new FIDO2 SSH key pair with chosen option
    log "INFO" "🛠️ Generating new FIDO2 SSH key pair..."
    ssh-keygen -t ecdsa-sk $resident_flag -f "$SSH_KEY" -C "ALEPH_SERVICES"
    
    if [ $? -eq 0 ]; then
        log "INFO" "✅ FIDO2 SSH key pair generated successfully."
        log "INFO" "🔍 Public key located at $SSH_KEY_PUB."
        
        # Backup the keys to the project directory
        cp "$SSH_KEY_PUB" "$KEY_DIR/"
        log "INFO" "🔑 Public key backed up to $KEY_DIR/$(basename $SSH_KEY_PUB)."
        
        # Check for private key (non-resident) and backup if available
        if [ -f "$SSH_KEY" ]; then
            cp "$SSH_KEY" "$KEY_DIR/"
            log "INFO" "🔑 Private key backed up to $KEY_DIR/$(basename $SSH_KEY)."
        else
            log "INFO" "🔐 Resident key created - no private key file generated (stored directly on YubiKey)."
        fi

        # Ensure a FIDO2 PIN is set immediately after key generation
        log "INFO" "🔐 Setting FIDO2 PIN (required for credential management)..."
        ykman fido access change-pin
        if [ $? -eq 0 ]; then
            log "INFO" "✅ FIDO2 PIN set successfully."
        else
            log "ERROR" "❌ Failed to set FIDO2 PIN. Credential management might be limited."
        fi
    else
        log "ERROR" "❌ Failed to generate FIDO2 SSH key pair."
        return 1
    fi
}

# Deploy FIDO2 Public Key to Remote Servers - INCOMPLETE 
deploy_fido2_public_key() {
    local remote_user="root"
    local remote_host="[ipv6_address]"  # Replace with your actual IPv6 address or hostname

    log "INFO" "🔧 Deploying FIDO2 public key to remote server $remote_host..."

    # Check if remote_host is provided
    if [ "$remote_host" == "[ipv6_address]" ]; then
        log "ERROR" "❌ Remote host IPv6 address not set. Please update the script with your VM's IPv6 address."
        return 1
    fi

    # Deploy using ssh-copy-id
    ssh-copy-id -i "$SSH_KEY_PUB" "$remote_user@$remote_host" || {
        log "ERROR" "❌ Failed to deploy FIDO2 public key to $remote_host."
        return 1
    }

    log "INFO" "✅ FIDO2 public key deployed to $remote_host successfully."
}

# Export FIDO2 (ecdsa-sk/ed25519-sk) Public Key(s)
export_fido2_public_key() {  
    # Attempt to pull FIDO2 resident keys directly to ~/.ssh/
    log "INFO" "🔐 Checking for FIDO2 resident keys on YubiKey (via ssh-keygen -K):"
    
    # Ensure ~/.ssh exists
    mkdir -p "$SSH_DIR"
    
    # Export FIDO2 resident key explicitly to ~/.ssh/
    ssh-keygen -K -f "$SSH_DIR/id_ecdsa_sk_rk" 2>&1 | tee /tmp/fido_resident_key.log
    
    if grep -q "Saved" /tmp/fido_resident_key.log; then
        log "INFO" "✅ FIDO2 resident keys successfully retrieved and saved to $SSH_DIR."
        
        # Copy the new resident keys from ~/.ssh to KEY_DIR
        cp "$SSH_DIR/id_ecdsa_sk_rk" "$KEY_DIR/" 2>/dev/null
        cp "$SSH_DIR/id_ecdsa_sk_rk.pub" "$KEY_DIR/" 2>/dev/null
        log "INFO" "🔑 Copied FIDO2 SSH Key to $KEY_DIR: id_ecdsa_sk_rk"
    else
        log "INFO" "No FIDO2 resident keys found on YubiKey."
    fi

    echo ""

    # Handle misplaced files in project directory
    log "INFO" "🔍 Checking for misplaced FIDO2 SSH keys in project directory ($PROJECT_ROOT):"
    
    # Explicitly check for the specific files
    for keyfile in id_ecdsa_sk_rk id_ecdsa_sk_rk.pub; do
        if [ -f "$PROJECT_ROOT/$keyfile" ]; then
            # Move key to ~/.ssh/
            mv "$PROJECT_ROOT/$keyfile" "$SSH_DIR/" 2>/dev/null
            log "INFO" "🔑 Moved $keyfile to $SSH_DIR."

            # Copy to KEY_DIR as backup
            cp "$SSH_DIR/$keyfile" "$KEY_DIR/" 2>/dev/null
            log "INFO" "🔑 Copied $keyfile to $KEY_DIR for backup."
        fi
    done

    # Check both local directories for non-resident FIDO2 SSH keys
    log "INFO" "🔍 Searching for local FIDO2 SSH keys in $SSH_DIR and $KEY_DIR:"

    for dir in "$SSH_DIR" "$KEY_DIR"; do
        if [ -d "$dir" ]; then
            fido2_keys=$(ls "$dir"/*_sk 2>/dev/null)

            if [ -z "$fido2_keys" ]; then
                log "INFO" "No FIDO2 SSH keys found in $dir."
            else
                for key in $fido2_keys; do
                    log "INFO" "FIDO2 SSH Key (Local): $key"
                    log "INFO" "Public Key:"
                    cat "${key}.pub" 2>/dev/null || log "ERROR" "Failed to read public key for $key."
                done
            fi
        fi
    done
}