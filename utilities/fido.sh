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
    # Declare local variables using environment variables
    local ssh_key_dir="$SSH_DIR"
    local key_backup_dir="$KEY_DIR"
    local log_dir="$LOG_DIR"
    local project_root="$PROJECT_ROOT"
    
    log "INFO" "🔐 Initiating export of FIDO2 SSH public keys..."
    
    # Ensure SSH_DIR exists
    mkdir -p "$ssh_key_dir"
    
    # Attempt to pull FIDO2 resident keys directly to ~/.ssh/
    log "INFO" "🔐 Checking for FIDO2 resident keys on YubiKey (via ssh-keygen -K):"
    
    # Change to SSH directory to force ssh-keygen to save keys in the right place
    (
        cd "$ssh_key_dir" || exit
        ssh-keygen -K 2>&1 | tee "$log_dir/fido_resident_key.log"
    )
    
    # Handle resident key export
    if grep -q "Saved" "$log_dir/fido_resident_key.log"; then
        log "INFO" "✅ FIDO2 resident keys successfully retrieved and saved to $ssh_key_dir."
        
        # Copy the new resident keys from ~/.ssh to KEY_DIR
        for keyfile in id_ecdsa_sk_rk id_ecdsa_sk; do
            if [ -f "$ssh_key_dir/$keyfile" ]; then
                cp "$ssh_key_dir/$keyfile" "$key_backup_dir/" 2>/dev/null
                cp "$ssh_key_dir/$keyfile.pub" "$key_backup_dir/" 2>/dev/null
                log "INFO" "🔑 Copied FIDO2 SSH Key to $key_backup_dir: $keyfile"
            fi
        done
    else
        log "INFO" "No FIDO2 resident keys found on YubiKey."
    fi

    # Check for non-resident FIDO2 keys by scanning for *_sk files
    log "INFO" "🔍 Searching for all FIDO2 SSH keys (resident and non-resident) in $ssh_key_dir and $key_backup_dir:"
    
    # Search in ~/.ssh and backup directories for keys
    for dir in "$ssh_key_dir" "$key_backup_dir"; do
        if [ -d "$dir" ]; then
            fido2_keys=$(ls "$dir"/*_sk "$dir"/*_sk_rk 2>/dev/null)

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

    echo ""

    # Handle misplaced files in project directory
    log "INFO" "🔍 Checking for misplaced FIDO2 SSH keys in project directory ($project_root):"
    
    # Explicitly check for misplaced *_sk files
    for keyfile in id_ecdsa_sk_rk id_ecdsa_sk id_ecdsa_sk_rk.pub id_ecdsa_sk.pub; do
        if [ -f "$project_root/$keyfile" ]; then
            # Move key to ~/.ssh/
            mv "$project_root/$keyfile" "$ssh_key_dir/" 2>/dev/null
            log "INFO" "🔑 Moved $keyfile to $ssh_key_dir."

            # Copy to KEY_DIR as backup
            cp "$ssh_key_dir/$keyfile" "$key_backup_dir/" 2>/dev/null
            log "INFO" "🔑 Copied $keyfile to $key_backup_dir for backup."
        fi
    done

    log "INFO" "🎉 FIDO2 SSH key export process completed."
}

