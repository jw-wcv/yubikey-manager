#!/bin/bash

# =============================================================================
# Load Utilities and Environment
# =============================================================================
# Dynamically load all utility scripts and environment variables
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/utilities/loader.sh"


################################################################################
#####                   Backup / Resets Config                             #####
################################################################################

# Ensure Dependencies are Present
check_dependencies() {
    log "INFO" "🔍 Checking for required dependencies..."
    
    # List of dependencies
    local dependencies=("ykman" "openssl" "ssh")
    
    # Loop through dependencies and install if missing
    for dep in "${dependencies[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            log "WARN" "$dep not found. Installing..."
            
            # Special handling for ykman (from Yubico tap)
            if [ "$dep" == "ykman" ]; then
                brew tap yubico/yubico
                brew install ykman &>/dev/null &
            else
                brew install "$dep" &>/dev/null &
            fi
            
            spinner
            
            # Verify installation
            if ! command -v "$dep" &>/dev/null; then
                log "ERROR" "Failed to install $dep. Check brew logs."
                error_exit "$dep installation failed."
            fi
        fi
    done
    log "INFO" "✅ All dependencies are installed."
}

# Factory Reset 
factory_reset_yubikey() {
    check_yubikey_presence || return
    read -p "⚠️ This will completely reset your YubiKey. Continue? (y/N): " confirm
    if [[ $confirm =~ ^[Yy]$ ]]; then
        ykman config mode fido+ccid
        ykman piv reset
        ykman fido reset
        # ykman otp reset
        ykman oath reset
        log "INFO" "🧹 YubiKey has been reset to factory defaults."
    else
        log "INFO" "Factory reset cancelled."
    fi
}

# Backup SSH and YubiKey configuration
backup_configuration() {
    mkdir -p "$BACKUP_DIR"
    cp "$IP_CONFIG_FILE" "$BACKUP_DIR/yubikey_ssh_config.bak.$(date +%s)"
    log "INFO" "🔒 Configuration backed up to $BACKUP_DIR."

    log "INFO" "⚠️  Reminder: FIDO2 keys cannot be backed up directly. Ensure a second YubiKey is enrolled as a backup."
}


# Restore latest backup configuration
restore_configuration() {
    local latest_backup
    latest_backup=$(ls -t "$BACKUP_DIR" | head -n 1)
    if [ -n "$latest_backup" ]; then
        cp "$BACKUP_DIR/$latest_backup" "$IP_CONFIG_FILE"
        log "INFO" "🔄 Configuration restored from $latest_backup."
    else
        log "WARN" "No backup found."
    fi
    log "INFO" "⚠️  Remember to verify FIDO2 backup YubiKeys are enrolled with your services."
}


################################################################################
#####                       Smart Card Config                              #####
################################################################################

# View Smart Card Identities
view_smart_cards() {
    log "INFO" "🔍 Viewing paired smart cards..."
    sc_auth identities
}

# Add Smart Card (Pair with Selected User)
add_smart_card() {
    log "INFO" "➕ Pairing smart card with a selected user..."

    # List available users
    log "INFO" "🔍 Listing available users..."
    dscl . list /Users | grep -vE '_|daemon|nobody|root' | sort

    # Prompt user to select the account to pair the smart card with
    echo ""
    read -rp "Enter the username to pair the smart card with: " selected_user

    if id "$selected_user" &>/dev/null; then
        log "INFO" "🔑 Selected user: $selected_user"
    else
        log "ERROR" "❌ User $selected_user not found. Aborting."
        echo "Error: User $selected_user does not exist."
        return
    fi

    # Attempt to auto-pair with the selected user explicitly
    sudo sc_auth pair -u "$selected_user"
    if [ $? -ne 0 ]; then
        log "WARN" "⚠️  Auto pairing failed. Attempting manual pairing by specifying certificate hash."

        # Display available smart card identities
        sc_auth identities
        
        echo ""
        read -rp "Enter the public key hash for the identity to pair (or leave blank to cancel): " public_key_hash
        
        if [[ -z "$public_key_hash" ]]; then
            log "ERROR" "❌ No public key hash provided. Aborting pairing."
            return
        fi

        # Manually pair the card to the selected user by specifying the hash
        sudo sc_auth pair -h "$public_key_hash" -u "$selected_user"
        
        if [ $? -eq 0 ]; then
            # Automatically update keychain settings to unlock at login
            log "INFO" "🔐 Configuring keychain to unlock with smart card login for $selected_user..."
            if sudo -u "$selected_user" security set-keychain-settings -lu; then
                log "INFO" "✅ Keychain settings updated successfully for $selected_user."
            else
                log "ERROR" "❌ Failed to update keychain settings for $selected_user."
            fi
            log "INFO" "✅ Smart card paired successfully with hash $public_key_hash for user $selected_user."
        else
            log "ERROR" "❌ Failed to pair smart card with hash $public_key_hash for user $selected_user."
        fi
    else
        log "INFO" "✅ Smart card paired successfully with user $selected_user."
    fi
}

# Remove Smart Card (Unpair)
remove_smart_card() {
    log "INFO" "➖ Removing paired smart cards..."

    # List paired identities
    paired_identities=$(sc_auth identities | awk '{print $1}')

    if [[ -z "$paired_identities" ]]; then
        log "WARN" "⚠️ No paired smart cards found."
        echo "No paired smart cards detected."
        return
    fi

    echo "Paired Smart Card Identities:"
    sc_auth identities

    echo ""
    read -rp "Enter the public key hash to unpair (or leave blank to remove all): " public_key_hash

    if [[ -z "$public_key_hash" ]]; then
        log "INFO" "🔄 Removing all paired smart cards..."
        while IFS= read -r identity; do
            sudo sc_auth unpair -h "$identity"
            if [ $? -eq 0 ]; then
                log "INFO" "✅ Smart card with hash $identity unpaired successfully."
            else
                log "ERROR" "❌ Failed to unpair smart card with hash $identity. Attempting force removal..."
                sudo sc_auth pair -d -h "$identity"
                sudo sc_auth unpair -h "$identity"
            fi
        done <<< "$paired_identities"

        # Clear the system-level token mappings
        log "INFO" "🔧 Clearing system-level token mappings..."
        sudo defaults delete /Library/Preferences/com.apple.security.smartcard "TokenMapping" 2>/dev/null
        sudo defaults delete /Library/Preferences/com.apple.security.smartcard "UserPairing" 2>/dev/null
        sudo security delete-smartcard
        log "INFO" "✅ System smart card mappings and tokens cleared."

    else
        sudo sc_auth unpair -h "$public_key_hash"
        if [ $? -ne 0 ]; then
            log "ERROR" "❌ Failed to unpair smart card with hash $public_key_hash. Forcing removal..."
            sudo sc_auth pair -d -h "$public_key_hash"
            sudo sc_auth unpair -h "$public_key_hash"
        fi

        # Double-check if the smart card persists
        remaining=$(sc_auth identities | grep "$public_key_hash")
        if [[ -n "$remaining" ]]; then
            log "ERROR" "❌ Smart card with hash $public_key_hash is still paired. Trying direct deletion..."
            sudo defaults delete /Library/Preferences/com.apple.security.smartcard "TokenMapping"
            sudo defaults delete /Library/Preferences/com.apple.security.smartcard "UserPairing"
            sudo security delete-smartcard
        fi
    fi

    # Recheck identities to confirm
    log "INFO" "🔍 Rechecking smart card identities..."
    sc_auth identities

    # Force refresh smart card services
    log "INFO" "🔄 Refreshing Smart Card Services..."
    sudo killall -HUP scardservicesd 2>/dev/null
    sudo killall -HUP pcscd 2>/dev/null
    log "INFO" "✅ Smart Card services refreshed. Unpairing complete."
}

# Main Function - Configure Smart Cards
configure_smart_cards() {
    echo "--------------------------------------"
    echo "  🛡️  Smart Card Configuration Manager  "
    echo "--------------------------------------"
    echo "1) View Smart Cards (sc_auth identities)"
    echo "2) Add Smart Card (Pair)"
    echo "3) Remove Smart Card (Unpair)"
    echo "4) Exit"
    echo ""

    read -p "Select an option [1-4]: " choice

    case $choice in
        1) # Attempt to pair with specified hash
        sudo sc_auth pair -u $USER -h "$public_key_hash"
            view_smart_cards
            ;;
        2)
            add_smart_card
            ;;
        3)
            remove_smart_card
            ;;
        4)
            log "INFO" "❌ Exiting smart card configuration."
            echo "Goodbye!"
            exit 0
            ;;
        *)
            log "WARN" "⚠️  Invalid option selected."
            echo "Invalid option. Please try again."
            ;;
    esac
}

################################################################################
#####                        FileVault Config                              #####
################################################################################

# Enable Full Disk Encryption
enable_full_disk_encryption() {
    mkdir -p "$KEY_DIR"

    log "INFO" "🔒 Enabling Full Disk Encryption with YubiKey..."

    # Fetch management key dynamically
    local management_key
    management_key=$(jq -r '.management_key' "$KEY_DIR/../data/yubi_config.json" 2>/dev/null)
    if [[ -z "$management_key" || "$management_key" == "null" ]]; then
        log "ERROR" "❌ Management key not found. Configure YubiKey first."
        echo "Error: Management key not found. Cannot proceed."
        return
    fi

    # Generate Key Pair in Slot 9d (Key Management)
    log "INFO" "🔑 Generating Key Management key in YubiKey slot 9d..."
    ykman piv keys generate --management-key "$management_key" --touch-policy=always --pin-policy=always 9d "$KEY_DIR/slot_9d_key.pub"

    if [ $? -ne 0 ]; then
        log "ERROR" "❌ Failed to generate key in slot 9d."
        echo "Error: Key generation failed. Aborting."
        return
    fi

    # Export Public Key from Slot 9d for Encryption
    ykman piv keys export 9d "$KEY_DIR/slot_9d_key.pem"

    if [ $? -ne 0 ]; then
        log "ERROR" "❌ Failed to export public key from YubiKey."
        echo "Error: Public key export failed. Aborting."
        return
    fi

    # Prompt for Recovery Key
    echo ""
    read -s -p "Enter FileVault Recovery Key (hidden): " recovery_key
    echo ""

    # Validate Recovery Key
    if [[ -z "$recovery_key" ]]; then
        log "ERROR" "❌ Recovery key not provided."
        echo "Error: Recovery key cannot be empty. Aborting."
        return
    fi

    # Encrypt Recovery Key with Exported Public Key (YubiKey Slot 9d)
    log "INFO" "🔐 Encrypting recovery key using YubiKey's public key (slot 9d)..."
    echo "$recovery_key" | openssl pkeyutl -encrypt -pubin -inkey "$KEY_DIR/slot_9d_key.pem" -out "$RECOVERY_KEY_PATH"

    if [ $? -ne 0 ]; then
        log "ERROR" "❌ Failed to encrypt recovery key."
        echo "Error: Encryption failed. Aborting."
        return
    fi

    # Update PLIST to Store the Actual Recovery Key
    /usr/libexec/PlistBuddy -c "Delete :RecoveryKeyPath" "$PLIST_PATH" 2>/dev/null
    /usr/libexec/PlistBuddy -c "Delete :RecoveryKey" "$PLIST_PATH" 2>/dev/null
    /usr/libexec/PlistBuddy -c "Add :RecoveryKey string $recovery_key" "$PLIST_PATH"

    log "INFO" "🔏 Plaintext recovery key saved in plist for FileVault. Encrypted key backup stored at $RECOVERY_KEY_PATH."

    # Enable FileVault with Deferred Activation
    log "INFO" "🔄 Initiating FileVault encryption process..."
    sudo fdesetup enable -defer "$PLIST_PATH" 2>&1 | tee /tmp/fdesetup_enable.log
    enable_exit_code=${PIPESTATUS[0]}

    if [ $enable_exit_code -ne 0 ]; then
        log "ERROR" "❌ Failed to enable Full Disk Encryption. Check /tmp/fdesetup_enable.log for details."
        echo "Error: Failed to enable Full Disk Encryption. Check /tmp/fdesetup_enable.log for details."
        return
    fi

    log "INFO" "🕒 Deferred enablement detected. Please reboot to complete FileVault activation."
    echo "Deferred enablement is active. Reboot required to complete encryption."
}

# Disable Full Disk Encryption 
disable_full_disk_encryption() {
    log "INFO" "🔓 Disabling Full Disk Encryption with YubiKey..."

    # Ensure FileVault isn't in deferred mode
    local status=$(fdesetup status)
    if [[ $status == *"Deferred enablement appears to be active"* ]]; then
        log "WARN" "🕒 FileVault is in deferred mode. Disabling..."
        sudo fdesetup disable
        echo "FileVault is in deferred mode. Disabling."
        rm -f "$PLIST_PATH"
        log "INFO" "🗑️  PLIST file removed after disabling FileVault in deferred mode."
        return
    fi

    # Check if the encrypted recovery key exists
    if [ ! -f "$RECOVERY_KEY_PATH" ]; then
        log "ERROR" "❌ Encrypted recovery key not found. Cannot disable encryption."
        echo "Error: Encrypted recovery key missing. Generate it first."
        return
    fi

    # Decrypt the recovery key using the YubiKey
    log "INFO" "🔑 Decrypting recovery key with YubiKey (slot 9d)..."
    if ! ykman piv decrypt 9d "$RECOVERY_KEY_PATH" > "$decrypted_key_path" 2>&1; then
        log "ERROR" "❌ Failed to decrypt recovery key. Ensure the YubiKey is inserted and touch the key when prompted."
        echo "Error: Failed to decrypt recovery key. Cannot disable encryption."
        return
    fi

    # Disable FileVault using the decrypted key
    log "INFO" "🚫 Disabling FileVault..."
    if sudo fdesetup disable -inputplist < "$PLIST_PATH"; then
        log "INFO" "✅ FileVault disabled successfully."
        echo "FileVault has been disabled."
        
        # Remove the config.plist after successful disable
        if [ -f "$PLIST_PATH" ]; then
            rm -f "$PLIST_PATH"
            log "INFO" "🗑️  PLIST file removed after disabling FileVault."
            echo "PLIST configuration removed."
        fi
    else
        log "ERROR" "❌ Failed to disable FileVault."
        echo "Error: Failed to disable FileVault. Check logs for more details."
    fi

    # Cleanup
    rm -f "$decrypted_key_path"
}

# Manage Full Disk Encryption
manage_disk_encryption() {
    echo "---------------------------------------------"
    echo "        🛡️  Full Disk Encryption Manager 🛡️        "
    echo "---------------------------------------------"
    echo "Please select an option:"
    echo "1) Enable Full Disk Encryption"
    echo "2) Disable Full Disk Encryption"
    echo "3) Cancel"
    echo ""

    read -p "Enter your choice [1-3]: " choice

    case "$choice" in
        1)
            enable_full_disk_encryption
            ;;
        2)
            disable_full_disk_encryption
            ;;
        3)
            log "INFO" "🔄 Operation cancelled by user."
            echo "Operation cancelled."
            ;;
        *)
            log "WARN" "⚠️  Invalid selection: $choice"
            echo "Invalid selection. Please enter a number between 1 and 3."
            ;;
    esac
}

# Post-Reboot - Generate and Encrypt Recovery Key
generate_recovery_key() {
    log "INFO" "🔐 Generating and encrypting recovery key after reboot..."

    # Ensure FileVault is fully enabled
    local status=$(fdesetup status)
    if [[ $status != *"FileVault is On"* ]]; then
        log "ERROR" "❌ FileVault is not fully enabled. Cannot generate recovery key."
        echo "Error: FileVault is not enabled. Reboot and complete encryption first."
        return
    fi

    # Generate Recovery Key and Encrypt with YubiKey
    local recovery_key
    recovery_key=$(sudo fdesetup changerecovery -personal)

    if [ -z "$recovery_key" ]; then
        log "ERROR" "❌ Failed to generate recovery key."
        echo "Error: Failed to generate recovery key."
        return
    fi

    # Use the RECOVERY_KEY_FILE environment variable for storing the plaintext key
    echo "$recovery_key" > "$RECOVERY_KEY_FILE"
    echo "$recovery_key" | ykman piv encrypt 9d > "$RECOVERY_KEY_PATH"
    
    log "INFO" "🔏 Recovery key encrypted and stored at $RECOVERY_KEY_PATH."
    log "INFO" "📄 Plaintext recovery key saved to $RECOVERY_KEY_FILE."
    echo "Recovery key successfully encrypted with YubiKey."
}

# Create Configuration Plist File
create_plist_file() {    
    echo "Creating FileVault configuration plist at $PLIST_PATH..."
    log "INFO" "📝 Creating FileVault configuration plist at $PLIST_PATH..."

    # Generate a secure Recovery Key
    recovery_key=$(openssl rand -base64 32)
    echo "A secure Recovery Key has been generated."

    # Prompt for Username and Password
    read -p "Enter your macOS username: " mac_username
    read -s -p "Enter your macOS password: " mac_password
    echo ""

    # Create the plist file with the actual recovery key
    cat <<EOF > "$PLIST_PATH"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Deferred</key>
    <true/>
    <key>MountVolumes</key>
    <array>
        <string>/</string>
    </array>
    <key>RecoveryKey</key>
    <string>$recovery_key</string>
    <key>UserRecords</key>
    <array>
        <dict>
            <key>Username</key>
            <string>$mac_username</string>
            <key>Password</key>
            <string>$mac_password</string>
        </dict>
    </array>
</dict>
</plist>
EOF

    # Secure the plist file
    chmod 600 "$PLIST_PATH"
    log "INFO" "✅ Plist file created at $PLIST_PATH with secure permissions."
    echo "Plist file created successfully at $PLIST_PATH."

    # Save the Recovery Key to a separate file for storage
    echo "$recovery_key" > "$RECOVERY_KEY_FILE"
    chmod 600 "$RECOVERY_KEY_FILE"
    log "INFO" "🔑 Recovery Key saved to $RECOVERY_KEY_FILE. Store it securely."
    echo "Recovery Key saved to $RECOVERY_KEY_FILE. Please store it securely."
}

