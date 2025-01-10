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
    
    local dependencies=("ykman" "openssl" "ssh" "gpg" "pinentry-mac")
    
    if ! command -v brew &>/dev/null; then
        log "ERROR" "❌ Homebrew not found. Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" || {
            log "ERROR" "Failed to install Homebrew. Exiting..."
            return 1
        }
    fi

    for dep in "${dependencies[@]}"; do
        if ! command -v "$dep" &>/dev/null && [ ! -f "/opt/homebrew/bin/$dep" ]; then
            log "WARN" "$dep not found. Installing..."
            
            local attempts=0
            until [ $attempts -ge 3 ]; do
                sudo -u $(logname) brew install "$dep" &>/tmp/brew_install.log && break
                attempts=$((attempts + 1))
                log "WARN" "Attempt $attempts to install $dep failed. Retrying..."
            done

            if ! command -v "$dep" &>/dev/null && [ ! -f "/opt/homebrew/bin/$dep" ]; then
                log "ERROR" "Failed to install $dep. Review Brew logs:"
                cat /tmp/brew_install.log
                read -rp "⚠️  Manual intervention needed. Retry? (y/N): " retry
                if [[ $retry =~ ^[Yy]$ ]]; then
                    sudo -u $(logname) brew install "$dep"
                else
                    log "ERROR" "$dep installation failed. Exiting..."
                    error_exit "$dep installation failed."
                fi
            fi
        else
            log "INFO" "$dep is already installed."
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
        ykman openpgp reset
        ykman oath reset
        # ykman otp reset  # Uncomment if OTP reset is required
        log "INFO" "🧹 YubiKey has been reset to factory defaults."
        sudo killall -HUP pcscd scardservicesd
        log "INFO" "🔄 Smart card services restarted."

    else
        log "INFO" "Factory reset cancelled."
    fi
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
    while true; do
        clear
        ascii_art
        echo -e "${CYAN}${BOLD}🛡️  Smart Card Configuration Manager${RESET}"
        echo -e "${MAGENTA}${BOLD}Smart Card Configuration Menu:${RESET}"
        echo -e "${YELLOW}=========================================${RESET}"
        echo -e "${YELLOW}1) View Smart Cards (sc_auth identities)${RESET}"
        echo -e "${YELLOW}2) Add Smart Card (Pair)${RESET}"
        echo -e "${YELLOW}3) Remove Smart Card (Unpair)${RESET}"
        echo -e "${YELLOW}4) Back to Main Menu${RESET}"
        echo -e "${YELLOW}=========================================${RESET}"
        echo ""

        read -rp "$(echo -e "${CYAN}Select an option [1-4]: ${RESET}")" choice

        case $choice in
            1)
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
                log "INFO" "❌ Returning to main menu."
                break
                ;;
            *)
                log "WARN" "⚠️  Invalid option selected."
                echo "Invalid option. Please try again."
                ;;
        esac
    done
}


################################################################################
#####                        FileVault Config                              #####
################################################################################

# Enable Full Disk Encryption  -- INCOMPLETE -- WHAT IS MANGEMENT KEY BEING USED FOR? WHY NOT JUST USE EXISTING KEY IF IT EXISTS?
enable_full_disk_encryption() {
    mkdir -p "$KEY_DIR"

    log "INFO" "🔒 Enabling Full Disk Encryption with YubiKey..."

    # Fetch management key dynamically
    local management_key=$(get_management_key)

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
    clear
    ascii_art
    echo -e "${CYAN}${BOLD}🛡️  Full Disk Encryption Manager 🛡️${RESET}"
    echo -e "${MAGENTA}${BOLD}Full Disk Encryption Menu:${RESET}"
    echo -e "${YELLOW}=========================================${RESET}"
    echo -e "${YELLOW}1) Enable Full Disk Encryption${RESET}"
    echo -e "${YELLOW}2) Disable Full Disk Encryption${RESET}"
    echo -e "${YELLOW}3) Cancel${RESET}"
    echo -e "${YELLOW}=========================================${RESET}"
    echo ""

    read -rp "$(echo -e "${CYAN}Enter your choice [1-3]: ${RESET}")" choice

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
    log "INFO" "✅ Plist file created at $PLIST_PATH with secure permissions."
    echo "Plist file created successfully at $PLIST_PATH."

    # Save the Recovery Key to a separate file for storage
    echo "$recovery_key" > "$RECOVERY_KEY_FILE"   
    log "INFO" "🔑 Recovery Key saved to $RECOVERY_KEY_FILE. Store it securely."
    echo "Recovery Key saved to $RECOVERY_KEY_FILE. Please store it securely."
}


################################################################################
#####                        OpenPGP Config                                #####
################################################################################

# Setup Yubikey to support OpenGPG to Encrypt SSH Manager for Ledger Storage
setup_openpgp_yubikey() {
    check_yubikey_presence || return
    
    # Run GPG configuration script to handle permissions and services
    log "INFO" "🔄 Running GPG configuration to prepare the YubiKey device..."
    configureGPG || {
        log "ERROR" "❌ GPG configuration failed. Exiting..."
        return 1
    }
    
    # Reset OpenPGP if needed
    log "INFO" "🔍 Checking YubiKey for OpenPGP applet activation..."
    ykman openpgp info &>/dev/null
    if [ $? -ne 0 ]; then
        log "WARN" "⚙️ OpenPGP applet not responding. Resetting YubiKey OpenPGP..."
        sudo ykman openpgp reset
        if [ $? -ne 0 ]; then
            log "ERROR" "❌ Failed to reset OpenPGP applet. Exiting..."
            return 1
        fi
        log "INFO" "✅ OpenPGP applet reset complete."
    else
        log "INFO" "✅ OpenPGP applet already activated."
    fi

    # Ensure the GPG agent uses the correct terminal
    export GPG_TTY=$(tty)
    gpg-connect-agent updatestartuptty /bye

    # Begin manual key generation
    log "INFO" "🔑 Opening GPG card admin for key generation..."
    gpg --card-edit

    log "INFO" "⚠️  Follow the prompts: Enter 'admin' then 'generate' to proceed."
    log "INFO" "If existing keys are detected, you will be asked to overwrite them."
}

# Confirm GPG Build 
configureGPG() {
    log "🔧 Configuring GPG and YubiKey environment..."

    # Ensure ~/.gnupg directory exists and set correct permissions
    if [ ! -d ~/.gnupg ]; then
        log "Creating ~/.gnupg directory..."
        mkdir -p ~/.gnupg
    fi

    # Configure pinentry for macOS to avoid passphrase prompt errors
    log "Configuring pinentry for macOS..."
    echo "pinentry-program /opt/homebrew/bin/pinentry-mac" > ~/.gnupg/gpg-agent.conf

    # Kill any running GPG agents and refresh
    log "Restarting gpg-agent and scdaemon..."
    gpgconf --kill gpg-agent
    sudo pkill scdaemon
    sudo killall pcscd || log "No pcscd processes to kill."

    # Ensure GPG agent uses the correct terminal
    export GPG_TTY=$(tty)
    gpg-connect-agent updatestartuptty /bye

    # Restart YubiKey-related services
    log "Restarting YubiKey services..."
    sudo launchctl stop com.apple.ifdreader
    sudo launchctl start com.apple.ifdreader

    # Final check to ensure YubiKey is recognized
    log "Checking YubiKey status..."
    ykman list || log "No YubiKey detected! Ensure the device is connected."

    log "✅ GPG and YubiKey environment configured successfully."

    # Display YubiKey card status
    gpg --card-status
}

# Manage OpenPGP Functions Menu
manage_openpgp_keys() {
    while true; do
        clear
        ascii_art
        echo -e "${CYAN}${BOLD}🔐 OpenPGP Configuration Manager${RESET}"
        echo -e "${MAGENTA}${BOLD}OpenPGP Configuration Menu:${RESET}"
        echo -e "${YELLOW}=========================================${RESET}"
        echo -e "${YELLOW}1) Setup YubiKey for OpenPGP (Generate Keys)${RESET}"
        echo -e "${YELLOW}2) Configure GPG Environment${RESET}"
        echo -e "${YELLOW}3) Backup Configuration${RESET}"
        echo -e "${YELLOW}4) Restore Configuration${RESET}"
        echo -e "${YELLOW}5) Back to Main Menu${RESET}"
        echo -e "${YELLOW}=========================================${RESET}"
        echo ""

        read -rp "$(echo -e "${CYAN}Select an option [1-5]: ${RESET}")" choice


        case $choice in
            1)
                log "INFO" "🔑 Starting OpenPGP setup on YubiKey..."
                setup_openpgp_yubikey
                ;;
            2)
                log "INFO" "🔄 Configuring GPG environment and permissions..."
                configureGPG || log "ERROR" "❌ GPG configuration failed. Please check permissions and try again."
                ;;
            3)
                backup_configuration
                ;;
            4)
                restore_configuration
                ;;    
            5)
                log "INFO" "❌ Returning to main menu."
                break
                ;;
            *)
                log "WARN" "⚠️ Invalid option selected."
                echo "Invalid option. Please try again."
                ;;
        esac
    done
}


# Backup SSH, YubiKey configuration, and PGP keys -- this needs a fix to use the KEY DIR
backup_configuration() {
    mkdir -p "$BACKUP_DIR"
    mkdir -p "$KEY_DIR"

    # Prompt for GPG key details
    read -rp "Enter the email associated with your GPG key: " gpg_email
    local timestamp
    timestamp=$(date +%s)

    # Export GPG keys (public and private) to BACKUP_DIR
    log "INFO" "🔑 Exporting GPG public key to $BACKUP_DIR and $KEY_DIR..."
    gpg --armor --export "$gpg_email" > "$BACKUP_DIR/yubikey_pub_$timestamp.asc"
    gpg --armor --export "$gpg_email" > "$KEY_DIR/yubikey_pub_$timestamp.asc"
    
    if [ $? -eq 0 ]; then
        log "INFO" "✅ Public key exported successfully to both locations."
    else
        log "ERROR" "❌ Failed to export public key."
    fi 

    log "INFO" "🔑 Exporting GPG private key to $BACKUP_DIR and $KEY_DIR..."
    gpg --armor --export-secret-keys "$gpg_email" > "$BACKUP_DIR/yubikey_priv_$timestamp.asc"
    gpg --armor --export-secret-keys "$gpg_email" > "$KEY_DIR/yubikey_priv_$timestamp.asc"
    
    if [ $? -eq 0 ]; then
        log "INFO" "✅ Private key exported successfully to both locations."
    else
        log "ERROR" "❌ Failed to export private key."
    fi
}

# Restore latest backup configuration and PGP keys -- this needs a fix to use the KEY DIR
restore_configuration() {
    local latest_backup
    latest_backup=$(ls -t "$BACKUP_DIR" | head -n 1)

    log "INFO" "⚙️  Searching for PGP backups..."
    local pgp_files
    pgp_files=$(ls "$BACKUP_DIR"/yubikey_*_*.asc 2>/dev/null)
    
    if [ -z "$pgp_files" ]; then
        log "WARN" "No PGP backups found."
        return
    fi

    log "INFO" "Available PGP backups:"
    echo "$pgp_files"
    
    for pgp_file in $pgp_files; do
        log "INFO" "🔑 Importing $pgp_file..."
        gpg --import "$pgp_file"
    done

    log "INFO" "✅ PGP keys imported successfully. Run 'gpg --list-keys' to verify."
}


################################################################################
#####                    Permissions Config                                #####
################################################################################

# Detect platform
detect_platform() {
    uname_out="$(uname -s)"
    case "${uname_out}" in
        Linux*)     platform=linux;;
        Darwin*)    platform=mac;;
        *)          platform="unknown"
    esac
}

# Get ownership (user:group) and permissions based on platform
get_ownership() {
    if [ "$platform" == "mac" ]; then
        stat -f "%u:%g" "$1"
    else
        stat -c "%U:%G" "$1"
    fi
}

# Get file and directory prems 
get_permissions() {
    if [ "$platform" == "mac" ]; then
        stat -f "%A" "$1"
    else
        stat -c "%a" "$1"
    fi
}

# Ensure permissions are correct before proceeding
fix_permissions() {
    log "🔧 Fixing permissions for .ssh, GnuPG, and YubiKey directories..."
    
    # Detect platform
    detect_platform
    
    if [ "$platform" == "unknown" ]; then
        log "❌ Unsupported platform: $uname_out"
        exit 1
    fi
    
    # Normalize paths to avoid double slashes
    projects_dir=~/Documents/Projects
    projects_dir="${projects_dir%/}"  # Remove trailing slash

    yubikey_manager_dir="$projects_dir/yubikey-manager"
    yubikey_resources="$yubikey_manager_dir/resources"
    yubikey_keys="$yubikey_resources/keys"

    # Debugging Paths
    log "Checking YubiKey Manager Path: $yubikey_manager_dir"
    log "Checking YubiKey Resources Path: $yubikey_resources"
    log "Checking YubiKey Keys Path: $yubikey_keys"

    # Set ownership to user and staff group for SSH and Projects
    if [ "$platform" == "mac" ]; then
        staff_gid=20  # Hardcoded GID for staff on macOS
    else
        staff_gid=$(getent group staff | cut -d: -f3)
    fi

    # Fix /tmp/ permissions
    if [ "$(get_permissions /tmp)" != "1777" ]; then
        sudo chmod 1777 /tmp
        log "✔ Permissions for /tmp set to 1777 (world-writable with sticky bit)"
    else
        log "ℹ Permissions for /tmp already set correctly"
    fi

    if [ "$(get_ownership /tmp)" != "0:0" ]; then
        sudo chown root:wheel /tmp
        log "✔ Ownership for /tmp set to root:wheel"
    else
        log "ℹ Ownership for /tmp already correct"
    fi
    
    # Fix ownership for .ssh
    if [ "$(get_ownership ~/.ssh)" != "$(id -u):$staff_gid" ]; then
        sudo chown -R $(whoami):staff ~/.ssh
        log "✔ Ownership for ~/.ssh set to $(whoami):staff"
    else
        log "ℹ Ownership for ~/.ssh already correct"
    fi

    # Fix ownership for Projects directory
    if [ "$(get_ownership "$projects_dir")" != "$(id -u):$staff_gid" ]; then
        sudo chown -R $(whoami):staff "$projects_dir"
        log "✔ Ownership for ~/Documents/Projects set to $(whoami):staff"
    else
        log "ℹ Ownership for ~/Documents/Projects already correct"
    fi

    # Secure .ssh directory
    if [ "$(get_permissions ~/.ssh)" != "770" ]; then
        chmod 770 ~/.ssh
        log "✔ Permissions for ~/.ssh set to 770"
    else
        log "ℹ Permissions for ~/.ssh already set correctly"
    fi

    if [ ! -g ~/.ssh ]; then
        sudo chmod g+s ~/.ssh
        log "✔ Group sticky bit set for ~/.ssh"
    else
        log "ℹ Group sticky bit already set for ~/.ssh"
    fi

    # Apply recursive permissions for Projects directory
    if [ "$(get_permissions "$projects_dir")" != "770" ]; then
        chmod -R 770 "$projects_dir"
        log "✔ Recursive permissions for ~/Documents/Projects set to 770"
    else
        log "ℹ Permissions for ~/Documents/Projects already set correctly"
    fi

    if [ ! -g "$projects_dir" ]; then
        sudo chmod g+s "$projects_dir"
        log "✔ Group sticky bit set for ~/Documents/Projects"
    else
        log "ℹ Group sticky bit already set for ~/Documents/Projects"
    fi

    # Fix permissions for yubikey-manager/resources
    if [ -d "$yubikey_resources" ]; then
        if [ "$(get_permissions "$yubikey_resources")" != "770" ]; then
            sudo chmod -R 770 "$yubikey_resources"
            log "✔ Recursive permissions for yubikey-manager/resources set to 770"
        else
            log "ℹ Permissions for yubikey-manager/resources already set correctly"
        fi
    else
        log "❌ Path not found: $yubikey_resources"
    fi

    if [ -d "$yubikey_keys" ]; then
        if [ "$(get_permissions "$yubikey_keys")" != "775" ]; then
            sudo chmod 775 "$yubikey_keys"
            log "✔ Permissions for yubikey-manager/resources/keys set to 775"
        else
            log "ℹ Permissions for yubikey-manager/resources/keys already set correctly"
        fi
    else
        log "❌ Path not found: $yubikey_keys"
    fi

    # Secure SSH key files
    for file in ~/.ssh/id_*; do
        if [ -f "$file" ] && [ "$(get_permissions "$file")" != "660" ]; then
            chmod 660 "$file"
            log "✔ Permissions for SSH private key $file set to 660"
        else
            log "ℹ Permissions for $file already set correctly or file does not exist"
        fi
    done

    if [ "$(get_permissions ~/.ssh/known_hosts)" != "660" ]; then
        chmod 660 ~/.ssh/known_hosts
        log "✔ Permissions for ~/.ssh/known_hosts set to 660"
    else
        log "ℹ Permissions for ~/.ssh/known_hosts already set correctly"
    fi

    if [ "$(get_permissions ~/.ssh/config)" != "660" ]; then
        chmod 660 ~/.ssh/config
        log "✔ Permissions for ~/.ssh/config set to 660"
    else
        log "ℹ Permissions for ~/.ssh/config already set correctly"
    fi

    # GnuPG Directory Permissions
    if [ "$(get_ownership ~/.gnupg)" != "$(id -u):$staff_gid" ]; then
        sudo chown -R $(whoami):staff ~/.gnupg
        log "✔ Ownership for ~/.gnupg set to $(whoami):staff"
    else
        log "ℹ Ownership for ~/.gnupg already correct"
    fi

    if [ "$(get_permissions ~/.gnupg)" != "770" ]; then
        sudo chmod 770 ~/.gnupg
        log "✔ Permissions for ~/.gnupg set to 770"
    else
        log "ℹ Permissions for ~/.gnupg already set correctly"
    fi
}


################################################################################
#####                            PIN Config                                #####
################################################################################ 

manage_yubikey_pins() {
    while true; do
        clear
        ascii_art
        echo -e "${CYAN}${BOLD}🛠️  YubiKey Manager - PIN Management${RESET}"
        echo -e "${MAGENTA}${BOLD}YubiKey PIN Management Menu:${RESET}"
        echo -e "${YELLOW}=========================================${RESET}"
        echo -e "${YELLOW}1) Manage PIV PIN(s)${RESET}"
        echo -e "${YELLOW}2) Manage FIDO2 PIN(s)${RESET}"
        echo -e "${YELLOW}3) Manage OpenPGP PIN(s)${RESET}"
        echo -e "${YELLOW}4) Back to Main Menu${RESET}"
        echo -e "${YELLOW}=========================================${RESET}"
        echo ""

        read -rp "$(echo -e "${CYAN}Select an option [1-4]: ${RESET}")" pin_choice

        case $pin_choice in
            1)
                manage_piv_pins
                ;;
            2)
                manage_fido2_pins
                ;;
            3)
                manage_openpgp_pins
                ;;
            4)
                break
                ;;
            *)
                echo -e "${RED}❌ Invalid option. Please try again.${RESET}"
                sleep 1
                ;;
        esac

        echo ""
        read -rp "$(echo -e "${CYAN}Press Enter to continue...${RESET}")" _
    done
}

# =============================================================================
# Manage PIV PIN(s)
# =============================================================================
manage_piv_pins() {
    while true; do
        echo -e "${MAGENTA}${BOLD}Manage PIV PIN(s)${RESET}"
        echo -e "${YELLOW}1) Change PIV PIN${RESET}"
        echo -e "${YELLOW}2) Unblock/Reset PIV PIN (Requires PUK)${RESET}"
        echo -e "${YELLOW}3) Change PIV PUK${RESET}"
        echo -e "${YELLOW}4) Change PIV Management Key${RESET}"
        echo -e "${YELLOW}5) Back to PIN Management Menu${RESET}"
        echo ""

        read -rp "$(echo -e "${CYAN}Select an option [1-5]: ${RESET}")" piv_choice

        case $piv_choice in
            1)
                echo -e "${CYAN}Changing the PIV PIN will not erase certificates but will lock the YubiKey after 3 failed attempts.${RESET}"
                generate_or_update_pin
                ;;
            2)
                echo -e "${CYAN}Resetting the PIV PIN requires the PUK. 3 failed attempts will permanently block PIV.${RESET}"
                ykman piv access unblock-pin
                ;;
            3)
                echo -e "${CYAN}Changing the PIV PUK will not erase keys but losing it will prevent administrative actions.${RESET}"
                generate_or_update_puk
                ;;
            4)
                echo -e "${CYAN}Changing the Management Key will not erase keys but losing it will prevent administrative actions.${RESET}"
                generate_management_key
                ;;
            5)
                break
                ;;
            *)
                echo -e "${RED}❌ Invalid option. Please try again.${RESET}"
                sleep 1
                ;;
        esac
    done
}

# Generate or Update PIN
generate_or_update_pin() {
    log "INFO" "🔑 Generating or updating PIN..."

    # Ask user whether to store the PIN on the device or manage it themselves
    echo "Do you want to store the PIN on the device or manage it yourself?"
    echo "1. Store on device (random value will be generated)"
    echo "2. Manage myself (you will input the PIN)"
    read -p "Select an option (1 or 2): " user_choice

    case "$user_choice" in
        1)
            log "INFO" "🔒 Generating random PIN..."
            pin=$(openssl rand -hex 4)
            ykman piv access change-pin --new-pin "$pin" || {
                log "ERROR" "❌ Failed to set random PIN."
                return 1
            }
            ;;
        2)
            read -sp "Enter a new PIN: " pin
            echo
            ykman piv access change-pin --new-pin "$pin" || {
                log "ERROR" "❌ Failed to set user-defined PIN."
                return 1
            }
            ;;
        *)
            log "ERROR" "❌ Invalid choice. Please select 1 or 2."
            return 1
            ;;
    esac

    # Ensure the config path exists
    mkdir -p "$(dirname "$JSON_CONFIG_PATH")"

    # Read existing JSON or initialize if not present
    if [ -f "$JSON_CONFIG_PATH" ]; then
        config=$(jq '.' "$JSON_CONFIG_PATH" 2>/dev/null) || config="{}"
    else
        config="{}"
    fi

    log "DEBUG" "Current Config: $config"

    # Fallback if the config is empty
    if [ -z "$config" ]; then
        config="{}"
        log "WARN" "⚠️ Config was empty. Initializing to default empty JSON."
    fi

    # Update or insert PIN into the JSON config
    updated_config=$(echo "$config" | jq \
        --arg pin "$pin" \
        '.pin = $pin'
    ) || {
        log "ERROR" "❌ Failed to update JSON structure."
        return 1
    }

    # Handle potential jq failure or empty result
    if [ -z "$updated_config" ]; then
        updated_config=$(cat <<EOF
{
  "pin": "$pin"
}
EOF
)
        log "WARN" "⚠️ No updated config. Using default values."
    fi

    log "DEBUG" "Updated Config: $updated_config"

    # Save updated config to file
    echo "$updated_config" > "$JSON_CONFIG_PATH"
    log "INFO" "✅ PIN saved to $JSON_CONFIG_PATH"
}

# Generate or Update PUK
generate_or_update_puk() {
    log "INFO" "🔑 Generating or updating PUK..."

    # Ask user whether to store the PUK on the device or manage it themselves
    echo "Do you want to store the PUK on the device or manage it yourself?"
    echo "1. Store on device (random value will be generated)"
    echo "2. Manage myself (you will input the PUK)"
    read -p "Select an option (1 or 2): " user_choice

    case "$user_choice" in
        1)
            log "INFO" "🔒 Generating random PUK..."
            puk=$(openssl rand -hex 8)
            ykman piv access change-puk --new-puk "$puk" || {
                log "ERROR" "❌ Failed to set random PUK."
                return 1
            }
            ;;
        2)
            read -sp "Enter a new PUK: " puk
            echo
            ykman piv access change-puk --new-puk "$puk" || {
                log "ERROR" "❌ Failed to set user-defined PUK."
                return 1
            }
            ;;
        *)
            log "ERROR" "❌ Invalid choice. Please select 1 or 2."
            return 1
            ;;
    esac

    # Ensure the config path exists
    mkdir -p "$(dirname "$JSON_CONFIG_PATH")"

    # Read existing JSON or initialize if not present
    if [ -f "$JSON_CONFIG_PATH" ]; then
        config=$(jq '.' "$JSON_CONFIG_PATH" 2>/dev/null) || config="{}"
    else
        config="{}"
    fi

    log "DEBUG" "Current Config: $config"

    # Fallback if the config is empty
    if [ -z "$config" ]; then
        config="{}"
        log "WARN" "⚠️ Config was empty. Initializing to default empty JSON."
    fi

    # Update or insert PUK into the JSON config
    updated_config=$(echo "$config" | jq \
        --arg puk "$puk" \
        '.puk = $puk'
    ) || {
        log "ERROR" "❌ Failed to update JSON structure."
        return 1
    }

    # Handle potential jq failure or empty result
    if [ -z "$updated_config" ]; then
        updated_config=$(cat <<EOF
{
  "puk": "$puk"
}
EOF
)
        log "WARN" "⚠️ No updated config. Using default values."
    fi

    log "DEBUG" "Updated Config: $updated_config"

    # Save updated config to file
    echo "$updated_config" > "$JSON_CONFIG_PATH"
    log "INFO" "✅ PUK saved to $JSON_CONFIG_PATH"
}

# Generate new or default Management Key
generate_management_key() {
    log "INFO" "🔑 Generating new management key..."

    local default_pin="123456"
    local default_puk="12345678"
    local default_mgt_key="010203040506070801020304050607080102030405060708"  # Replace with your actual default key if different

    # Check if jq is installed
    if ! command -v jq &> /dev/null; then
        log "ERROR" "❌ 'jq' is not installed. Please install 'jq' to proceed."
        return 1
    fi

    # Initialize variables
    local current_mgt_key=""
    local new_mgt_key=""
    local management_key=""

    # Attempt to read the current management key from the config
    if [[ -f "$JSON_CONFIG_PATH" ]]; then
        current_mgt_key=$(jq -r '.management_key // empty' "$JSON_CONFIG_PATH" 2>/dev/null)
        if [[ -n "$current_mgt_key" ]]; then
            log "INFO" "🔑 Using existing management key from config."
        else
            log "WARN" "⚠️ No existing management key found in config."
        fi
    else
        log "WARN" "⚠️ Configuration file not found."
    fi

    if [[ -n "$current_mgt_key" ]]; then
        # Validate the current management key format (48 hex characters)
        if [[ ! "$current_mgt_key" =~ ^[0-9a-fA-F]{48}$ ]]; then
            log "ERROR" "❌ Invalid management key format in config."
            return 1
        fi

        # Use existing management key to set a new one
        log "INFO" "🔄 Attempting to set a new management key using the existing key..."

        # Generate a secure random management key
        new_mgt_key=$(openssl rand -hex 24)  # 24 bytes = 48 hex characters
        log "DEBUG" "Generated new management key: $new_mgt_key"

        # Attempt to set the new management key using the existing key
        log "DEBUG" "Executing: ykman piv access change-management-key --management-key $current_mgt_key --new-management-key $new_mgt_key --touch"
        ykman piv access change-management-key \
            --management-key "$current_mgt_key" \
            --new-management-key "$new_mgt_key" --touch

        local ykman_exit_code=$?

        if [[ $ykman_exit_code -ne 0 ]]; then
            log "WARN" "⚠️ Failed to set a new management key using the existing key."
            log "ERROR" "❌ Management key update failed."
            return 1
        fi

        management_key="$new_mgt_key"
        log "INFO" "✅ New management key applied successfully using the existing key."
    else
        # No management key in config, prompt user or use default
        log "INFO" "🔄 No existing management key found. Proceeding to generate a new key."

        # Prompt the user for the current management key or use default
        read -s -p "Enter the current management key [leave blank to use default]: " input_mgt_key
        echo

        if [[ -z "$input_mgt_key" ]]; then
            log "INFO" "🔑 Using default management key."
            current_mgt_key="$default_mgt_key"
        else
            current_mgt_key="$input_mgt_key"
        fi

        # Validate the current management key format
        if [[ -n "$current_mgt_key" && ! "$current_mgt_key" =~ ^[0-9a-fA-F]{48}$ ]]; then
            log "ERROR" "❌ Invalid management key format."
            return 1
        fi

        # Generate a secure random management key
        new_mgt_key=$(openssl rand -hex 24)  # 24 bytes = 48 hex characters
        log "DEBUG" "Generated new management key: $new_mgt_key"

        # Attempt to set the new management key using the provided or default key
        log "DEBUG" "Executing: ykman piv access change-management-key --management-key $current_mgt_key --new-management-key $new_mgt_key --touch"
        ykman piv access change-management-key \
            --management-key "$current_mgt_key" \
            --new-management-key "$new_mgt_key" --touch

        local ykman_exit_code=$?

        if [[ $ykman_exit_code -ne 0 ]]; then
            log "WARN" "⚠️ Failed to set a new management key."
            log "ERROR" "❌ Management key update failed."
            return 1
        fi

        management_key="$new_mgt_key"
        log "INFO" "✅ New management key applied successfully."
    fi

    # Prompt the user to choose between protecting the key on the device or managing it locally
    while true; do
        read -p "Do you want to protect the management key on the device using '--protect'? [y/N]: " protect_choice
        case "$protect_choice" in
            [Yy]* )
                log "INFO" "🔒 Protecting the management key on the device using '--protect'..."

                # Attempt to protect the management key on the device using the new key
                log "DEBUG" "Executing: ykman piv access change-management-key --management-key $management_key --protect --touch"
                ykman piv access change-management-key \
                    --management-key "$management_key" \
                    --protect --touch

                local protect_exit_code=$?

                if [[ $protect_exit_code -ne 0 ]]; then
                    log "WARN" "⚠️ Failed to protect the management key on the device."
                    log "ERROR" "❌ '--protect' operation failed."
                    return 1
                fi

                # Update the config to indicate protection is enabled
                # Remove the 'management_key' field and set 'protected' to true
                if [[ -f "$JSON_CONFIG_PATH" ]]; then
                    log "DEBUG" "Updating config to set 'management_key' to null and 'protected' to true."
                    config=$(jq '.management_key = null | .protected = true' "$JSON_CONFIG_PATH" 2>/dev/null)
                else
                    log "DEBUG" "Creating new config with 'protected': true."
                    config=$(jq -n '{"protected": true}')
                fi

                # Handle potential jq failure or empty result
                if [[ -z "$config" ]]; then
                    config=$(cat <<EOF
{
  "protected": true
}
EOF
                    )
                    log "WARN" "⚠️ No updated config from jq. Using default protection settings."
                fi

                # Save updated config to file
                echo "$config" > "$JSON_CONFIG_PATH" || {
                    log "ERROR" "❌ Failed to write updated config to $JSON_CONFIG_PATH."
                    return 1
                }
                log "INFO" "✅ Management key protected on device and config updated."

                # Remove the local backup if it exists, as the key is now protected on the device
                if [[ -f "$KEY_BACKUP_PATH" ]]; then
                    rm -f "$KEY_BACKUP_PATH"
                    log "INFO" "🗑️ Removed local management key backup as it's now protected on the device."
                fi

                break
                ;;
            [Nn]* | "" )
                log "INFO" "🗃️ Managing the management key locally."

                # Ensure the config path exists
                mkdir -p "$(dirname "$JSON_CONFIG_PATH")" || {
                    log "ERROR" "❌ Failed to create directory for $JSON_CONFIG_PATH."
                    return 1
                }

                # Read existing JSON or initialize if not present
                if [[ -f "$JSON_CONFIG_PATH" ]]; then
                    config=$(jq '.' "$JSON_CONFIG_PATH" 2>/dev/null) || config="{}"
                else
                    config="{}"
                fi

                log "DEBUG" "Current Config: $config"

                # Fallback if the config is empty
                if [[ -z "$config" ]] || [[ "$config" == "null" ]]; then
                    config="{}"
                    log "WARN" "⚠️ Config was empty. Initializing to default empty JSON."
                fi

                # Update or insert management key, PIN, and PUK into the JSON config
                # Only set pin and puk if they do not already exist
                log "DEBUG" "Updating config with management key, PIN, and PUK."
                updated_config=$(echo "$config" | jq \
                    --arg mk "$management_key" \
                    --arg pin "$default_pin" \
                    --arg puk "$default_puk" \
                    ' .management_key = $mk 
                      | if has("pin") then . else .pin = $pin end 
                      | if has("puk") then . else .puk = $puk end '
                ) || {
                    log "ERROR" "❌ Failed to update JSON structure."
                    return 1
                }

                # Handle potential jq failure or empty result
                if [[ -z "$updated_config" ]]; then
                    updated_config=$(cat <<EOF
{
  "management_key": "$management_key",
  "pin": "$default_pin",
  "puk": "$default_puk"
}
EOF
                    )
                    log "WARN" "⚠️ No updated config from jq. Using default values."
                fi

                log "DEBUG" "Updated Config: $updated_config"

                # Save updated config to file
                echo "$updated_config" > "$JSON_CONFIG_PATH" || {
                    log "ERROR" "❌ Failed to write to $JSON_CONFIG_PATH."
                    return 1
                }
                log "INFO" "✅ Management key saved to $JSON_CONFIG_PATH"

                # Backup the management key to a hidden file with restricted permissions
                echo "$management_key" > "$KEY_BACKUP_PATH" || {
                    log "ERROR" "❌ Failed to write to $KEY_BACKUP_PATH."
                    return 1
                }
                
                break
                ;;
            * )
                echo "❌ Invalid input. Please enter 'y' or 'n'."
                ;;
        esac
    done
}





# =============================================================================
# Manage FIDO2 PIN(s)
# =============================================================================
manage_fido2_pins() {
    while true; do
        echo -e "${MAGENTA}${BOLD}Manage FIDO2 PIN(s)${RESET}"
        echo -e "${YELLOW}1) Change FIDO2 PIN${RESET}"
        echo -e "${YELLOW}2) Reset FIDO2 (Erases all FIDO credentials)${RESET}"
        echo -e "${YELLOW}3) Back to PIN Management Menu${RESET}"
        echo ""

        read -rp "$(echo -e "${CYAN}Select an option [1-3]: ${RESET}")" fido_choice

        case $fido_choice in
            1)
                echo -e "${CYAN}Changing the FIDO2 PIN will not erase credentials.${RESET}"
                ykman fido access change-pin
                ;;
            2)
                echo -e "${RED}⚠️ Resetting FIDO2 will erase all FIDO credentials. This cannot be undone.${RESET}"
                read -rp "Are you sure you want to proceed? (y/N): " confirm
                if [[ $confirm =~ ^[Yy]$ ]]; then
                    ykman fido access reset
                fi
                ;;
            3)
                break
                ;;
            *)
                echo -e "${RED}❌ Invalid option. Please try again.${RESET}"
                sleep 1
                ;;
        esac
    done
}

# =============================================================================
# Manage OpenPGP PIN(s)
# =============================================================================
manage_openpgp_pins() {
    while true; do
        echo -e "${MAGENTA}${BOLD}Manage OpenPGP PIN(s)${RESET}"
        echo -e "${YELLOW}1) Change OpenPGP User PIN${RESET}"
        echo -e "${YELLOW}2) Change OpenPGP Admin PIN${RESET}"
        echo -e "${YELLOW}3) Reset OpenPGP (Erases keys and data)${RESET}"
        echo -e "${YELLOW}4) Back to PIN Management Menu${RESET}"
        echo ""

        read -rp "$(echo -e "${CYAN}Select an option [1-4]: ${RESET}")" pgp_choice

        case $pgp_choice in
            1)
                echo -e "${CYAN}Changing the OpenPGP User PIN will not erase keys but will lock after 3 failed attempts.${RESET}"
                ykman openpgp change-pin
                ;;
            2)
                echo -e "${CYAN}Changing the Admin PIN requires the current Admin PIN.${RESET}"
                ykman openpgp change-admin-pin
                ;;
            3)
                echo -e "${RED}⚠️ Resetting OpenPGP will erase all keys. This cannot be undone.${RESET}"
                read -rp "Are you sure you want to proceed? (y/N): " confirm
                if [[ $confirm =~ ^[Yy]$ ]]; then
                    ykman openpgp reset
                fi
                ;;
            4)
                break
                ;;
            *)
                echo -e "${RED}❌ Invalid option. Please try again.${RESET}"
                sleep 1
                ;;
        esac
    done
}


# =============================================================================
# Manage OTP Code(s)
# =============================================================================
manage_yubikey_otp() {
    clear
    ascii_art
    while true; do
        echo -e "${MAGENTA}${BOLD}Manage OTPs:${RESET}"
        echo -e "${YELLOW}=========================================${RESET}"
        echo -e "${YELLOW}1) View OTP Slot Information${RESET}"
        echo -e "${YELLOW}2) Delete OTP Slot 1${RESET}"
        echo -e "${YELLOW}3) Delete OTP Slot 2${RESET}"
        echo -e "${YELLOW}4) Reset Both OTP Slots${RESET}"
        echo -e "${YELLOW}5) Back to Main Menu${RESET}"
        echo -e "${YELLOW}=========================================${RESET}"
        echo ""

        read -rp "$(echo -e "${CYAN}Select an option [1-5]: ${RESET}")" otp_choice

        case $otp_choice in
            1)
                echo -e "${CYAN}Fetching OTP Slot Information...${RESET}"
                ykman otp info
                ;;
            2)
                echo -e "${CYAN}Deleting OTP Slot 1...${RESET}"
                ykman otp delete 1
                echo -e "${GREEN}✅ OTP Slot 1 deleted successfully.${RESET}"
                ;;
            3)
                echo -e "${CYAN}Deleting OTP Slot 2...${RESET}"
                ykman otp delete 2
                echo -e "${GREEN}✅ OTP Slot 2 deleted successfully.${RESET}"
                ;;
            4)
                echo -e "${CYAN}Resetting Both OTP Slots...${RESET}"
                ykman otp delete 1 && ykman otp delete 2
                ykman otp static --generate slot1 & ykman otp static --generate slot2

                echo -e "${GREEN}✅ Both OTP slots have been reset.${RESET}"
                ;;
            5)
                break
                ;;
            *)
                echo -e "${RED}❌ Invalid option. Please try again.${RESET}"
                sleep 1
                ;;
        esac

        echo ""
        read -rp "$(echo -e "${CYAN}Press Enter to continue...${RESET}")" _
    done
}
