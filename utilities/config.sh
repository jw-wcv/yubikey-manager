#!/bin/bash

# =============================================================================
# Load Utilities and Environment
# =============================================================================
# Dynamically load all utility scripts and environment variables
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/utilities/loader.sh"


################################################################################
#####                            General Config                            #####
################################################################################

# Check if YubiKey is detected
check_yubikey_presence() {
    ykman piv info &>/dev/null
    if [ $? -ne 0 ]; then
        log "ERROR" "No YubiKey detected. Please insert your YubiKey and try again."
        return 1
    fi
    return 0
}

# Generate new or default MGT Key
generate_management_key() {
    log "INFO" "🔑 Generating new management key..."
    
    local default_pin="123456"
    local default_puk="12345678"

    # Generate management key and cleanly extract it
    management_key=$(ykman piv access change-management-key --generate --touch 2>&1 | awk '/Generated management key:/ {print $4}')
    
    # Fallback in case generation fails
    if [[ -z "$management_key" ]]; then
        log "ERROR" "❌ Management key generation failed. Using default key..."
        management_key="010203040506070801020304050607080102030405060708"
        
        ykman piv access change-management-key \
            --management-key "$management_key" \
            --new-management-key "$management_key" --touch || {
                log "WARN" "⚠️ Failed to set default management key."
                return 1
            }
        log "INFO" "✅ Default management key applied."
    fi

    log "INFO" "✅ New management key: $management_key"

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

    # Update or insert management key, PIN, and PUK into the JSON config
    updated_config=$(echo "$config" | jq \
        --arg mk "$management_key" \
        --arg pin "$default_pin" \
        --arg puk "$default_puk" \
        '.management_key = $mk | .pin = $pin | .puk = $puk'
    ) || {
        log "ERROR" "❌ Failed to update JSON structure."
        return 1
    }

    # Handle potential jq failure or empty result
    if [ -z "$updated_config" ]; then
        updated_config=$(cat <<EOF
{
  "management_key": "$management_key",
  "pin": "$default_pin",
  "puk": "$default_puk"
}
EOF
)
        log "WARN" "⚠️ No updated config. Using default values."
    fi

    log "DEBUG" "Updated Config: $updated_config"

    # Save updated config to file
    echo "$updated_config" > "$JSON_CONFIG_PATH"
    log "INFO" "✅ Management key, PIN, and PUK saved to $JSON_CONFIG_PATH"

    # Backup the management key to a hidden file
    echo "$management_key" > "$KEY_BACKUP_PATH"
    log "INFO" "✅ Management key backed up to $KEY_BACKUP_PATH"
}



################################################################################
#####                          SSH Config Prep                             #####
################################################################################

# Full SSH Setup for YubiKey (FIDO2-based configuration)
setup_yubikey_for_ssh() {
    check_yubikey_presence || return

    log "INFO" "🔧 Initializing YubiKey SSH configuration..."
    ykman piv access change-pin
    generate_management_key
    log "INFO" "✅ PIN and Management Key Configured"

    # Choose key type to set up
    echo "Select SSH key type to configure with YubiKey:"
    echo "1) FIDO2 (ecdsa-sk)"
    echo "2) Traditional ssh-rsa via PIV"
    echo "3) Both FIDO2 and ssh-rsa"
    read -p "Enter your choice [1-3]: " key_choice

    case $key_choice in
        1)
            setup_fido2_ssh
            ;;
        2)
            setup_rsa_piv_ssh
            ;;
        3)
            generate_fido2_ssh_key
            setup_rsa_piv_ssh
            ;;
        *)
            log "WARN" "Invalid choice. Exiting setup."
            return
            ;;
    esac

    log "INFO" "🎉 YubiKey SSH configuration completed."
}

# Setup FIDO2 SSH Configuration
setup_fido2_ssh() {
    generate_fido2_ssh_key
  #  deploy_fido2_public_key
}

# Setup ssh-rsa via PIV SSH Configuration
setup_rsa_piv_ssh() {
    manage_rsa_keys
  #  deploy_rsa_piv_public_key
}


################################################################################
#####                            Ready Check                               #####
################################################################################

# YubiKey Ready Check and System Configuration
ready_check() {
    log() {
        echo "$(date +'%Y-%m-%d %H:%M:%S') [INFO] - $1"
    }

    log "🔍 Running YubiKey Ready Check..."

    # 1. Check YubiKey JSON Configuration
    if [ ! -f "$JSON_CONFIG_PATH" ] || ! grep -q "management_key" "$JSON_CONFIG_PATH"; then
        log "❌ YubiKey configuration is incomplete or missing."
        echo "Redirecting to YubiKey configuration..."
        setup_yubikey_for_ssh
        return
    else
        log "✅ YubiKey JSON configuration found."
    fi

    # 2. Confirm FIDO/SSH Key (Slot 9a or 9c)
    local fido_key_present
    fido_key_present=$(ykman piv info | grep -E "9a|9c" || echo "not_found")
    
    if [[ "$fido_key_present" == "not_found" ]]; then
        log "⚠️ No SSH or FIDO2 keys found on YubiKey (Slot 9a/9c)."
        echo "Redirecting to SSH/FIDO key setup..."
        setup_yubikey_for_ssh
        return
    else
        log "✅ YubiKey SSH/FIDO key detected."
    fi

    # 3. Ask About Additional Configurations (FileVault, Smart Card, OpenPGP)
    echo "Would you like to configure any of the following services?"
    echo "1) FileVault (macOS Disk Encryption)"
    echo "2) Smart Card Pairing"
    echo "3) OpenPGP Setup"
    echo "4) Configure All"
    echo "5) Skip Additional Configurations"
    read -rp "Select an option [1-5]: " service_choice

    case $service_choice in
        1)
            log "🔒 Configuring FileVault..."
            manage_full_disk_encryption
            ;;
        2)
            log "💳 Managing Smart Cards..."
            configure_smart_cards
            ;;
        3)
            log "🔑 Managing OpenPGP Keys..."
            manage_openpgp_keys
            ;;
        4)
            log "⚙️ Configuring All Services (FileVault, Smart Card, OpenPGP)..."
            manage_full_disk_encryption
            configure_smart_cards
            manage_openpgp_keys
            ;;
        5)
            log "⏩ Skipping additional configurations."
            ;;
        *)
            log "❌ Invalid option. Please choose between 1-5."
            ;;
    esac

    # 4. Final Validation - Ensure Configurations Are Active
    log "🔄 Verifying Configurations..."
    
    # Verify PGP Keys
    gpg --list-keys &>/dev/null
    if [ $? -eq 0 ]; then
        log "✅ OpenPGP keys detected."
    else
        log "❌ No OpenPGP keys found. Run 'manage_openpgp_keys' to generate keys."
    fi

    # Verify Smart Card
    sc_auth identities &>/dev/null
    if [ $? -eq 0 ]; then
        log "✅ Smart Card detected and paired."
    else
        log "❌ No Smart Card paired. Use 'configure_smart_cards' to pair."
    fi

    # Verify FileVault (macOS Specific)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        fdesetup status | grep "FileVault is On" &>/dev/null
        if [ $? -eq 0 ]; then
            log "✅ FileVault is enabled."
        else
            log "❌ FileVault is not enabled. Run 'manage_full_disk_encryption'."
        fi
    fi

    log "🏁 YubiKey Ready Check Complete."
}
