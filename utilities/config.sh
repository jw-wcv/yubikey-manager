#!/bin/bash

# Import general utility functions
source ./general.sh
source ./keys.sh
source ./settings.sh
source ./ssh.sh

backup_dir="$HOME/.yubikey_backups" #ROOT
# ip_config_file="$HOME/.yubikey_ssh_config"
ip_config_file="./resources/data/ipv6_config.json"  # Store in project directory
key_backup_path="/Users/JJ/Documents/Projects/yubikey-manager/resources/keys/.yubikey_management_key"
json_config_path="/Users/JJ/Documents/Projects/yubikey-manager/resources/data/yubi_config.json"


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

# Configure YubiKey for PIV and SSH
configure_yubikey() {
    log "INFO" "🛠 Configuring YubiKey for PIV and SSH..."
    ykman piv reset --force || log "ERROR" "Failed to reset YubiKey"
    ykman piv access set-retries 3 3 || log "WARN" "Failed to set PIN retries"

    generate_management_key || {
        log "ERROR" "Management key generation failed."
        return 1
    }
    
    log "INFO" "✅ YubiKey configured."
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
    mkdir -p "$(dirname "$json_config_path")"

    # Read existing JSON or initialize if not present
    if [ -f "$json_config_path" ]; then
        config=$(jq '.' "$json_config_path" 2>/dev/null) || config="{}"
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
    echo "$updated_config" > "$json_config_path"
    chmod 600 "$json_config_path"
    log "INFO" "✅ Management key, PIN, and PUK saved to $json_config_path"

    # Backup the management key to a hidden file
    echo "$management_key" > "$key_backup_path"
    chmod 600 "$key_backup_path"
    log "INFO" "✅ Management key backed up to $key_backup_path"
}


# Set PIN retries separately for reusability
set_pin_retries() {
    log "INFO" "🔑 Setting PIN retries to 3 attempts..."
    ykman piv set-pin-retries 3 3 3 &>/dev/null || log "WARN" "Failed to set PIN retries"
    spinner
}

# Change YubiKey PIN and PUK
configure_pin() {
    log "INFO" "🔑 Configuring YubiKey PINs..."
    ykman piv access change-pin || log "WARN" "Failed to change PIN"
    ykman piv access change-puk || log "WARN" "Failed to change PUK"
}


################################################################################
#####                            SSH Config                                #####
################################################################################

# Full SSH Setup for YubiKey (FIDO2-based configuration)
setup_yubikey_for_ssh() {
    check_yubikey_presence || return

    log "INFO" "🔧 Initializing YubiKey SSH configuration..."

    configure_pin
    log "INFO" "✅ PIN Configured"

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
            setup_fido2_ssh
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
    deploy_fido2_public_key
    configure_fido2_ssh_config
}

# Setup ssh-rsa via PIV SSH Configuration
setup_rsa_piv_ssh() {
    generate_rsa_piv_key
    deploy_rsa_piv_public_key
    configure_rsa_piv_ssh_config
}

# Configure SSH to Use FIDO2 SSH Key
configure_fido2_ssh_config() {
    local ssh_config="$HOME/.ssh/config"
    local ssh_key="$HOME/.ssh/id_ecdsa_sk"

    log "INFO" "⚙️ Configuring SSH to use FIDO2 SSH key..."

    # Backup existing SSH config
    cp "$ssh_config" "${ssh_config}.backup" 2>/dev/null

    # Check if FIDO2 IdentityFile is already set
    if grep -q "IdentityFile $ssh_key" "$ssh_config"; then
        log "INFO" "✅ SSH config already references the FIDO2 SSH key."
    else
        # Add configuration for FIDO2 key
        cat <<EOL >> "$ssh_config"

# YubiKey FIDO2 SSH Key
Host *
    IdentityFile $ssh_key
    IdentitiesOnly yes
EOL
        log "INFO" "🔧 Added FIDO2 SSH key configuration to SSH config."
    fi
}

# Configure SSH to Use ssh-rsa via PIV
configure_rsa_piv_ssh_config() {
    local ssh_config="$HOME/.ssh/config"
    local ssh_key_pub="$HOME/resources/keys/id_rsa_piv.pub"

    log "INFO" "⚙️ Configuring SSH to use ssh-rsa via PIV..."

    # Backup existing SSH config
    cp "$ssh_config" "${ssh_config}.backup" 2>/dev/null

    # Check if PKCS11Provider is already set
    if grep -q "PKCS11Provider /opt/homebrew/lib/libykcs11.dylib" "$ssh_config"; then
        log "INFO" "✅ PKCS11Provider already configured in SSH config."
    else
        # Add configuration for ssh-rsa via PIV
        cat <<EOL >> "$ssh_config"

# YubiKey ssh-rsa via PIV
Host *
    PKCS11Provider /opt/homebrew/lib/libykcs11.dylib
    IdentitiesOnly yes
EOL
        log "INFO" "🔧 Added PKCS11Provider configuration to SSH config."
    fi
}


