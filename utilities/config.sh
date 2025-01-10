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

################################################################################
#####                          SSH Config Prep                             #####
################################################################################

# Full SSH Setup for YubiKey (FIDO2-based configuration)
setup_yubikey_for_ssh() {
    check_yubikey_presence || return

    log "INFO" "🔧 Initializing YubiKey SSH configuration..."
    generate_or_update_pin
    generate_or_update_puk
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
