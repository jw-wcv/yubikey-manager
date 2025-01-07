#!/bin/bash

# =============================================================================
# Load Utilities and Environment
# =============================================================================
# Dynamically load all utility scripts and environment variables
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/utilities/loader.sh"


################################################################################
#####                            Key Config                                #####
################################################################################

# Get List of Keys
list_keys () {
    log "INFO" "🔑 Listing SSH keys managed by YubiKey:"
    
    # List PIV-managed keys
    log "INFO" "📄 PIV (ssh-rsa) Keys:"
    ykman piv info || log "ERROR" "Failed to list PIV keys."
}

# Export Public Key of Active Slots (Both PIV and FIDO2)
export_ssh_public_key() {
    log "INFO" "🔐 Exporting SSH public key(s) from YubiKey..."
    
    echo "Select the type of SSH public key to export:"
    echo "1) PIV (ssh-rsa) Key"
    echo "2) FIDO2 (ecdsa-sk/ed25519-sk) Key"
    echo "3) Both PIV and FIDO2 Keys"
    echo "4) 9a/9c SSH Keys"
    read -p "Enter your choice [1-4]: " export_choice
    
    case $export_choice in
        1)
            export_piv_public_key
            ;;
        2)
            export_fido2_public_key
            ;;
        3)
            export_piv_public_key
            export_fido2_public_key
            ;;
        4)
            generate_ssh_key_from_yubikey
            ;;
        *)
            log "WARN" "Invalid choice. Returning to main menu."
            return
            ;;
    esac
}


