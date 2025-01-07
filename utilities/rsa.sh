#!/bin/bash

# =============================================================================
# Load Utilities and Environment
# =============================================================================
# Dynamically load all utility scripts and environment variables
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/utilities/loader.sh"

################################################################################
#####                          RSA Key Management                           #####
################################################################################

# Main Menu for Key Management
manage_rsa_keys() {
    echo "--------------------------------------"
    echo " 🔐 RSA Key Management for YubiKey     "
    echo "--------------------------------------"
    echo "1) Configure Authentication (9a/9d)"
    echo "2) Configure Resident RSA Key (9c)"
    echo "3) Exit"
    echo ""
    read -p "Select an option [1-3]: " choice

    case $choice in
        1) configure_yubikey_9a_9d ;;
        2) configure_yubikey_9c ;;
        3) echo "Exiting..." ;;
        *) echo "Invalid option. Please try again." ;;
    esac
}

# Configure Authentication and Key Management (9a and 9d)
configure_yubikey_9a_9d() {
    local cert_subject_9a="Sentinel_Identity"
    local cert_subject_9d="Core_Anchor"
    local key_name_9a="9a_$(whoami)_key"
    local key_name_9d="9d_$(whoami)_key"
    local privkey_9a="$SSH_DIR/$key_name_9a"
    local privkey_9d="$SSH_DIR/$key_name_9d"
    local pubkey_9a="$privkey_9a.pub"
    local pubkey_9d="$privkey_9d.pub"
    local cert_9a="$KEY_DIR/9a_Sentinel_Identity_cert.pem"
    local cert_9d="$KEY_DIR/9d_Core_Anchor_cert.pem"
    local management_key=$(get_management_key)

    mkdir -p "$SSH_DIR"
    mkdir -p "$KEY_DIR"

    log "🔑 Generating ECCP256 keys for slots 9a and 9d..."

    # Generate keys for slots 9a (Auth) and 9d (Key Management)
    ykman piv keys generate 9a --algorithm ECCP256 "$pubkey_9a" --management-key "$MANAGEMENT_KEY"
    ykman piv keys generate 9d --algorithm ECCP256 "$pubkey_9d" --management-key "$MANAGEMENT_KEY"

    if [ $? -eq 0 ]; then
        cp "$pubkey_9a" "$KEY_DIR/$key_name_9a.pub"
        cp "$pubkey_9d" "$KEY_DIR/$key_name_9d.pub"
        
        log "✅ Public keys saved to $SSH_DIR and $KEY_DIR"
    else
        log "❌ Key generation failed for 9a or 9d."
        exit 1
    fi

    log "📜 Generating certificates for slots 9a and 9d..."

    # Generate certificates for 9a and 9d with specific subjects
    ykman piv certificates generate 9a --subject "$cert_subject_9a" "$pubkey_9a" --management-key "$MANAGEMENT_KEY"
    ykman piv certificates generate 9d --subject "$cert_subject_9d" "$pubkey_9d" --management-key "$MANAGEMENT_KEY"

    # Export certificates to KEY_DIR and .ssh
    ykman piv certificates export 9a "$cert_9a"
    ykman piv certificates export 9d "$cert_9d"

    cp "$cert_9a" "$SSH_DIR/"
    cp "$cert_9d" "$SSH_DIR/"

    log "✅ Certificates exported to $KEY_DIR and copied to $SSH_DIR"

    log "🔌 Please remove and reinsert your YubiKey to complete pairing."
    read -p "Press Enter after reinserting the YubiKey..."

    sc_auth identities
    log "✅ YubiKey should now appear as an unpaired identity. Use macOS UI to complete pairing."
}

# Generate Resident RSA Key and Cert for 9c
configure_yubikey_9c() {
    local yubikey_slot="9c"
    local key_name="Guardian_Seal"

    # Avoid prefix duplication
    if [[ ! "$key_name" =~ ^${yubikey_slot}_ ]]; then
        key_name="${yubikey_slot}_${key_name}"
    fi

    local pubkey_path="$SSH_DIR/${key_name}.pub"
    local management_key=$(get_management_key)

    log "🔐 Generating RSA key directly on YubiKey (slot $yubikey_slot)..."

    # Ask user if key should be generated on the device
    read -p "Generate RSA key directly on the YubiKey (slot $yubikey_slot)? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then
        log "❌ Operation cancelled by user."
        return
    fi

    # Generate RSA key on YubiKey for slot 9c
    ykman piv keys generate --pin-policy=once --touch-policy=always \
        --management-key "$management_key" "$yubikey_slot" "$pubkey_path"

    if [ $? -eq 0 ]; then
        log "✅ RSA key generated on YubiKey for slot $yubikey_slot."

        # Generate certificate directly
        mkdir -p "$KEY_DIR"

        local cert_path="$KEY_DIR/${key_name}_cert.pem"
        log "📜 Generating certificate on YubiKey for slot 9c..."

        (
            cd "$KEY_DIR" || exit
            ykman piv certificates generate --subject "CN=$key_name" \
                --management-key "$management_key" "$yubikey_slot" "$pubkey_path"

            if [ $? -eq 0 ]; then
                ykman piv certificates export "$yubikey_slot" "${key_name}_cert.pem" --format=PEM
                if [ -f "${key_name}_cert.pem" ]; then
                    log "✅ Certificate exported from YubiKey to $cert_path"
                else
                    log "❌ Failed to export certificate from YubiKey."
                fi
            else
                log "❌ Certificate generation failed on YubiKey for slot $yubikey_slot."
            fi
        )

        # Export public key to KEY_DIR
        if [ -f "$pubkey_path" ]; then
            mkdir -p "$KEY_DIR"
            cp "$pubkey_path" "$KEY_DIR/${key_name}.pub"
            log "📂 Public key exported to $KEY_DIR"
        else
            log "⚠️ Public key not found at $pubkey_path."
        fi
    else
        log "❌ Failed to generate RSA key for slot $yubikey_slot."
    fi
}

# Export Public Key from YubiKey
export_piv_public_key() {
    read -p "Select YubiKey slot to export from (default 9a): " yubikey_slot
    yubikey_slot=${yubikey_slot:-9a}

    log "INFO" "🔐 Exporting PIV public key from slot $yubikey_slot..."

    # Verify slot contains a key by checking piv info directly
    if ! ykman piv info | grep -q "Slot $yubikey_slot (AUTHENTICATION\|SIGNATURE)"; then
        log "WARN" "⚠️ No PIV key found in slot $yubikey_slot. Skipping export."
        return 1
    fi

    # Define export paths
    mkdir -p "$KEY_DIR"
    export_file="$KEY_DIR/piv_public_key_slot_${yubikey_slot}.pem"

    # Export the public key (using export-key instead of certificates if no cert exists)
    if ! ykman piv certificates export "$yubikey_slot" "$export_file" 2>/tmp/ykman_piv_export_error.log; then
        log "WARN" "⚠️ No certificate found in slot $yubikey_slot. Exporting raw public key instead..."
        ykman piv keys export "$yubikey_slot" "$export_file" 2>&1 | tee /tmp/ykman_piv_export_error.log
    fi

    # Check for successful export
    if [ $? -ne 0 ]; then
        log "ERROR" "❌ Failed to export PIV public key from slot $yubikey_slot."
        log "ERROR" "🔍 Check /tmp/ykman_piv_export_error.log for details."
        return 1
    fi

    # Inform user of successful export
    log "INFO" "✅ PIV public key exported successfully to $export_file."
}

# Generate Public SSH Key from YubiKey PIV (Slot 9a or 9c)
generate_ssh_key_from_yubikey() {
    local ssh_key_dir="$KEY_DIR"
    mkdir -p "$ssh_key_dir"
    local slot=""
    local output_file=""
    local piv_slot=""

    # Prompt user to choose the slot
    echo "Select PIV Slot to generate SSH key from:"
    echo "1) Slot 9a (Authentication)"
    echo "2) Slot 9c (Digital Signature)"
    read -p "Select an option [1-2]: " slot_choice

    case $slot_choice in
    1)
        piv_slot="9a"
        output_file="9a_public_ssh_key"
        ;;
    2)
        piv_slot="9c"
        output_file="9c_public_ssh_key"
        ;;
    *)
        echo -e "${RED}❌ Invalid option. Exiting...${RESET}"
        return 1
        ;;
    esac

    log "INFO" "🔑 Exporting public key from slot $piv_slot..."
    
    # Export public key from the selected slot (no management key needed)
    if ykman piv keys export $piv_slot "$ssh_key_dir/public.pem"; then
        log "INFO" "✅ Public key exported from slot $piv_slot."
    else
        log "ERROR" "❌ Failed to export public key from slot $piv_slot."
        return 1
    fi

    # Convert public key to OpenSSH format
    log "INFO" "🔧 Converting public key to OpenSSH format..."
    if ssh-keygen -i -m PKCS8 -f "$ssh_key_dir/public.pem" > "$ssh_key_dir/${output_file}.pub"; then
        log "INFO" "✅ SSH public key generated as ${output_file}.pub."
    else
        log "ERROR" "❌ Failed to convert public key to SSH format."
        return 1
    fi

    # Clean up temporary PEM file
    rm -f "$ssh_key_dir/public.pem"
    log "INFO" "🗑 Temporary PEM file removed."

    # Display the resulting public key
    log "INFO" "🔍 SSH Public Key (${output_file}.pub):"
    cat "$ssh_key_dir/${output_file}.pub"

    echo -e "${GREEN}✅ SSH key generation complete. Key saved to $ssh_key_dir/${output_file}.pub.${RESET}"
}



########### WORK IN PROGRESS ###########

# Import Existing RSA Key to YubiKey with PEM Validation and PKCS#12 Conversion - INCOMPLETE 
import_existing_rsa_key() {
    log "🔍 Searching for RSA private keys in $SSH_DIR and $KEY_DIR..."
    
    # Find all RSA private keys and display for selection
    available_keys=($(find $SSH_DIR $KEY_DIR -type f \( -name "*.pem" -o -name "*.key" \) 2>/dev/null))
    
    if [ ${#available_keys[@]} -eq 0 ]; then
        log "ERROR" "❌ No RSA private keys found in $SSH_DIR or $KEY_DIR."
        echo -e "${RED}❌ No keys found for import.${RESET}"
        return 1
    fi

    # Display key selection menu
    echo "Select RSA private key to import to YubiKey:"
    select privkey_path in "${available_keys[@]}" "Cancel"; do
        [[ "$privkey_path" == "Cancel" ]] && return
        break
    done

    read -p "Import to YubiKey slot (9a/9c): " yubikey_slot
    yubikey_slot=${yubikey_slot:-9a}
    local management_key=$(get_management_key)

    if [[ -z "$management_key" || "$management_key" == "null" ]]; then
        log "ERROR" "❌ Management key not found. Configure the YubiKey first."
        return
    fi

    # Determine public key paths
    pubkey_path="${privkey_path%.*}.pub"
    pkcs12_path="${privkey_path%.*}.p12"

    # Convert to PEM format if necessary
    if ! openssl rsa -in "$privkey_path" -check &>/dev/null; then
        log "INFO" "🔄 Converting RSA private key to PEM format..."
        ssh-keygen -p -m PEM -f "$privkey_path" -N ""
    fi

    # Ensure public key exists, regenerate if needed
    if [ ! -f "$pubkey_path" ]; then
        log "🔄 Regenerating public key from private key..."
        ssh-keygen -y -f "$privkey_path" > "$pubkey_path"
        if [ $? -ne 0 ]; then
            log "ERROR" "❌ Failed to regenerate public key."
            return
        fi
    fi

    # Convert to PKCS#12 format if needed
    log "🔄 Checking and converting to PKCS#12 format..."
    openssl pkcs12 -export -inkey "$privkey_path" -in "$pubkey_path" -out "$pkcs12_path" -nocerts -passout pass:"" 2>/tmp/openssl_error.log
    if [ ! -s "$pkcs12_path" ]; then
        log "ERROR" "❌ Failed to convert key to PKCS#12 format."
        cat /tmp/openssl_error.log
        return
    fi

    # Import key to YubiKey with retry logic
    local attempts=0
    local retry_limit=3
    while [ $attempts -lt $retry_limit ]; do
        log "🔑 Importing RSA key to YubiKey slot $yubikey_slot (Attempt $((attempts+1)))..."
        timeout 30s ykman piv keys import "$yubikey_slot" "$pkcs12_path" --management-key "$management_key" 2>/tmp/ykman_import_error.log
        exit_code=$?

        if [ $exit_code -eq 0 ]; then
            log "✅ RSA key successfully imported to slot $yubikey_slot."

            # Generate certificate immediately after import
            log "🔏 Generating self-signed certificate (Touch Required)..."
            ykman piv certificates generate --subject "CN=$(basename $privkey_path)" "$yubikey_slot" "$pubkey_path" --management-key "$management_key" 2>&1 | tee /tmp/ykman_cert_error.log

            if grep -q "error" /tmp/ykman_cert_error.log; then
                log "ERROR" "❌ Failed to generate certificate for slot $yubikey_slot."
            else
                log "✅ Certificate successfully generated for $privkey_path."
            fi

            # Export artifacts to key directory
            cp "$privkey_path" "$KEY_DIR/"
            cp "$pubkey_path" "$KEY_DIR/"
            cp "$pkcs12_path" "$KEY_DIR/"
            log "INFO" "📂 Key artifacts exported to $KEY_DIR."

            return 0
        else
            log "ERROR" "❌ Import failed. Error log:"
            cat /tmp/ykman_import_error.log
        fi

        attempts=$((attempts+1))
        log "WARN" "Retrying key import... ($attempts/$retry_limit)"
    done

    log "ERROR" "❌ Failed to import RSA key after $retry_limit attempts."
}

# Deploy ssh-rsa Public Key to Remote Servers - INCOMPLETE 
deploy_rsa_piv_public_key() {
    local remote_user="root"
    local remote_host="[ipv6_address]"  # Replace with your actual IPv6 address or hostname

    log "INFO" "🔧 Deploying ssh-rsa public key to remote server $remote_host..."

    # Check if remote_host is provided
    if [ "$remote_host" == "[ipv6_address]" ]; then
        log "ERROR" "❌ Remote host IPv6 address not set. Please update the script with your VM's IPv6 address."
        return 1
    fi

    # Convert PEM to OpenSSH format
    ssh_key_openssh="$KEY_DIR/id_rsa_piv.pub"
    ssh-keygen -i -m PKCS8 -f "$SSH_KEY_PUB" > "$ssh_key_openssh" 2>/dev/null

    if [ $? -ne 0 ] || [ ! -f "$ssh_key_openssh" ]; then
        log "ERROR" "❌ Failed to convert PEM to OpenSSH public key format."
        return 1
    fi

    # Deploy using ssh-copy-id
    ssh-copy-id -i "$ssh_key_openssh" "$remote_user@$remote_host" || {
        log "ERROR" "❌ Failed to deploy ssh-rsa public key to $remote_host."
        return 1
    }

    log "INFO" "✅ ssh-rsa public key deployed to $remote_host successfully."
}

# Remove a Key from Slot (NOT FOR FIRMWARE < 5.7) --- INCOMPLETE
remove_key_from_yubikey() { 
    read -p "Select YubiKey slot to remove key from (default 9a): " yubikey_slot
    yubikey_slot=${yubikey_slot:-9a}

    read -p "⚠️ Are you sure you want to delete the key in slot $yubikey_slot? (y/N): " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        log "INFO" "❌ Key removal cancelled."
        return
    fi

    # Check if a key exists in the selected slot
    ykman piv info | grep -q "$yubikey_slot"
    if [ $? -ne 0 ]; then
        log "WARN" "No key found in slot $yubikey_slot. Skipping removal."
        return
    fi

    log "INFO" "🛢 Removing key from YubiKey (slot $yubikey_slot)..."

    # Attempt to delete key
    ykman piv keys delete "$yubikey_slot" &>/dev/null
    if [ $? -eq 0 ]; then
        log "INFO" "✅ Key successfully removed from YubiKey (slot $yubikey_slot)."
    else
        log "ERROR" "Failed to remove key from slot $yubikey_slot. Ensure YubiKey is connected and try again."
    fi
}