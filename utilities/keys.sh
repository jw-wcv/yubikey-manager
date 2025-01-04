#!/bin/bash

# Import general utility functions
source ./general.sh

config_file="/Users/JJ/Documents/Projects/yubikey-manager/resources/data/yubi_config.json"
export_dir="/Users/JJ/Documents/Projects/yubikey-manager/resources/keys"
key_dir="/Users/JJ/Documents/Projects/yubikey-manager/resources/keys"
path="/Users/JJ/Documents/Projects/yubikey-manager/"
ssh_dir="$HOME/.ssh"



################################################################################
#####                        General Config                                #####
################################################################################

# Get List of Keys
list_keys () {
    log "INFO" "🔑 Listing SSH keys managed by YubiKey:"
    
    # List PIV-managed keys
    log "INFO" "📄 PIV (ssh-rsa) Keys:"
    ykman piv info || log "ERROR" "Failed to list PIV keys."
    
    echo ""
    
    # List FIDO2 keys by scanning for *any* resident keys in .ssh directory
    log "INFO" "🔐 FIDO2 (ecdsa-sk/ed25519-sk) Keys:"
    
    # Scan for all resident keys ending with _sk in the .ssh directory
    fido2_keys=$(ls $HOME/.ssh/*_sk 2>/dev/null)

    if [ -z "$fido2_keys" ]; then
        log "INFO" "No FIDO2 SSH keys found."
    else
        for key in $fido2_keys; do
            log "INFO" "FIDO2 SSH Key: $key"
            log "INFO" "Public Key:"
            cat "${key}.pub" 2>/dev/null || log "ERROR" "Failed to read public key for $key."
        done
    fi
}

# Remove a Key from Slot (NOT FOR FIRMWARE < 5.7)
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

# Select Key from List to Use for SSH Config 
select_key_from_list() {
    # ssh_dir="$HOME/.ssh"
    keys=($(ls -1 "$ssh_dir" 2>/dev/null))

    if [ ${#keys[@]} -eq 0 ]; then
        log "ERROR" "No files found in $ssh_dir."
        echo -e "${RED}❌ No files found in $ssh_dir.${RESET}"
        return 1
    fi

    echo "Select a file to import to YubiKey (keys, certs, etc.):"
    select key_path in "${keys[@]}" "Cancel"; do
        file_count=${#keys[@]}
        if [[ "$REPLY" =~ ^[0-9]+$ && "$REPLY" -ge 1 && "$REPLY" -le "$file_count" ]]; then
            selected_file="${keys[$((REPLY - 1))]}"
            full_key_path="$ssh_dir/$selected_file"
            log "INFO" "Selected file: $full_key_path"

            # Handle PEM keys
            if [[ "$selected_file" == *.pem ]]; then
                # Validate the PEM key before proceeding
                if openssl rsa -in "$full_key_path" -check &>/dev/null; then
                    pkcs12="${full_key_path%.pem}.p12"
                    openssl pkcs12 -export -in "$full_key_path" -out "$pkcs12" -nocerts -passout pass:"" 2>/tmp/openssl_error.log

                    # Explicit check if the file was created
                    if [ -s "$pkcs12" ]; then
                        import_key_to_yubikey "$pkcs12"
                        key_path="$pkcs12"
                        echo -e "${GREEN}✅ Imported and selected file: $selected_file${RESET}"
                        log "INFO" "✅ Imported and selected .pem key: $selected_file"
                    else
                        log "ERROR" "Failed to convert $selected_file to PKCS#12."
                        cat /tmp/openssl_error.log
                        echo -e "${RED}❌ Conversion of $selected_file to PKCS#12 failed.${RESET}"
                        key_path=""
                    fi
                else
                    log "ERROR" "Invalid .pem file: $selected_file."
                    echo -e "${RED}❌ $selected_file is not a valid .pem key.${RESET}"
                fi
            else
                # Handle non-pem keys (FIDO, RSA, etc.)
                log "INFO" "Selected non-pem key: $selected_file"
                key_path="$full_key_path"
                echo -e "${GREEN}✅ Key selected: $selected_file${RESET}"
            fi
            break
        elif [ "$REPLY" -eq $((file_count + 1)) ]; then
            log "INFO" "Cancelled."
            echo -e "${YELLOW}⚠️  Operation canceled.${RESET}"
            break
        else
            log "WARN" "Invalid option selected: $REPLY"
            echo -e "${RED}❌ Invalid option. Try again.${RESET}"
        fi
    done
}



################################################################################
#####                           FIDO Config                                #####
################################################################################

# Generate FIDO2 SSH Key Pair on YubiKey (Resident or Non-Resident)
generate_fido2_ssh_key() {
    local ssh_key="$HOME/.ssh/id_ecdsa_sk"
    local ssh_key_pub="$ssh_key.pub"
    local project_dir="/Users/JJ/Documents/Projects/yubikey-manager/resources/keys"
    local resident_flag=""
    mkdir -p "$project_dir"

    # Prompt user for resident or non-resident key
    echo ""
    echo "🔑 FIDO2 SSH Key Generation"
    echo "1) Generate Non-Resident FIDO2 SSH Key (Default)"
    echo "2) Generate Resident FIDO2 SSH Key (Stored on YubiKey, Recoverable)"
    read -rp "Select an option [1-2]: " fido_choice

    case $fido_choice in
        1)
            log "INFO" "🔐 Generating Non-Resident FIDO2 SSH key..."
            ;;
        2)
            log "INFO" "🔐 Generating Resident FIDO2 SSH key (stored on YubiKey)..."
            resident_flag="-O resident"
            ;;
        *)
            log "WARN" "⚠️ Invalid option. Defaulting to Non-Resident FIDO2 SSH key."
            ;;
    esac

    # Delete existing FIDO2 SSH key if it exists
    if [ -f "$ssh_key" ]; then
        log "WARN" "⚠️ Existing FIDO2 SSH key detected. Removing old key to ensure consistency."
        rm -f "$ssh_key" "$ssh_key_pub"
        log "INFO" "🧹 Old FIDO2 SSH key removed."
    fi

    # Generate a new FIDO2 SSH key pair with chosen option
    log "INFO" "🛠️ Generating new FIDO2 SSH key pair..."
    ssh-keygen -t ecdsa-sk $resident_flag -f "$ssh_key" -C "ALEPH_SERVICES"
    
    if [ $? -eq 0 ]; then
        log "INFO" "✅ FIDO2 SSH key pair generated successfully."
        log "INFO" "🔍 Public key located at $ssh_key_pub."
        
        # Backup the keys to the project directory
        cp "$ssh_key_pub" "$project_dir/"
        log "INFO" "🔑 Public key backed up to $project_dir/$(basename $ssh_key_pub)."
        
        # Check for private key (non-resident) and backup if available
        if [ -f "$ssh_key" ]; then
            cp "$ssh_key" "$project_dir/"
            log "INFO" "🔑 Private key backed up to $project_dir/$(basename $ssh_key)."
        else
            log "INFO" "🔐 Resident key created - no private key file generated (stored directly on YubiKey)."
        fi
    else
        log "ERROR" "❌ Failed to generate FIDO2 SSH key pair."
        return 1
    fi
}

# Deploy FIDO2 Public Key to Remote Servers
deploy_fido2_public_key() {
    local ssh_key_pub="$HOME/.ssh/id_ecdsa_sk.pub"
    local remote_user="root"
    local remote_host="[ipv6_address]"  # Replace with your actual IPv6 address or hostname

    log "INFO" "🔧 Deploying FIDO2 public key to remote server $remote_host..."

    # Check if remote_host is provided
    if [ "$remote_host" == "[ipv6_address]" ]; then
        log "ERROR" "❌ Remote host IPv6 address not set. Please update the script with your VM's IPv6 address."
        return 1
    fi

    # Deploy using ssh-copy-id
    ssh-copy-id -i "$ssh_key_pub" "$remote_user@$remote_host" || {
        log "ERROR" "❌ Failed to deploy FIDO2 public key to $remote_host."
        return 1
    }

    log "INFO" "✅ FIDO2 public key deployed to $remote_host successfully."
}

# Export FIDO2 (ecdsa-sk/ed25519-sk) Public Key(s)
export_fido2_public_key() {
    local ssh_dir="$HOME/.ssh"
    local export_dir="$HOME/yubikey_exports"
    
    log "INFO" "🔐 Exporting FIDO2 public key(s)..."

    # Search for all FIDO2 keys (.pub) that match common patterns (ecdsa-sk, ed25519-sk)
    fido2_keys=($(find "$ssh_dir" -maxdepth 1 -type f \( -name "*.pub" \) -exec grep -l "sk-" {} \;))

    # Create the export directory if it doesn't exist
    mkdir -p "$export_dir"
    
    exported=false

    for key_file in "${fido2_keys[@]}"; do
        if [ -f "$key_file" ]; then
            base_name=$(basename "$key_file")
            export_file="$export_dir/$base_name"

            # Copy the public key to the export directory
            cp "$key_file" "$export_file" 2>/dev/null
            if [ $? -eq 0 ]; then
                log "INFO" "✅ FIDO2 public key exported successfully to $export_file."
                exported=true
            else
                log "ERROR" "❌ Failed to export FIDO2 public key from $key_file."
            fi
        fi
    done

    if [ "$exported" = false ]; then
        log "INFO" "No FIDO2 public keys were exported."
    fi
}



################################################################################
#####                            RSA Config                                #####
################################################################################

# Generate ssh-rsa key via YubiKey's PIV with optional resident key storage and local backup
generate_rsa_piv_key() {
    log "INFO" "🔧 Generating new ssh-rsa key for YubiKey..."

    # Choose where to generate the key
    echo "Where do you want to generate the SSH key?"
    echo "1) Directly on YubiKey (Resident Key - no private key access)"
    echo "2) Generate Locally (with private key backup)"
    read -p "Select an option [1/2]: " generate_option

    read -p "Enter a name for the new key (default: yubikey): " key_name
    key_name=${key_name:-yubikey}

    read -p "Select YubiKey slot to store the key (9a/9c) [default: 9a]: " yubikey_slot
    yubikey_slot=${yubikey_slot:-9a}

    if [[ "$generate_option" == "1" ]]; then
        handleDeviceRSAGeneration "$key_name" "$yubikey_slot"
    elif [[ "$generate_option" == "2" ]]; then
        handleLocalRSAGeneration "$key_name" "$yubikey_slot"
    else
        log "ERROR" "❌ Invalid option selected."
    fi
}

# Genereate the Key on Device (No access to private key)
handleDeviceRSAGeneration() {
    local key_name=$1
    local yubikey_slot=$2
    local key_dir="/Users/JJ/Documents/Projects/yubikey-manager/resources/keys"
    local ssh_dir="$HOME/.ssh"
    mkdir -p "$ssh_dir"

    local management_key
    management_key=$(jq -r '.management_key' "$key_dir/../data/yubi_config.json" 2>/dev/null)
    if [[ -z "$management_key" || "$management_key" == "null" ]]; then
        log "ERROR" "❌ Management key not found. Configure YubiKey first."
        return
    fi

    local pubkey_path="$ssh_dir/${yubikey_slot}_${key_name}.pub"
    local cert_path="$ssh_dir/${yubikey_slot}_${key_name}_cert.pem"
    local attestation_path="/tmp/${yubikey_slot}_${key_name}_attest.pem"
    local project_pubkey_path="$key_dir/${yubikey_slot}_${key_name}.pub"
    local project_cert_path="$key_dir/${yubikey_slot}_${key_name}_cert.pem"

    log "INFO" "🔐 Generating key directly on YubiKey (Resident)..."
    ykman piv keys generate --pin-policy=once --touch-policy=always \
    --management-key "$management_key" "$yubikey_slot" "$pubkey_path" 2>&1 | tee /tmp/ykman_error.log

    if [ -f "$pubkey_path" ]; then
        cp "$pubkey_path" "$project_pubkey_path"
        log "INFO" "✅ Public key cloned to $project_pubkey_path."
    else
        log "ERROR" "❌ Public key not found at $pubkey_path. Certificate generation may fail."
    fi

    log "INFO" "🔏 Generating self-signed certificate..."
    ykman piv certificates generate --subject "CN=$key_name" \
    --management-key "$management_key" "$yubikey_slot" "$pubkey_path" 2>&1 | tee /tmp/ykman_cert_error.log

    log "INFO" "📜 Exporting self-signed certificate..."
    ykman piv certificates export "$yubikey_slot" "$cert_path" --format=PEM

    if [ -f "$cert_path" ]; then
        cp "$cert_path" "$project_cert_path"
        log "INFO" "✅ Certificate exported to $cert_path and cloned to $project_cert_path."
    else
        log "ERROR" "❌ Certificate export failed. No PEM file generated."
    fi

    # Perform attestation step
    log "INFO" "🔍 Performing attestation for slot $yubikey_slot..."
    if ykman piv keys attest "$yubikey_slot" "$attestation_path" 2>&1 | tee /tmp/ykman_attest_error.log; then
        log "INFO" "✅ Attestation successful. Attestation file saved at $attestation_path."
    else
        log "ERROR" "❌ Attestation failed: $(cat /tmp/ykman_attest_error.log)"
    fi
}


# Generate the Key on the Machine for Private key Access
handleLocalRSAGeneration() {
    local key_name=$1
    local yubikey_slot=$2
    local key_dir="/Users/JJ/Documents/Projects/yubikey-manager/resources/keys"
    local ssh_dir="$HOME/.ssh"
    mkdir -p "$ssh_dir"

    local privkey_path="$ssh_dir/${yubikey_slot}_${key_name}"
    local pem_path="$privkey_path.pem"
    local pubkey_path="$ssh_dir/${yubikey_slot}_${key_name}.pub"
    local cert_path="$key_dir/${yubikey_slot}_${key_name}_cert.pem"
    local project_privkey_path="$key_dir/${yubikey_slot}_${key_name}" 
    local project_pubkey_path="$key_dir/${yubikey_slot}_${key_name}.pub"

    log "INFO" "🔑 Generating SSH key locally..."
    ssh-keygen -t rsa -b 2048 -f "$privkey_path" -C "$key_name" -o

    if [ $? -eq 0 ]; then
        log "INFO" "✅ Local private key saved at $privkey_path."

        # Clone the private and public keys to the project directory
        cp "$privkey_path" "$project_privkey_path"
        cp "$pubkey_path" "$project_pubkey_path"
        log "INFO" "✅ Private and public keys cloned to project directory."

        # Convert to PEM format and ensure permissions
        log "INFO" "🔄 Converting private key to PEM format..."
        ssh-keygen -p -m PEM -f "$privkey_path" -N "" -P "" > /dev/null 2>&1

        if [ $? -eq 0 ] && [ -f "$privkey_path" ]; then
            sudo mv "$privkey_path" "$pem_path"
            sudo chmod 600 "$pem_path"
            log "INFO" "✅ Private key converted to PEM format and permissions secured."

            # Reformat PEM using openssl to ensure compatibility with ykman
            sudo openssl rsa -in "$pem_path" -out "$pem_path" 2>&1
            if [ $? -ne 0 ]; then
                log "ERROR" "❌ PEM reformatting with openssl failed. Check PEM file integrity."
                return
            fi

            # Regenerate the public key directly from the PEM file
            sudo openssl rsa -in "$pem_path" -pubout -out "$pubkey_path"
            sudo cp "$pubkey_path" "$project_pubkey_path"
            log "INFO" "✅ Public key regenerated from PEM file."

            read -p "Store this key in YubiKey slot $yubikey_slot? (y/N): " import_to_yubi
            if [[ "$import_to_yubi" =~ ^[Yy]$ ]]; then
                local management_key
                management_key=$(jq -r '.management_key' "$key_dir/../data/yubi_config.json" 2>/dev/null)
                if [[ -z "$management_key" || "$management_key" == "null" ]]; then
                    log "ERROR" "❌ Management key not found. Configure YubiKey first."
                    return
                fi

                log "INFO" "🔄 Importing private key to YubiKey slot $yubikey_slot..."
                sudo ykman piv keys import "$yubikey_slot" "$pem_path" \
                --management-key "$management_key" 2>&1 | tee /tmp/ykman_error.log

                if [ $? -eq 0 ]; then
                    log "INFO" "🔏 Generating self-signed certificate for slot $yubikey_slot..."
                    
                    # Use regenerated .pub file to ensure compatibility
                    ykman piv certificates generate --subject "CN=$key_name" \
                    --management-key "$management_key" "$yubikey_slot" "$pubkey_path" 2>&1 | tee /tmp/ykman_cert_error.log
                    
                    if [ $? -eq 0 ]; then
                        ykman piv certificates export "$yubikey_slot" "$cert_path" --format=PEM
                        cp "$cert_path" "$ssh_dir/${yubikey_slot}_${key_name}_cert.pem"
                        log "INFO" "✅ Certificate exported to $cert_path and cloned to $ssh_dir/${yubikey_slot}_${key_name}_cert.pem."
                    else
                        log "ERROR" "❌ Failed to generate self-signed certificate."
                    fi
                else
                    log "ERROR" "❌ Failed to import private key into YubiKey."
                fi
            fi
        else
            log "ERROR" "❌ Failed to convert private key to PEM format."
            return
        fi
    else
        log "ERROR" "❌ SSH key generation failed."
    fi
}

# Deploy ssh-rsa Public Key to Remote Servers
deploy_rsa_piv_public_key() {
    local key_dir="$HOME/resources/keys"
    local ssh_key_pub="$key_dir/pubkey.pem"
    local remote_user="root"
    local remote_host="[ipv6_address]"  # Replace with your actual IPv6 address or hostname

    log "INFO" "🔧 Deploying ssh-rsa public key to remote server $remote_host..."

    # Check if remote_host is provided
    if [ "$remote_host" == "[ipv6_address]" ]; then
        log "ERROR" "❌ Remote host IPv6 address not set. Please update the script with your VM's IPv6 address."
        return 1
    fi

    # Convert PEM to OpenSSH format
    ssh_key_openssh="$key_dir/id_rsa_piv.pub"
    ssh-keygen -i -m PKCS8 -f "$ssh_key_pub" > "$ssh_key_openssh" 2>/dev/null

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

### Convert Key to PKCS#12 Format (Optional for ssh-rsa via PIV)
convert_pem_to_pkcs12() {
    ssh_dir="$HOME/.ssh"
    key_dir="/Users/JJ/Documents/Projects/yubikey-manager/resources/keys"
    available_combos=()

    # Search for matching key pairs
    for dir in "$ssh_dir" "$key_dir"; do
        if [ -d "$dir" ]; then
            for pem in "$dir"/*.pem; do
                [ -f "$pem" ] || continue
                
                # Find potential matches (with or without _cert)
                base_name=$(basename "$pem" .pem)
                pub="${pem%_cert.pem}.pub"
                alt_pub="${pem%.pem}.pub"  # Fallback if no _cert suffix

                if [ -f "$pub" ] || [ -f "$alt_pub" ]; then
                    match_pub="${pub:-$alt_pub}"
                    combo="$(basename "$pem") + $(basename "$match_pub")"
                    available_combos+=("$combo")
                fi
            done
        fi
    done

    # Exit if no key combos found
    if [ ${#available_combos[@]} -eq 0 ]; then
        log "ERROR" "❌ No matching key combos found in ~/.ssh or $key_dir."
        return 1
    fi

    # List available key pairs for user selection
    echo "Select a key pair to bundle to PKCS#12:"
    select selected_combo in "${available_combos[@]}" "Cancel"; do
        if [ "$selected_combo" == "Cancel" ]; then
            log "INFO" "Operation canceled by user."
            return 1
        fi
        
        # Extract base name and determine paths
        pem_file=$(echo "$selected_combo" | awk '{print $1}')
        pub_file=$(echo "$selected_combo" | awk '{print $3}')
        base_name="${pem_file%.pem}"
        pem_path="$ssh_dir/$pem_file"
        pub_path="$ssh_dir/$pub_file"

        # If not in ~/.ssh, check optional key_dir
        if [ ! -f "$pem_path" ]; then
            pem_path="$key_dir/$pem_file"
            pub_path="$key_dir/$pub_file"
        fi

        log "INFO" "Selected PEM: $pem_path"
        log "INFO" "Selected PUB: $pub_path"
        break
    done

    # Ask user which YubiKey slot to import the key into
    read -p "Select YubiKey slot to import the key (9a/9c): " yubikey_slot
    yubikey_slot=${yubikey_slot:-9a}

    # Set export path and convert to PKCS#12
    export_path="${pem_path%.*}.p12"

    read -sp "Enter export password (for PKCS#12): " export_pass
    echo ""
    read -sp "Confirm password: " confirm_pass
    echo ""

    if [ "$export_pass" != "$confirm_pass" ]; then
        log "ERROR" "Passwords do not match. Exiting."
        return 1
    fi

    log "INFO" "🚀 Bundling SSH private key and public key to PKCS#12 format..."
    openssl pkcs12 -export -inkey "$pem_path" -in "$pub_path" -out "$export_path" \
        -name "SSH Key" -passout pass:"$export_pass" 2>/tmp/openssl_error.log

    if [ $? -ne 0 ]; then
        log "ERROR" "Failed to convert key. Check permissions or file path."
        cat /tmp/openssl_error.log
        return 1
    fi

    log "INFO" "✅ Key successfully converted to PKCS#12: $export_path"

    # Import the PKCS#12 bundle into the specified YubiKey slot
    log "INFO" "🔑 Importing to YubiKey slot $yubikey_slot..."
    ykman piv keys import "$yubikey_slot" "$export_path" 2>/tmp/ykman_error.log

    if [ $? -eq 0 ]; then
        log "INFO" "✅ Key successfully imported to YubiKey slot $yubikey_slot."
    else
        log "ERROR" "❌ Failed to import key to YubiKey."
        cat /tmp/ykman_error.log
    fi

    # Copy PKCS#12 file to both ~/.ssh and the project directory (if it exists)
    cp "$export_path" "$ssh_dir/"

    if [ -d "$key_dir" ]; then
        cp "$export_path" "$key_dir/"
        log "INFO" "✅ PKCS#12 copied to $key_dir"
    fi
}

# Export PIV (ssh-rsa) Public Key
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
    mkdir -p "$export_dir"
    export_file="$export_dir/piv_public_key_slot_${yubikey_slot}.pem"

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



################################################################################
#####                            Key Config                                #####
################################################################################

# Import Existing Keys to YubiKey via PIV (Optional for ssh-rsa via PIV)
import_key_to_yubikey() {
    pkcs12_path=$1
    attempts=0
    retry_limit=${retry_limit:-3}               # Default to 3 retries if unset
    timeout_duration=${timeout_duration:-30s}   # Default to 30 seconds if unset

    # Extract management key from config
    management_key=$(jq -r '.management_key' "$config_file" 2>/dev/null)

    if [[ -z "$management_key" || "$management_key" == "null" ]]; then
        log "ERROR" "❌ Management key not found. Please configure the YubiKey first."
        return 1
    fi

    # Extract key name from file path (basename without .pem)
    key_name=$(basename "$pkcs12_path" .pem)
    pubkey_path="${pkcs12_path%.*}.pub"

    log "INFO" "🔑 Using management key for import."

    while [ $attempts -lt $retry_limit ]; do
        log "INFO" "🔑 Importing key to YubiKey (Attempt $((attempts+1)))..."

        if [[ ! "$timeout_duration" =~ ^[0-9]+[smh]?$ ]]; then
            log "ERROR" "❌ Invalid timeout duration: $timeout_duration"
            timeout_duration="30s"
            log "WARN" "⚠️ Defaulting to 30s timeout."
        fi

        # Import private key to 9a or 9c
        timeout "$timeout_duration" ykman piv keys import 9a "$pkcs12_path" \
            --management-key "$management_key" &>/tmp/ykman_import_error.log
        exit_code=$?

        if [ $exit_code -eq 0 ]; then
            log "INFO" "✅ Key successfully imported to YubiKey."
            
            # Generate certificate immediately after key import
            log "INFO" "🔏 Generating self-signed certificate for slot 9a (Second Touch Required)..."
            ykman piv certificates generate 9a "$pubkey_path" --subject "CN=$key_name" --management-key "$management_key" 2>&1 | tee /tmp/ykman_cert_error.log

            if grep -q "error" /tmp/ykman_cert_error.log; then
                log "ERROR" "❌ Failed to generate certificate for slot 9a."
            else
                log "INFO" "✅ Certificate successfully generated for $key_name."
            fi
            return 0
        else
            log "ERROR" "❌ Import failed. Error log:"
            cat /tmp/ykman_import_error.log
        fi

        attempts=$((attempts+1))
        log "WARN" "Retrying key import... ($attempts/$retry_limit)"
    done

    log "ERROR" "Failed to import key after $retry_limit attempts."
}

# Export Public Key of Active Slots (Both PIV and FIDO2)
export_ssh_public_key() {
    log "INFO" "🔐 Exporting SSH public key(s) from YubiKey..."
    
    echo "Select the type of SSH public key to export:"
    echo "1) PIV (ssh-rsa) Key"
    echo "2) FIDO2 (ecdsa-sk/ed25519-sk) Key"
    echo "3) Both PIV and FIDO2 Keys"
    read -p "Enter your choice [1-3]: " export_choice
    
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
        *)
            log "WARN" "Invalid choice. Returning to main menu."
            return
            ;;
    esac
}



