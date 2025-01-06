#!/bin/bash

# =============================================================================
# Load Utilities and Environment
# =============================================================================
# Dynamically load all utility scripts and environment variables
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/utilities/loader.sh"


################################################################################
#####                         SSH Management                               #####
################################################################################

# Manage IP Config Table
manage_ipv6_ssh_config() {
    mkdir -p "$(dirname "$IP_CONFIG_FILE")"
    touch "$IP_CONFIG_FILE"

    log "INFO" "⚙️ Managing IPv6 SSH configurations..."

    # Display current entries
    if [ -s "$IP_CONFIG_FILE" ]; then
        cat "$IP_CONFIG_FILE" | jq
    else
        echo "No existing configurations."
    fi

    echo -e "\nOptions:"
    echo "1) Add new entry"
    echo "2) Remove entry"
    echo "3) Cancel"
    read -p "Select an option: " choice

    case $choice in
    1)
        read -p "Enter IPv6 address: " ipv6_addr
        read -p "Enter server name: " server_name
        select_key_from_list
        if [ -n "$key_path" ]; then
            new_entry="{\"ipv6\":\"$ipv6_addr\", \"server\":\"$server_name\", \"key\":\"$key_path\"}"

            # Append the new entry to JSON
            if [ -s "$IP_CONFIG_FILE" ]; then
                jq ". += [$new_entry]" "$IP_CONFIG_FILE" > "$IP_CONFIG_FILE.tmp" && mv "$IP_CONFIG_FILE.tmp" "$IP_CONFIG_FILE"
            else
                echo "[$new_entry]" > "$IP_CONFIG_FILE"
            fi

            log "INFO" "✅ IPv6 entry saved for $server_name ($ipv6_addr)."
            echo -e "${GREEN}✅ IPv6 entry saved for $server_name ($ipv6_addr).${RESET}"
        else
            echo -e "${YELLOW}⚠️  IPv6 entry addition canceled.${RESET}"
            log "INFO" "⚠️  IPv6 entry addition canceled by user."
        fi
        ;;
    2)
        read -p "Enter server name or IPv6 to remove: " remove_entry
        if jq "del(.[] | select(.ipv6 == \"$remove_entry\" or .server == \"$remove_entry\"))" "$IP_CONFIG_FILE" > "$IP_CONFIG_FILE.tmp"; then
            mv "$IP_CONFIG_FILE.tmp" "$IP_CONFIG_FILE"
            log "INFO" "🗑 Entry removed for $remove_entry."
            echo -e "${GREEN}✅ Entry removed for $remove_entry.${RESET}"
        else
            echo -e "${RED}❌ Failed to remove entry for $remove_entry.${RESET}"
            log "ERROR" "Failed to remove entry for $remove_entry."
        fi
        ;;
    3)
        log "INFO" "Cancelled."
        echo -e "${YELLOW}⚠️  Operation canceled.${RESET}"
        ;;
    *)
        log "WARN" "Invalid option. Try again."
        echo -e "${RED}❌ Invalid option. Try again.${RESET}"
        sleep 1
        ;;
    esac
}

# Select Key from List to Use for SSH Config 
select_key_from_list() {
    keys=($(ls -1 "$SSH_DIR" 2>/dev/null))

    if [ ${#keys[@]} -eq 0 ]; then
        log "ERROR" "No files found in $SSH_DIR."
        echo -e "${RED}❌ No files found in $SSH_DIR.${RESET}"
        return 1
    fi

    echo "Select a file to import to YubiKey (keys, certs, etc.):"
    select key_path in "${keys[@]}" "Cancel"; do
        file_count=${#keys[@]}
        if [[ "$REPLY" =~ ^[0-9]+$ && "$REPLY" -ge 1 && "$REPLY" -le "$file_count" ]]; then
            selected_file="${keys[$((REPLY - 1))]}"
            full_key_path="$SSH_DIR/$selected_file"
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

# Start SSH Session Using Stored IPv6 Configurations
start_selected_ssh_session() {
    log "INFO" "🔗 Starting SSH session using stored IPv6 configurations..."    
    if [ ! -s "$IP_CONFIG_FILE" ]; then
        log "WARN" "No IPv6 configurations found. Add an entry first."
        echo "No IPv6 configurations found."
        manage_ipv6_ssh_config
        return
    fi
    
    ipv6_entries=()
    
    while IFS= read -r entry; do
        server=$(echo "$entry" | jq -r '.server')
        ipv6=$(echo "$entry" | jq -r '.ipv6')
        key=$(echo "$entry" | jq -r '.key')
        ipv6_entries+=("$server ($ipv6) -> $key")
    done < <(jq -c '.[]' "$IP_CONFIG_FILE")
    
    if [ ${#ipv6_entries[@]} -eq 0 ]; then
        log "WARN" "No IPv6 configurations found."
        echo "No IPv6 configurations found."
        manage_ipv6_ssh_config
        return
    fi
    
    echo "Select server to SSH into:"
    PS3="Select an option [1-${#ipv6_entries[@]}] or $((${#ipv6_entries[@]} + 1)): "
    select choice in "${ipv6_entries[@]}" "Cancel"; do
        if [ "$REPLY" -eq $((${#ipv6_entries[@]} + 1)) ]; then
            log "INFO" "Cancelled."
            echo -e "${YELLOW}⚠️  Operation canceled.${RESET}"
            break
        elif [ -n "$choice" ]; then
            ipv6_addr=$(echo "$choice" | sed -n 's/.*(\([^)]*\)).*/\1/p')
            key=$(echo "$choice" | awk -F'->' '{print $2}' | xargs)
            
            if [ -n "$ipv6_addr" ]; then
                log "INFO" "Selected IPv6: $ipv6_addr"
                log "INFO" "Using SSH Key: $key"
                
                # Detect key type (FIDO or Regular)
                if [[ "$key" == *"_sk"* ]]; then
                    # FIDO2/WebAuthn keys - Use PKCS#11
                    log "INFO" "Detected FIDO2 key. Using PKCS#11 provider for direct authentication."
                    SSH_AUTH_SOCK= ssh -o IdentitiesOnly=yes \
                        -o PKCS11Provider=/opt/homebrew/lib/libykcs11.dylib \
                        -o PreferredAuthentications=publickey \
                        -i "$key" root@"$ipv6_addr"
                else
                    # Regular RSA/ECDSA/ED25519 keys - Use SSH agent or direct key path
                    log "INFO" "Detected standard SSH key. Proceeding with standard SSH authentication."
                    
                    # Test if key is loaded in agent
                    ssh-add -L | grep -q "$key"
                    if [ $? -ne 0 ]; then
                        log "WARN" "Key not found in agent. Adding key: $key"
                        ssh-add "$key"
                        if [ $? -ne 0 ]; then
                            log "ERROR" "Failed to add key to SSH agent."
                            return
                        fi
                    else
                        log "INFO" "✅ Key is already loaded in the agent."
                    fi
                    
                    ssh -o IdentitiesOnly=yes -i "$key" root@"$ipv6_addr"
                fi
                
                if [ $? -eq 0 ]; then
                    log "INFO" "✅ SSH session established to $ipv6_addr."
                else
                    log "ERROR" "Failed to connect to $ipv6_addr."
                fi
                break
            else
                log "WARN" "Failed to extract IPv6 address from selection."
                echo -e "${RED}❌ Failed to extract IPv6 address from selection.${RESET}"
            fi
        else
            log "WARN" "Invalid selection. Try again."
            echo -e "${RED}❌ Invalid selection. Try again.${RESET}"
        fi
    done
}





