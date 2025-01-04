#!/bin/bash

# Import general utility functions
source ./general.sh
source ./keys.sh  # For key selection and SSH key management functions
ipv6_config_file="./resources/data/ipv6_config.json"  # Store in project directory

# Manage IP Config Table
manage_ipv6_ssh_config() {
    mkdir -p "$(dirname "$ipv6_config_file")"
    touch "$ipv6_config_file"

    log "INFO" "⚙️ Managing IPv6 SSH configurations..."

    # Display current entries
    if [ -s "$ipv6_config_file" ]; then
        cat "$ipv6_config_file" | jq
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
            if [ -s "$ipv6_config_file" ]; then
                jq ". += [$new_entry]" "$ipv6_config_file" > "$ipv6_config_file.tmp" && mv "$ipv6_config_file.tmp" "$ipv6_config_file"
            else
                echo "[$new_entry]" > "$ipv6_config_file"
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
        if jq "del(.[] | select(.ipv6 == \"$remove_entry\" or .server == \"$remove_entry\"))" "$ipv6_config_file" > "$ipv6_config_file.tmp"; then
            mv "$ipv6_config_file.tmp" "$ipv6_config_file"
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

# Start SSH Session Using Stored IPv6 Configurations
start_selected_ssh_session() {
    log "INFO" "🔗 Starting SSH session using stored IPv6 configurations..."    
    if [ ! -s "$ipv6_config_file" ]; then
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
    done < <(jq -c '.[]' "$ipv6_config_file")
    
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





