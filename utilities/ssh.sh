#!/bin/bash

# =============================================================================
# Load Utilities and Environment
# =============================================================================
# Dynamically load all utility scripts and environment variables
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/utilities/loader.sh"


################################################################################
#####                         SSH Management                               #####
################################################################################

# Manage IP Config Table with YubiKey Support
manage_ipv6_ssh_config() {
    mkdir -p "$(dirname "$IP_CONFIG_FILE")"
    touch "$IP_CONFIG_FILE"

    log "INFO" "🤝 Managing IPv6 SSH configurations..."

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
        read -p "Use YubiKey for this host? (y/n): " use_yubikey

        if [ "$use_yubikey" == "y" ]; then
            read -p "IPv4 or IPv6? (4/6): " ip_version
            read -p "Enter username (default: root): " user_name
            user_name=${user_name:-root}

            # Prepare YubiKey SSH Config
            cat <<EOF >> ~/.ssh/config

Host $server_name
    HostName $ipv6_addr
    User $user_name
    PKCS11Provider /opt/homebrew/lib/opensc-pkcs11.so
    AddressFamily inet${ip_version}
    IdentitiesOnly yes
EOF
            new_entry="{\"ipv6\":\"$ipv6_addr\", \"server\":\"$server_name\", \"key\":\"yubikey\"}"
        else
            select_key_from_list
            if [ -n "$key_path" ]; then
                new_entry="{\"ipv6\":\"$ipv6_addr\", \"server\":\"$server_name\", \"key\":\"$key_path\"}"

                cat <<EOF >> ~/.ssh/config

Host $server_name
    HostName $ipv6_addr
    User root
    IdentityFile $key_path
    IdentitiesOnly yes
EOF
            fi
        fi

        if [ -s "$IP_CONFIG_FILE" ]; then
            jq ". += [$new_entry]" "$IP_CONFIG_FILE" > "$IP_CONFIG_FILE.tmp" && mv "$IP_CONFIG_FILE.tmp" "$IP_CONFIG_FILE"
        else
            echo "[$new_entry]" > "$IP_CONFIG_FILE"
        fi

        log "INFO" "✅ IPv6 entry saved for $server_name ($ipv6_addr)."
        echo -e "${GREEN}✅ IPv6 entry saved for $server_name ($ipv6_addr).${RESET}"
        ;;

    2)
    read -p "Enter server name or IPv6 to remove: " remove_entry
    if jq "del(.[] | select(.ipv6 == \"$remove_entry\" or .server == \"$remove_entry\"))" "$IP_CONFIG_FILE" > "$IP_CONFIG_FILE.tmp"; then
        mv "$IP_CONFIG_FILE.tmp" "$IP_CONFIG_FILE"
        log "INFO" "🗑 Entry removed for $remove_entry."
        echo -e "${GREEN}✅ Entry removed for $remove_entry.${RESET}"

        # Remove from SSH config
        sed -i '' "/^Host $remove_entry\$/,/^$/d" ~/.ssh/config
        log "INFO" "🗑 SSH config block removed for $remove_entry."
    else
        echo -e "${RED}❌ Failed to remove entry for $remove_entry.${RESET}"
        log "ERROR" "Failed to remove entry for $remove_entry."
    fi
    ;;


    3)
        log "INFO" "Cancelled."
        echo -e "${YELLOW}⚠️ Operation canceled.${RESET}"
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
            key_path="$full_key_path"
            echo -e "${GREEN}✅ Key selected: $selected_file${RESET}"
            break
        elif [ "$REPLY" -eq $((file_count + 1)) ]; then
            log "INFO" "Cancelled."
            echo -e "${YELLOW}⚠️ Operation canceled.${RESET}"
            break
        else
            log "WARN" "Invalid option selected: $REPLY"
            echo -e "${RED}❌ Invalid option. Try again.${RESET}"
        fi
    done
}


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
            server_name=$(echo "$choice" | awk -F' ' '{print $1}')
            log "INFO" "Selected server: $server_name"
            ssh $server_name
            
            if [ $? -eq 0 ]; then
                log "INFO" "✅ SSH session established to $server_name."
            else
                log "ERROR" "Failed to connect to $server_name."
            fi
            break
        else
            log "WARN" "Invalid selection. Try again."
            echo -e "${RED}❌ Invalid selection. Try again.${RESET}"
        fi
    done
}






