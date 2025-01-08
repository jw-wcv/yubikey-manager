#!/bin/bash

# =============================================================================
# Load Utilities and Environment
# =============================================================================
# Dynamically load all utility scripts and environment variables
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/utilities/loader.sh"

# =============================================================================
# Initialize SSH Artifacts if They Don't Exist
# =============================================================================
initialize_ssh_artifacts() {
    mkdir -p "$DATA_DIR"

    if [ ! -f "$SSH_CONFIG_ARTIFACT" ]; then
        echo "Initializing SSH config artifact from template..."
        cp "$SSH_CONFIG_TEMPLATE" "$SSH_CONFIG_ARTIFACT"
    fi

    if [ ! -f "$IPV6_ARTIFACT" ]; then
        echo "Initializing IPv6 config artifact from template..."
        cp "$IPV6_TEMPLATE" "$IPV6_ARTIFACT"
    fi
}

# =============================================================================
# Sync SSH Config with Artifact (Bidirectional) and Update IPv6 Artifact
# =============================================================================
sync_ssh_with_artifact() {
    local sync_needed=false
    missing_in_ssh=()
    missing_in_artifact=()

    # Extract valid hosts by parsing ~/.ssh/config
    local ssh_hosts=()
    while IFS= read -r line; do
        # Capture valid hosts excluding '*' or unrelated patterns, and skip comments
        if [[ "$line" =~ ^Host[[:space:]]+([^*[:space:]]+)$ ]] && [[ ! "$line" =~ ^# ]]; then
            ssh_hosts+=("${BASH_REMATCH[1]}")
        fi
    done < "$SSH_CONFIG_FILE"

    # Extract hosts from artifact, excluding unwanted entries
    local artifact_hosts=($(jq -r '.[] | select(.server != "artifacts" and .server != "key_manager.sh" and .server != "resources" and .server != "utilities") | .server' "$IPV6_ARTIFACT"))

    # Compare Artifact Hosts with SSH Config
    for host in "${artifact_hosts[@]}"; do
        if ! printf "%s\n" "${ssh_hosts[@]}" | grep -qx "$host"; then
            missing_in_ssh+=("$host")
            sync_needed=true
        fi
    done

    # Compare SSH Config Hosts with Artifact
    for host in "${ssh_hosts[@]}"; do
        if ! printf "%s\n" "${artifact_hosts[@]}" | grep -qx "$host"; then
            missing_in_artifact+=("$host")
            sync_needed=true
        fi
    done

    # Display Discrepancies
    if [ "$sync_needed" = true ]; then
        echo -e "\n⚠️ Discrepancies Found:"
        [ ${#missing_in_ssh[@]} -gt 0 ] && echo "🟩 Missing in SSH Config (from artifact): ${missing_in_ssh[*]}"
        [ ${#missing_in_artifact[@]} -gt 0 ] && echo "🟧 Missing in Artifact (from SSH Config): ${missing_in_artifact[*]}"
        
        echo -e "\nOptions:"
        echo "1) Sync Missing Entries"
        echo "2) Overwrite Artifact with SSH Config Hosts"
        echo "3) Overwrite SSH Config with Artifact Hosts"
        echo "4) Restore from ssh_config Template"
        echo "5) Cancel"
        read -p "Select an option: " sync_choice

        case $sync_choice in
        1) apply_sync ; update_ipv6_artifact ;; 
        2) overwrite_artifact_with_ssh ; update_ipv6_artifact ;; 
        3) overwrite_ssh_with_artifact ; update_ipv6_artifact ;; 
        4) restore_ssh_from_template ;;
        5) echo "⚠️ Sync canceled." ;;
        *) echo "❌ Invalid choice. No changes made." ;;
        esac
    else
        echo "✅ SSH Config and Artifact are in sync."
        update_ipv6_artifact
    fi
}



# =============================================================================
# Apply Sync for Missing Entries (Prevent Duplicates)
# =============================================================================
apply_sync() {
    for host in "${missing_in_artifact[@]}"; do
        # Check if host already exists before adding
        if ! jq -e --arg server "$host" '.[] | select(.server == $server)' "$IPV6_ARTIFACT" > /dev/null; then
            jq ". += [{\"server\":\"$host\",\"ipv6\":\"\",\"key\":\"~/.ssh/id_rsa\"}]" "$IPV6_ARTIFACT" > "$IPV6_ARTIFACT.tmp" && \
            mv "$IPV6_ARTIFACT.tmp" "$IPV6_ARTIFACT"
            log "INFO" "✅ Added $host to artifact."
        else
            log "INFO" "⚠️ $host already exists in artifact. Skipping..."
        fi
    done

    for host in "${missing_in_ssh[@]}"; do
        # Check if host already exists in ssh_config
        if ! grep -q "Host $host" "$SSH_CONFIG_FILE"; then
            cat <<EOF >> "$SSH_CONFIG_FILE"

Host $host
    HostName <ipv6-address>
    User root
    IdentityFile ~/.ssh/id_rsa
EOF
            log "INFO" "✅ Added $host to SSH Config."
        else
            log "INFO" "⚠️ $host already exists in SSH Config. Skipping..."
        fi
    done
}


# =============================================================================
# Update IPv6 Artifact to Reflect SSH Config (Prevent Duplicates)
# =============================================================================
update_ipv6_artifact() {
    local updated_artifact=()
    local temp_artifact_file="$IPV6_ARTIFACT.tmp"
    
    # Create a copy of the artifact to modify
    jq -c '.' "$IPV6_ARTIFACT" > "$temp_artifact_file"

    # Parse valid Host entries and update or add new entries
    while IFS= read -r line; do
        if [[ "$line" =~ ^Host[[:space:]]+([^*]+) ]]; then
            host="${BASH_REMATCH[1]}"
            ipv6=$(awk -v host="$host" '$0 ~ "Host " host {found=1} found && /HostName/ {print $2; exit}' "$SSH_CONFIG_FILE")
            [ -z "$ipv6" ] && ipv6=""  # Default to empty if no IP is found

            # Remove existing entry if it exists
            jq --arg server "$host" 'del(.[] | select(.server == $server))' "$temp_artifact_file" > "$temp_artifact_file.tmp" \
                && mv "$temp_artifact_file.tmp" "$temp_artifact_file"

            # Add updated entry
            jq --arg server "$host" --arg ipv6 "$ipv6" --arg key "~/.ssh/id_rsa" \
                '. += [{"server": $server, "ipv6": $ipv6, "key": $key}]' "$temp_artifact_file" > "$temp_artifact_file.tmp" \
                && mv "$temp_artifact_file.tmp" "$temp_artifact_file"
        fi
    done < "$SSH_CONFIG_FILE"

    # Overwrite the artifact with the updated version
    mv "$temp_artifact_file" "$IPV6_ARTIFACT"
    log "INFO" "✅ IPv6 artifact updated with duplicates removed and new entries added."
}



# =============================================================================
# Overwrite Artifact with SSH Config Hosts (Preserve Global Host * Section)
# =============================================================================
overwrite_artifact_with_ssh() {
    echo "⚠️ Overwriting artifact with SSH Config hosts..."
    jq -n '[]' > "$IPV6_ARTIFACT.tmp"

    # Extract 'Host *' section to preserve general settings in artifact
    cat <<EOF > "$IPV6_ARTIFACT.tmp"
[
  {
    "server": "*",
    "ipv6": "",
    "key": "yubikey",
    "config": {
      "PKCS11Provider": "/opt/homebrew/lib/opensc-pkcs11.so",
      "ForwardAgent": "no",
      "ForwardX11": "no",
      "PasswordAuthentication": "no",
      "ChallengeResponseAuthentication": "no",
      "IdentityFile": ["~/.ssh/id_ecdsa_sk", "~/.ssh/id_ecdsa_sk_rk"],
      "KexAlgorithms": "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256",
      "Ciphers": "aes256-gcm@openssh.com,aes128-gcm@openssh.com,chacha20-poly1305@openssh.com",
      "HostKeyAlgorithms": "rsa-sha2-512,rsa-sha2-256,ssh-ed25519,ecdsa-sha2-nistp256",
      "ServerAliveInterval": "60",
      "ServerAliveCountMax": "3",
      "Compression": "no",
      "StrictHostKeyChecking": "ask",
      "UserKnownHostsFile": "~/.ssh/known_hosts",
      "TCPKeepAlive": "no",
      "PermitLocalCommand": "no",
      "RekeyLimit": "1G 1h",
      "LogLevel": "VERBOSE"
    }
  }
]
EOF

    # Parse individual host entries from SSH config
    grep -E "^Host " "$SSH_CONFIG_FILE" | awk '{print $2}' | while read -r host; do
        # Skip the wildcard host '*' since it's already added
        if [[ "$host" != "*" ]]; then
            ipv6=$(awk -v host="$host" '$0 ~ "Host " host {found=1} found && /HostName/ {print $2; exit}' "$SSH_CONFIG_FILE")

            # Fallback key logic
            if grep -A3 "^Host $host" "$SSH_CONFIG_FILE" | grep -q 'PKCS11Provider'; then
                key="yubikey"
            else
                key=$(awk -v host="$host" '$0 ~ "Host " host {found=1} found && /IdentityFile/ {print $2; exit}' "$SSH_CONFIG_FILE")
                [ -z "$key" ] && key="~/.ssh/id_rsa"
            fi

            # Construct new entry for artifact
            new_entry="{\"server\":\"$host\",\"ipv6\":\"$ipv6\",\"key\":\"$key\"}"

            # Append the entry to artifact
            jq ". += [$new_entry]" "$IPV6_ARTIFACT.tmp" > "$IPV6_ARTIFACT.tmp.2" && \
            mv "$IPV6_ARTIFACT.tmp.2" "$IPV6_ARTIFACT.tmp"
        fi
    done

    # Replace the artifact with the updated version
    mv "$IPV6_ARTIFACT.tmp" "$IPV6_ARTIFACT"
    log "INFO" "✅ Artifact fully overwritten with SSH Config hosts and preserved Host * section."
}


# =============================================================================
# Overwrite SSH Config with Artifact Hosts (Preserve Global Host * Section)
# =============================================================================
overwrite_ssh_with_artifact() {
    echo "⚠️ Overwriting SSH Config with artifact hosts..."
    cp "$SSH_CONFIG_FILE" "$SSH_CONFIG_FILE.bak"

    # Preserve the global 'Host *' section at the top
    cat <<EOF > "$SSH_CONFIG_FILE"
Host *
    PKCS11Provider /opt/homebrew/lib/opensc-pkcs11.so
    ForwardAgent no
    ForwardX11 no
    PasswordAuthentication no
    ChallengeResponseAuthentication no

    # Prefer FIDO2 if available
    IdentityFile ~/.ssh/id_ecdsa_sk
    IdentityFile ~/.ssh/id_ecdsa_sk_rk  # Fallback resident key

    IdentitiesOnly no  # Try all identities (FIDO2 + YubiKey PIV)

    # KEX Algorithms - Strong and modern key exchanges
    KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256

    # Ciphers - Strong ciphers only
    Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,chacha20-poly1305@openssh.com

    # Host Key Algorithms - Exclude legacy DSA, use modern algorithms
    HostKeyAlgorithms rsa-sha2-512,rsa-sha2-256,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521

    # Session Management
    ServerAliveInterval 60
    ServerAliveCountMax 3

    Compression no
    StrictHostKeyChecking ask
    UserKnownHostsFile ~/.ssh/known_hosts

    TCPKeepAlive no
    PermitLocalCommand no
    RekeyLimit 1G 1h
    LogLevel VERBOSE
EOF

    # Append individual host configurations from artifact
    jq -c '.[]' "$IPV6_ARTIFACT" | while read -r entry; do
        server=$(echo "$entry" | jq -r '.server')
        ipv6=$(echo "$entry" | jq -r '.ipv6')
        key=$(echo "$entry" | jq -r '.key')

        # Set fallback key based on 'key' value (PIV or FIDO)
        if [[ "$key" == "yubikey" ]]; then
            identity_file="PKCS11Provider /opt/homebrew/lib/opensc-pkcs11.so"
        else
            identity_file="IdentityFile $key"
        fi

        cat <<EOF >> "$SSH_CONFIG_FILE"

Host $server
    HostName $ipv6
    User root
    $identity_file
    IdentitiesOnly yes
EOF
    done
    log "INFO" "✅ SSH Config fully overwritten with artifact hosts and preserved global settings."
}



# =============================================================================
# Restore SSH Config and Artifact from Template
# =============================================================================
restore_ssh_from_template() {
    local ssh_template="$SSH_CONFIG_TEMPLATE"
    local ipv6_template="$IPV6_TEMPLATE"

    # Restore SSH Config and Artifact
    if [ -f "$ssh_template" ]; then
        # Overwrite actual SSH config
        cp "$ssh_template" "$SSH_CONFIG_FILE"
        cp "$ssh_template" ~/.ssh/config
        
        # Overwrite SSH config artifact (in /data)
        cp "$ssh_template" "$SSH_CONFIG_ARTIFACT"
        
        log "INFO" "✅ SSH Config and artifact restored from template."
    else
        log "ERROR" "❌ SSH template file not found at $ssh_template."
    fi

    # Restore IPv6 Artifact Completely
    if [ -f "$ipv6_template" ]; then
        cp "$ipv6_template" "$IPV6_ARTIFACT"
        log "INFO" "✅ IPv6 Artifact restored from template (fully replaced)."
    else
        log "ERROR" "❌ IPv6 artifact template not found at $ipv6_template."
    fi
}




# =============================================================================
# Start SSH Session Based on Artifact (Numbered Selection) - Fixed Subshell Issue
# =============================================================================
start_selected_ssh_session() {
    local servers=()
    local count=1

    echo "Available Servers:"

    # Populate servers array and display options without subshell
    for entry in $(jq -c '.[]' "$IPV6_ARTIFACT"); do
        server=$(echo "$entry" | jq -r '.server')
        ipv6=$(echo "$entry" | jq -r '.ipv6')
        key=$(echo "$entry" | jq -r '.key')

        servers+=("$server")
        echo "$count) $server ($ipv6) -> $key"
        ((count++))
    done

    # Prompt for selection by number
    read -p "Select server by number: " selection

    # Validate selection
    if [[ "$selection" =~ ^[0-9]+$ ]] && [ "$selection" -ge 1 ] && [ "$selection" -le "${#servers[@]}" ]; then
        selected_server="${servers[$((selection - 1))]}"
        echo "🔐 Connecting to $selected_server..."
        ssh "$selected_server"
    else
        echo "❌ Invalid selection. Please enter a valid number."
    fi
}


# =============================================================================
# Main SSH Menu
# =============================================================================
main_ssh_menu() {
    while true; do
        echo -e "\n🔧 YubiKey SSH Configuration Manager"
        echo "1) Sync SSH Configurations"
        echo "2) Manage SSH Config"
        echo "3) Restore SSH Config"
        echo "4) Return to Main Menu"
        read -p "Select an option [1-4]: " choice

        case $choice in
        1) sync_ssh_with_artifact ;;
        2) manage_ipv6_ssh_config ;;
        3) 
            read -p "⚠️  Are you sure you want to restore SSH Config? This will overwrite existing files. (y/n): " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                restore_ssh_from_template
            else
                echo "Restore operation cancelled."
            fi
            ;;
        4) echo "Returning to Main Menu..."; break ;;
        *) echo "❌ Invalid option. Try again." ;;
        esac
    done
}


# =============================================================================
# Manage IP Config Table with YubiKey Support (IPv4 and IPv6)
# =============================================================================
manage_ipv6_ssh_config() {
    mkdir -p "$(dirname "$IPV6_ARTIFACT")"
    touch "$IPV6_ARTIFACT"
    touch "$SSH_CONFIG_ARTIFACT"

    log "INFO" "🤝 Managing SSH configurations (IPv4 and IPv6)..."

    # Display current configurations (visualize artifact)
    if [ -s "$IPV6_ARTIFACT" ]; then
        jq '.' "$IPV6_ARTIFACT"
    else
        echo "No existing configurations."
    fi

    echo -e "\nOptions:"
    echo "1) Add new IP entry"
    echo "2) Remove existing entry"
    echo "3) Return to Main Menu"
    read -p "Select an option: " choice

    case $choice in
    1)
        read -p "Enter IP address (IPv4 or IPv6): " ip_addr
        read -p "Enter server name: " server_name
        read -p "Yubikey or local certificate? (y/n): " use_yubikey

        # Check for existing entries in artifact
        if jq -e --arg server "$server_name" '.[] | select(.server == $server)' "$IPV6_ARTIFACT" > /dev/null; then
            echo -e "${RED}❌ Entry for $server_name already exists in artifact. Skipping...${RESET}"
            log "WARN" "$server_name already exists in artifact. Skipping..."
            return
        fi

        # Check for existing entries in SSH Config
        if grep -q "^Host $server_name\$" "$SSH_CONFIG_FILE"; then
            echo -e "${RED}❌ Host $server_name already exists in SSH config. Skipping...${RESET}"
            log "WARN" "$server_name already exists in SSH config. Skipping..."
            return
        fi

        # Determine IP version (IPv4/IPv6)
        if [[ "$ip_addr" =~ ":" ]]; then
            address_family="inet6"
        else
            address_family="inet"
        fi

        # Add entry logic
        if [ "$use_yubikey" == "y" ]; then
            read -p "Enter username (default: root): " user_name
            user_name=${user_name:-root}

            # Add YubiKey entry to SSH Config
            cat <<EOF >> "$SSH_CONFIG_FILE"

Host $server_name
    HostName $ip_addr
    User $user_name 
    PKCS11Provider /opt/homebrew/lib/opensc-pkcs11.so
    AddressFamily $address_family
    IdentitiesOnly yes
EOF
            new_entry="{\"server\":\"$server_name\", \"ipv6\":\"$ip_addr\", \"key\":\"yubikey\"}"
        else
            read -p "Enter path to SSH key (default: ~/.ssh/id_ecdsa_sk or ~/.ssh/id_ecdsa_sk_rk): " key_path
            if [ -z "$key_path" ]; then
                if [ -f ~/.ssh/id_ecdsa_sk ]; then
                    key_path=~/.ssh/id_ecdsa_sk
                else
                    key_path=~/.ssh/id_ecdsa_sk_rk
                fi
            fi

            # Add entry with SSH key
            cat <<EOF >> "$SSH_CONFIG_FILE"

Host $server_name
    HostName $ip_addr
    User root
    IdentityFile $key_path
    AddressFamily $address_family
    IdentitiesOnly yes
EOF
            new_entry="{\"server\":\"$server_name\", \"ipv6\":\"$ip_addr\", \"key\":\"$key_path\"}"
        fi

        # Update Artifact (store new entry)
        if [ -s "$IPV6_ARTIFACT" ]; then
            jq ". += [$new_entry]" "$IPV6_ARTIFACT" > "$IPV6_ARTIFACT.tmp" && mv "$IPV6_ARTIFACT.tmp" "$IPV6_ARTIFACT"
        else
            echo "[$new_entry]" > "$IPV6_ARTIFACT"
        fi

        # Sync SSH Config to artifact
        cp "$SSH_CONFIG_FILE" "$SSH_CONFIG_ARTIFACT"

        log "INFO" "✅ IP entry saved for $server_name ($ip_addr)."
        echo -e "${GREEN}✅ IP entry saved for $server_name ($ip_addr).${RESET}"
        ;;

    2)
        read -p "Enter server name or IP to remove: " remove_entry

        # Remove from Artifact
        if jq "del(.[] | select(.server == \"$remove_entry\" or .ipv6 == \"$remove_entry\"))" "$IPV6_ARTIFACT" > "$IPV6_ARTIFACT.tmp"; then
            mv "$IPV6_ARTIFACT.tmp" "$IPV6_ARTIFACT"
            log "INFO" "🗑 Entry removed for $remove_entry."

            # Remove entry from SSH Config
            sed -i '' "/^Host $remove_entry\$/,/^$/d" "$SSH_CONFIG_FILE"

            # Sync ~/.ssh/config to artifact
            cp "$SSH_CONFIG_FILE" "$SSH_CONFIG_ARTIFACT"

            echo -e "${GREEN}✅ Entry removed from SSH config and artifact.${RESET}"
        else
            echo -e "${RED}❌ Failed to remove entry for $remove_entry.${RESET}"
            log "ERROR" "Failed to remove entry for $remove_entry."
        fi
        ;;

    3)
        echo "Returning to Main Menu..."
        return
        ;;

    *)
        echo -e "${RED}❌ Invalid option. Try again.${RESET}"
        ;;
    esac
}

