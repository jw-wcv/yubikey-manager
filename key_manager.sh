#!/bin/bash

# =============================================================================
# 🐋 Whale Connected - YubiKey Manager v6.0 - Enhanced UI
# =============================================================================


# =============================================================================
# Define Color Codes
# =============================================================================
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
MAGENTA='\033[35m'
CYAN='\033[36m'
BOLD='\033[1m'
RESET='\033[0m'


# =============================================================================
# Log File
# =============================================================================
log_file="./resources/logs/yubikey_manager.log"


# =============================================================================
# Load Utilities and Environment
# =============================================================================
# Dynamically load all utility scripts and environment variables
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/utilities/loader.sh"


# =============================================================================
# Trap to Ensure Cursor Visibility on Exit
# =============================================================================
trap "tput cnorm; echo -e '\n${RED}✖️  Script interrupted. Exiting...${RESET}'; exit" SIGINT SIGTERM


# =============================================================================
# Function to Display Main Menu
# =============================================================================
main_menu() {
    while true; do
        # Display Menu Header
        echo -e "${CYAN}${BOLD}🛠️  YubiKey Manager${RESET}"
        echo -e "${MAGENTA}${BOLD}Main Menu:${RESET}"
        echo -e "${YELLOW}=========================================${RESET}"
        echo -e "${YELLOW}1) Setup${RESET}"
        echo -e "${YELLOW}2) Keys Management${RESET}"
        echo -e "${YELLOW}3) SSH Operations${RESET}"
        echo -e "${YELLOW}4) Settings${RESET}"
        echo -e "${YELLOW}5) Exit${RESET}"
        echo -e "${YELLOW}=========================================${RESET}"
        echo ""

        # Prompt for User Input
        read -rp "$(echo -e "${CYAN}Select an option [1-5]: ${RESET}")" main_choice

        case $main_choice in
            1)
                setup_menu
                ;;
            2)
                keys_management_menu
                ;;
            3)
                ssh_operations_menu
                ;;
            4)
                settings_menu
                ;;
            5)
                log "INFO" "👋 Exiting YubiKey Manager. Goodbye!"
                echo -e "${GREEN}✅ Exiting YubiKey Manager. Goodbye!${RESET}"
                exit 0
                ;;
            *)
                log "WARN" "Invalid option. Try again."
                echo -e "${RED}❌ Invalid option. Please try again.${RESET}"
                sleep 1
                ;;
        esac
    done
}

# =============================================================================
# Function for Setup Submenu
# =============================================================================
setup_menu() {
    while true; do
        clear
        ascii_art
        echo -e "${CYAN}${BOLD}🛠️  YubiKey Manager - Setup${RESET}"
        echo -e "${MAGENTA}${BOLD}Setup Menu:${RESET}"
        echo -e "${YELLOW}=========================================${RESET}"
        echo -e "${YELLOW}1) Install Dependencies${RESET}"
        echo -e "${YELLOW}2) Configure YubiKey (PIN, PUK, Management Key)${RESET}"
        echo -e "${YELLOW}3) Configure Yubikey for SSH${RESET}"
        echo -e "${YELLOW}4) 🚀 Ready Check 🚀${RESET}"
        echo -e "${YELLOW}5) Back to Main Menu${RESET}"
        echo -e "${YELLOW}=========================================${RESET}"
        echo ""

        read -rp "$(echo -e "${CYAN}Select an option [1-5]: ${RESET}")" setup_choice

        case $setup_choice in
            1)
                check_dependencies
                ;;
            2)
                configure_yubikey
                ;;
            3)
                setup_yubikey_for_ssh
                ;;
            4)
                ready_check
                ;;
            5)
                break
                ;;
            *)
                echo -e "${RED}❌ Invalid option. Please try again.${RESET}"
                sleep 1
                ;;
        esac

        # Prompt to return to Setup Menu
        echo ""
        read -rp "$(echo -e "${CYAN}Press Enter to continue...${RESET}")" _
    done
}

# =============================================================================
# Function for Keys Management Submenu
# =============================================================================
keys_management_menu() {
    while true; do
        clear
        ascii_art
        echo -e "${CYAN}${BOLD}🛠️  YubiKey Manager - Keys Management${RESET}"
        echo -e "${MAGENTA}${BOLD}Keys Management Menu:${RESET}"
        echo -e "${YELLOW}=========================================${RESET}"
        echo -e "${YELLOW}1) Generate FIDO2 SSH Key${RESET}"
        echo -e "${YELLOW}2) Generate ssh-rsa PIV Key${RESET}"
        echo -e "${YELLOW}3) Package PKCS12 PIV Key${RESET}"
        echo -e "${YELLOW}4) Import SSH Key${RESET}"
        echo -e "${YELLOW}5) Export SSH Keys${RESET}"
        echo -e "${YELLOW}6) List SSH Keys${RESET}"
        echo -e "${YELLOW}7) Remove SSH Key from YubiKey${RESET}"
        echo -e "${YELLOW}8) Back to Main Menu${RESET}"
        echo -e "${YELLOW}=========================================${RESET}"
        echo ""

        read -rp "$(echo -e "${CYAN}Select an option [1-8]: ${RESET}")" keys_choice

        case $keys_choice in
            1)
                setup_fido2_ssh
                ;;
            2)
                setup_rsa_piv_ssh
                ;;
            3)
                convert_pem_to_pkcs12
                ;;    
            4)
                select_key_from_list
                ;;
            5)
                export_ssh_public_key
                ;;
            6)
                list_keys
                ;;
            7)
                remove_key_from_yubikey
                ;;
            8)
                break
                ;;
            *)
                echo -e "${RED}❌ Invalid option. Please try again.${RESET}"
                sleep 1
                ;;
        esac

        # Prompt to return to Keys Management Menu
        echo ""
        read -rp "$(echo -e "${CYAN}Press Enter to continue...${RESET}")" _
    done
}

# =============================================================================
# Function for SSH Operations Submenu
# =============================================================================
ssh_operations_menu() {
    while true; do
        clear
        ascii_art
        echo -e "${CYAN}${BOLD}🛠️  YubiKey Manager - SSH Operations${RESET}"
        echo -e "${MAGENTA}${BOLD}SSH Operations Menu:${RESET}"
        echo -e "${YELLOW}=========================================${RESET}"
        echo -e "${YELLOW}1) Manage SSH Configurations${RESET}"
        echo -e "${YELLOW}2) Start SSH Session${RESET}"
        echo -e "${YELLOW}3) Back to Main Menu${RESET}"
        echo -e "${YELLOW}=========================================${RESET}"
        echo ""

        read -rp "$(echo -e "${CYAN}Select an option [1-3]: ${RESET}")" ssh_choice

        case $ssh_choice in
            1)
                manage_ipv6_ssh_config
                ;;
            2)
                start_selected_ssh_session
                ;;
            3)
                break
                ;;
            *)
                echo -e "${RED}❌ Invalid option. Please try again.${RESET}"
                sleep 1
                ;;
        esac

        # Prompt to return to SSH Operations Menu
        echo ""
        read -rp "$(echo -e "${CYAN}Press Enter to continue...${RESET}")" _
    done
}

# =============================================================================
# Function for Settings Submenu
# =============================================================================
settings_menu() {
    while true; do
        clear
        ascii_art
        echo -e "${CYAN}${BOLD}🛠️  YubiKey Manager - Settings${RESET}"
        echo -e "${MAGENTA}${BOLD}Settings Menu:${RESET}"
        echo -e "${YELLOW}=========================================${RESET}"
        echo -e "${YELLOW}1) Backup Configuration${RESET}"
        echo -e "${YELLOW}2) Restore Configuration${RESET}"
        echo -e "${YELLOW}3) Factory Reset YubiKey${RESET}"
        echo -e "${YELLOW}4) Manage OSX Disk Encryption${RESET}"
        echo -e "${YELLOW}5) Manage Smart Cards${RESET}"  
        echo -e "${YELLOW}6) Manage OpenPGP Keys${RESET}"
        echo -e "${YELLOW}7) Back to Main Menu${RESET}"
        echo -e "${YELLOW}=========================================${RESET}"
        echo ""

        read -rp "$(echo -e "${CYAN}Select an option [1-7]: ${RESET}")" settings_choice

        case $settings_choice in
            1)
                backup_configuration
                ;;
            2)
                restore_configuration
                ;;
            3)
                factory_reset_yubikey
                ;;
            4)
                manage_disk_encryption
                ;;
            5)
                configure_smart_cards  
                ;;
            6)
                manage_openpgp_keys
                ;;
            7)
                break
                ;;
            *)
                echo -e "${RED}❌ Invalid option. Please try again.${RESET}"
                sleep 1
                ;;
        esac

        # Prompt to return to Settings Menu
        echo ""
        read -rp "$(echo -e "${CYAN}Press Enter to continue...${RESET}")" _
    done
}

# =============================================================================
# Start the Script
# =============================================================================
# Ensure dependencies are installed before launching
check_dependencies

# Display Company Logo and Whale Animation once on startup
ascii_art
whale_animation

# Start the main menu
main_menu
