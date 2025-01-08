#!/bin/bash

# =============================================================================
# 🐋 Whale Connected - YubiKey & SSH Manager
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
        echo -e "${YELLOW}1) Configure Yubikey for SSH${RESET}"
        echo -e "${YELLOW}2) 🚀 Ready Check 🚀${RESET}"
        echo -e "${YELLOW}3) Back to Main Menu${RESET}"
        echo -e "${YELLOW}=========================================${RESET}"
        echo ""

        read -rp "$(echo -e "${CYAN}Select an option [1-3]: ${RESET}")" setup_choice

        case $setup_choice in
            1)
                setup_yubikey_for_ssh
                ;;
            2)
                ready_checkv
                ;;
            3)
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
        echo -e "${YELLOW}1) List SSH Keys${RESET}"
        echo -e "${YELLOW}2) Manage FIDO2 Key${RESET}"
        echo -e "${YELLOW}3) Manage RSA/PIV Keys${RESET}"
        echo -e "${YELLOW}4) Export SSH Keys${RESET}"
        echo -e "${YELLOW}5) Remove SSH Key from YubiKey${RESET}"
        echo -e "${YELLOW}6) Back to Main Menu${RESET}"
        echo -e "${YELLOW}=========================================${RESET}"
        echo ""

        read -rp "$(echo -e "${CYAN}Select an option [1-6]: ${RESET}")" keys_choice

        case $keys_choice in
            1)
                list_keys
                ;;
            2)
                setup_fido2_ssh
                ;;
            3)
                setup_rsa_piv_ssh
                ;;
            4)
                export_ssh_public_key
                ;;
            5)
                remove_key_from_yubikey
                ;;
            6)
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
                main_ssh_menu
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
# Function for Settings Submenu  manage_yubikey_pins
# =============================================================================
settings_menu() { #adding PIN Manager, ~/.ssh/config + ssh-add Manager etc
    while true; do
        clear
        ascii_art
        echo -e "${CYAN}${BOLD}🛠️  YubiKey Manager - Settings${RESET}"
        echo -e "${MAGENTA}${BOLD}Settings Menu:${RESET}"
        echo -e "${YELLOW}=========================================${RESET}"
        echo -e "${YELLOW}1) Manage Yubikey PINs${RESET}"
        echo -e "${YELLOW}2) Manage OSX Disk Encryption${RESET}"
        echo -e "${YELLOW}3) Manage Smart Cards${RESET}"  
        echo -e "${YELLOW}4) Manage OpenPGP Keys${RESET}"
        echo -e "${YELLOW}5) Factory Reset YubiKey${RESET}"
        echo -e "${YELLOW}6) Reset ~/.SSH+ Perms${RESET}"
        echo -e "${YELLOW}7) Back to Main Menu${RESET}"
        echo -e "${YELLOW}=========================================${RESET}"
        echo ""

        read -rp "$(echo -e "${CYAN}Select an option [1-7]: ${RESET}")" settings_choice

        case $settings_choice in
            1)
                manage_yubikey_pins
                ;;
            2)
                manage_disk_encryption
                ;;
            3)
                configure_smart_cards  
                ;;
            4)
                manage_openpgp_keys
                ;;
            5)
                factory_reset_yubikey
                ;;
            6)
                factory_reset_yubikey
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
