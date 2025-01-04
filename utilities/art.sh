#!/bin/bash
# =============================================================================
# Art Utility File - ASCII Art and Animations
# =============================================================================

# =============================================================================
# Function to Display Company Logo (Replace Placeholder with Actual Logo)
# =============================================================================
ascii_art() {
    clear
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
     __        __   _                            
     \ \      / /__| | ___ ___  _ __ ___   ___  
      \ \ /\ / / _ \ |/ __/ _ \| '_ ` _ \ / _ \ 
       \ V  V /  __/ | (_| (_) | | | | | |  __/ 
        \_/\_/ \___|_|\___\___/|_| |_| |_|\___| 
 
     =========================================
        🐋 Whale Connected - Secure SSH 🌊   
     =========================================
EOF
    echo -e "${RESET}"
}

# =============================================================================
# Function to Display Whale Animation (Plays Once)
# =============================================================================
whale_animation() {
    frames=(
"
            ~~~~~~~~~~~~~~~~~~~
                     \\
                      \\
                       \\
                        \\
                         \\        ____
                          \\      /    \\
                           \\    |      |
                            \\___|______|
                           /            \\
                          /              \\
                 ~~~~~~~/~~~~~~~~~~~~~~~~\~~~~~~"

"
            ~~~~~~~~~~~~~~~~~~~
                     \\
                      \\
                       \\
                        \\
                         \\        ____
                          \\      /    \\
                           \\    | 💨  |
                            \\___|______|
                           /            \\
                          /              \\
                 ~~~~~~~/~~~~~~~~~~~~~~~~\~~~~~~"

"
            ~~~~~~~~~~~~~~~~~~~
                     \\
                      \\
                       \\
                        \\
                         \\        ____
                          \\      /    \\
                           \\    | 💨💨 |
                            \\___|______|
                           /            \\
                          /              \\
                 ~~~~~~~/~~~~~~~~~~~~~~~~\~~~~~~"

"
            ~~~~~~~~~~~~~~~~~~~
                     \\
                      \\
                       \\
                        \\
                         \\        ____
                          \\      /    \\
                           \\    | 💨💨💨|
                            \\___|______|
                           /            \\
                          /              \\
                 ~~~~~~~/~~~~~~~~~~~~~~~~\~~~~~~"

"
            ~~~~~~~~~~~~~~~~~~~
                     \\
                      \\
                       \\
                        \\
                         \\        ____
                          \\      /    \\
                           \\    | 💨💨 |
                            \\___|______|
                           /            \\
                          /              \\
                 ~~~~~~~/~~~~~~~~~~~~~~~~\~~~~~~"

"
            ~~~~~~~~~~~~~~~~~~~
                     \\
                      \\
                       \\
                        \\
                         \\        ____
                          \\      /    \\
                           \\    |  💨  |
                            \\___|______|
                           /            \\
                          /              \\
                 ~~~~~~~/~~~~~~~~~~~~~~~~\~~~~~~"
    )
    delay=0.3  # Duration between frames in seconds
    loops=2     # Number of animation loops

    # Hide cursor
    tput civis

    for ((i=0;i<loops;i++)); do
        for frame in "${frames[@]}"; do
            echo -e "${BLUE}${frame}${RESET}"
            sleep "$delay"
            clear
            ascii_art
        done
    done

    # Show cursor
    tput cnorm
}
