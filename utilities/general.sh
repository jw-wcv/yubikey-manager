# Log UX
log() {
    local level="$1"
    local msg="$2"
    echo -e "$(date) [$level] - $msg" | tee -a "$log_file"
}

# Error UX
error_exit() {
    log "ERROR" "$1"
    exit 1
}

# Spinner for UX
spinner() {
    local pid=$!
    local delay=0.1
    local spinstr='|/-\\'
    while ps -p $pid &>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    wait $pid
    return $?
}

# Rotate in Logs
log_rotate() {
    if [ -f "$log_file" ]; then
        mv "$log_file" "$log_file.bak.$(date +%s)"
    fi
}