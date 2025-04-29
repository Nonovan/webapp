#!/bin/bash
# Memory Acquisition Script for Live Response Forensics
#
# This script acquires memory dumps from live systems during incident response,
# ensuring forensic integrity through proper hashing, chain of custody
# documentation, and minimizing system impact.

# Load common utility functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common_functions.sh"

# Script version
MEMORY_ACQUISITION_VERSION="1.0.0"
MEMORY_ACQUISITION_DATE="2024-08-16"

# --- Configuration ---
DEFAULT_OUTPUT_FORMAT="raw"           # Default memory dump format (raw, lime, aff4, etc.)
DEFAULT_COMPRESSION="true"            # Whether to compress memory dumps by default
DEFAULT_COMPRESSION_ALGO="zstd"       # Default compression algorithm for memory dumps
DEFAULT_CHUNK_SIZE="2G"               # Default memory acquisition chunk size to avoid OOM
DEFAULT_VERIFY_ACQUISITION="true"     # Verify acquisition integrity by default
DEFAULT_METADATA_COLLECTION="true"    # Collect system metadata along with memory dump
DEFAULT_RETAIN_LOGS="true"            # Keep detailed acquisition logs
DEFAULT_ACQUIRE_PAGEFILE="true"       # Whether to acquire pagefile/swap as well
DEFAULT_METHOD="auto"                 # Default acquisition method (auto, lime, winpmem, etc.)
DEFAULT_REMOTE_PORT="22"              # Default SSH port for remote acquisition
DEFAULT_TIMEOUT="3600"                # Default timeout for acquisition (1 hour)

# Load tool paths from configuration
TOOL_DEPENDENCIES_FILE="${SCRIPT_DIR}/tool_dependencies.conf"

# --- Main Functions ---

# Print usage information
usage() {
    cat << EOF
Memory Acquisition Script v${MEMORY_ACQUISITION_VERSION} (${MEMORY_ACQUISITION_DATE})

Usage: $(basename "$0") [OPTIONS]

Options:
  -h, --help                 Show this help message
  -o, --output PATH          Output file for memory dump (default: memory_<hostname>_<timestamp>.<format>)
  -f, --format FORMAT        Dump format: raw, lime, aff4, vmem (default: ${DEFAULT_OUTPUT_FORMAT})
  -m, --method METHOD        Acquisition method: auto, lime, winpmem, avml, dd (default: ${DEFAULT_METHOD})
                             'auto' will select the best method based on target OS

  Target Options:
  -t, --target HOST          Remote target hostname or IP (if not specified, local acquisition is performed)
  -u, --user USER            Username for SSH connection to remote target
  -k, --key KEY_FILE         SSH key file for authentication
  -p, --port PORT            SSH port for remote target (default: ${DEFAULT_REMOTE_PORT})

  Acquisition Options:
  -c, --compress             Compress memory dump (default: ${DEFAULT_COMPRESSION})
  --no-compress              Do not compress memory dump
  --compression-algo ALGO    Compression algorithm: zstd, gzip, xz (default: ${DEFAULT_COMPRESSION_ALGO})
  --chunk-size SIZE          Split acquisition into chunks of specified size (default: ${DEFAULT_CHUNK_SIZE})
  --verify                   Verify acquisition integrity (default: ${DEFAULT_VERIFY_ACQUISITION})
  --no-verify                Skip verification
  --acquire-pagefile         Acquire pagefile/swap (default: ${DEFAULT_ACQUIRE_PAGEFILE})
  --no-pagefile              Skip pagefile/swap acquisition

  Case Management:
  --case-id ID               Case identifier for evidence tracking
  --examiner ID              Examiner identifier for chain of custody
  --evidence-id ID           Pre-assigned evidence ID (if applicable)

  Advanced Options:
  --pre-acquisition-cmd CMD  Command to run before acquisition
  --post-acquisition-cmd CMD Command to run after acquisition
  --timeout SECONDS          Timeout for acquisition in seconds (default: ${DEFAULT_TIMEOUT})
  --hash-algo ALGO           Hash algorithm: md5, sha1, sha256, sha512 (default: ${DEFAULT_HASH_ALGO})
  --custom-params PARAMS     Custom parameters to pass to the acquisition tool

  Analysis Options:
  --analyze-volatility       Perform immediate basic analysis using Volatility
  --profile PROFILE          Volatility profile for analysis
  --ioc-file FILE            IOC file to check against memory dump

  Output Control:
  -v, --verbose              Show more detailed output
  -q, --quiet                Suppress non-error output
  --log FILE                 Log file path
  --audit-log FILE           Audit log file path
  --metadata-file FILE       Save system metadata to specified file
  --no-metadata              Do not collect system metadata
  --version                  Show version information and exit
EOF
    exit 0
}

# Show version information
show_version() {
    echo "Memory Acquisition Script v${MEMORY_ACQUISITION_VERSION} (${MEMORY_ACQUISITION_DATE})"
    echo "Using Common Functions v$(get_common_live_response_version)"
    exit 0
}

# Initialize environment for memory acquisition
init_acquisition_environment() {
    log_info "Initializing memory acquisition environment"

    # Load tool dependencies
    if [[ -f "$TOOL_DEPENDENCIES_FILE" ]]; then
        load_tool_dependencies "$TOOL_DEPENDENCIES_FILE" ||
            log_warn "Failed to load tool dependencies from $TOOL_DEPENDENCIES_FILE"
    else
        log_warn "Tool dependencies file not found: $TOOL_DEPENDENCIES_FILE"
    fi

    # Create necessary directories
    if [[ -n "$OUTPUT_FILE" ]]; then
        local output_dir
        output_dir="$(dirname "$OUTPUT_FILE")"
        ensure_output_dir "$output_dir" || error_exit "Failed to create output directory: $output_dir"
    fi

    # Initialize acquisition command
    ACQUISITION_COMMAND=""

    log_info "Environment initialized successfully"
}

# Determine the best acquisition method based on target OS and available tools
determine_acquisition_method() {
    if [[ "$METHOD" != "auto" ]]; then
        log_info "Using specified acquisition method: $METHOD"
        return 0
    fi

    log_info "Determining best acquisition method for target"

    local os_type

    # Determine if target is remote or local
    if [[ -n "$TARGET_HOST" ]]; then
        # Remote target - try to determine OS
        if ! ssh_command="ssh"; [[ -n "$SSH_KEY" ]] && ssh_command+=" -i $SSH_KEY";
           [[ -n "$SSH_PORT" ]] && ssh_command+=" -p $SSH_PORT";
           ssh_command+=" ${TARGET_USER}@${TARGET_HOST} 'uname -s'";
           os_type=$(eval "$ssh_command" 2>/dev/null); then
            log_warn "Failed to determine remote OS type, defaulting to Linux"
            os_type="Linux" # Default to Linux for remote targets
        fi
    else
        # Local target
        os_type=$(uname -s)
    fi

    log_debug "Detected OS type: $os_type"

    case "$os_type" in
        Linux)
            # For Linux, prefer LiME, then AVML, then dd
            if check_tool_dependency "memory_acquisition" "lime"; then
                METHOD="lime"
            elif check_tool_dependency "memory_acquisition" "avml"; then
                METHOD="avml"
            else
                METHOD="dd"
                log_warn "Using dd for memory acquisition - less reliable than specialized tools"
            fi
            ;;
        Darwin)
            # For macOS, use macOS specific tools
            METHOD="mac_memory"
            ;;
        MINGW*|MSYS*|Windows*)
            # For Windows, use WinPmem
            METHOD="winpmem"
            ;;
        *)
            log_warn "Unknown OS type: $os_type. Defaulting to dd method."
            METHOD="dd"
            ;;
    esac

    log_info "Selected acquisition method: $METHOD"
    return 0
}

# Prepare for memory acquisition
prepare_acquisition() {
    log_info "Preparing for memory acquisition"

    # Set default output filename if not specified
    if [[ -z "$OUTPUT_FILE" ]]; then
        local hostname
        if [[ -n "$TARGET_HOST" ]]; then
            hostname="$TARGET_HOST"
        else
            hostname=$(hostname)
        fi

        local timestamp
        timestamp=$(get_filename_timestamp)

        # Default to OUTPUT_DIR/memory_<hostname>_<timestamp>.<format>
        OUTPUT_FILE="${OUTPUT_DIR}/memory_${hostname}_${timestamp}.${FORMAT}"
        log_info "Output file set to: $OUTPUT_FILE"
    fi

    # Determine best acquisition method if set to auto
    determine_acquisition_method

    # Run pre-acquisition commands if specified
    if [[ -n "$PRE_ACQUISITION_CMD" ]]; then
        log_info "Running pre-acquisition command"

        if [[ -n "$TARGET_HOST" ]]; then
            # Run on remote target
            execute_remote_command "$PRE_ACQUISITION_CMD" ||
                log_warn "Pre-acquisition command failed on remote target"
        else
            # Run locally
            eval "$PRE_ACQUISITION_CMD" ||
                log_warn "Pre-acquisition command failed"
        fi
    fi

    # Create metadata file (system information before acquisition)
    if [[ "$COLLECT_METADATA" == "true" ]]; then
        # Set default metadata filename if not specified
        if [[ -z "$METADATA_FILE" ]]; then
            METADATA_FILE="${OUTPUT_FILE}.metadata.json"
        fi

        collect_system_metadata ||
            log_warn "Failed to collect system metadata"
    fi

    # Log preparation complete
    log_info "Acquisition preparation complete"

    return 0
}

# Execute a command on a remote target via SSH
execute_remote_command() {
    local command="$1"
    local timeout="${2:-$TIMEOUT}"
    local ssh_cmd="ssh"

    [[ -n "$SSH_KEY" ]] && ssh_cmd+=" -i $SSH_KEY"
    [[ -n "$SSH_PORT" ]] && ssh_cmd+=" -p $SSH_PORT"

    ssh_cmd+=" -o ConnectTimeout=30 -o StrictHostKeyChecking=accept-new ${TARGET_USER}@${TARGET_HOST}"

    log_debug "Executing remote command: $command"
    timeout "$timeout" $ssh_cmd "$command"
    return $?
}

# Build and return the appropriate acquisition command
build_acquisition_command() {
    local output="$1"

    case "$METHOD" in
        lime)
            build_lime_command "$output"
            ;;
        avml)
            build_avml_command "$output"
            ;;
        winpmem)
            build_winpmem_command "$output"
            ;;
        dd)
            build_dd_command "$output"
            ;;
        mac_memory)
            build_mac_memory_command "$output"
            ;;
        *)
            log_error "Unsupported acquisition method: $METHOD"
            return 1
            ;;
    esac

    return 0
}

# Build command for LiME acquisition
build_lime_command() {
    local output="$1"
    local lime_path
    lime_path=$(get_tool_path "memory_acquisition" "lime")
    local lime_util_path
    lime_util_path=$(get_tool_path "memory_acquisition" "lime_util")

    if [[ -z "$lime_path" ]]; then
        log_warn "LiME kernel module path not found in config, using fallback"
        lime_path="/opt/lime/lime.ko"
    fi

    local format_arg=""
    case "$FORMAT" in
        lime|raw) format_arg="format=lime" ;;
        padded) format_arg="format=padded" ;;
        *)
            log_warn "Unsupported format $FORMAT for LiME, defaulting to lime format"
            format_arg="format=lime"
            ;;
    esac

    # Build LiME command
    if [[ -n "$TARGET_HOST" ]]; then
        # Remote acquisition
        local remote_output="/tmp/memory_$$.lime"
        local scp_output_cmd

        # First part: Load LiME module on remote system
        local load_cmd="insmod ${lime_path} path=${remote_output} ${format_arg} ${CUSTOM_PARAMS}"

        # Second part: Copy the memory image back to the acquisition system
        scp_output_cmd="scp"
        [[ -n "$SSH_KEY" ]] && scp_output_cmd+=" -i $SSH_KEY"
        [[ -n "$SSH_PORT" ]] && scp_output_cmd+=" -P $SSH_PORT"
        scp_output_cmd+=" ${TARGET_USER}@${TARGET_HOST}:${remote_output} ${output}"

        # Third part: Clean up the remote file
        local cleanup_cmd="rm -f ${remote_output}"

        ACQUISITION_COMMAND="execute_remote_command \"sudo ${load_cmd}\" && ${scp_output_cmd} && execute_remote_command \"sudo ${cleanup_cmd}\""
    else
        # Local acquisition
        ACQUISITION_COMMAND="sudo insmod ${lime_path} path=${output} ${format_arg} ${CUSTOM_PARAMS}"
    fi

    log_debug "LiME acquisition command: $ACQUISITION_COMMAND"
    return 0
}

# Build command for AVML acquisition
build_avml_command() {
    local output="$1"
    local avml_path
    avml_path=$(get_tool_path "memory_acquisition" "avml")

    if [[ -z "$avml_path" ]]; then
        log_warn "AVML binary path not found in config, using fallback"
        avml_path="/usr/local/bin/avml"
    fi

    # Build AVML command
    if [[ -n "$TARGET_HOST" ]]; then
        # For remote acquisition with AVML, we need to:
        # 1. Copy AVML to the remote system
        # 2. Execute AVML on the remote system
        # 3. Copy the memory image back
        # 4. Clean up

        local remote_avml="/tmp/avml_$$"
        local remote_output="/tmp/memory_$$.raw"
        local scp_tool_cmd
        local scp_output_cmd

        # Copy AVML to remote system
        scp_tool_cmd="scp"
        [[ -n "$SSH_KEY" ]] && scp_tool_cmd+=" -i $SSH_KEY"
        [[ -n "$SSH_PORT" ]] && scp_tool_cmd+=" -P $SSH_PORT"
        scp_tool_cmd+=" ${avml_path} ${TARGET_USER}@${TARGET_HOST}:${remote_avml}"

        # Execute AVML on remote system
        local run_cmd="chmod +x ${remote_avml} && sudo ${remote_avml} ${remote_output} ${CUSTOM_PARAMS}"

        # Copy memory image back
        scp_output_cmd="scp"
        [[ -n "$SSH_KEY" ]] && scp_output_cmd+=" -i $SSH_KEY"
        [[ -n "$SSH_PORT" ]] && scp_output_cmd+=" -P $SSH_PORT"
        scp_output_cmd+=" ${TARGET_USER}@${TARGET_HOST}:${remote_output} ${output}"

        # Clean up remote files
        local cleanup_cmd="rm -f ${remote_avml} ${remote_output}"

        ACQUISITION_COMMAND="${scp_tool_cmd} && execute_remote_command \"${run_cmd}\" && ${scp_output_cmd} && execute_remote_command \"${cleanup_cmd}\""
    else
        # Local acquisition
        ACQUISITION_COMMAND="sudo ${avml_path} ${output} ${CUSTOM_PARAMS}"
    fi

    log_debug "AVML acquisition command: $ACQUISITION_COMMAND"
    return 0
}

# Build command for WinPmem acquisition
build_winpmem_command() {
    local output="$1"
    local winpmem_path
    winpmem_path=$(get_tool_path "memory_acquisition" "winpmem")

    if [[ -z "$winpmem_path" ]]; then
        log_warn "WinPmem binary path not found in config, using fallback"
        winpmem_path="/opt/forensic_tools/winpmem/winpmem.exe"
    fi

    # Get appropriate architecture
    local arch_suffix=""
    if [[ -n "$TARGET_HOST" ]]; then
        # Try to determine architecture
        local arch_check="wmic os get osarchitecture"
        local arch
        arch=$(execute_remote_command "$arch_check" | grep -i "bit" | grep -o "[0-9]*")

        if [[ "$arch" == "64" ]]; then
            arch_suffix="_x64"
        elif [[ "$arch" == "32" ]]; then
            arch_suffix="_x86"
        else
            log_warn "Could not determine Windows architecture, defaulting to x64"
            arch_suffix="_x64"
        fi
    else
        # Local Windows - determine architecture
        if [[ "$(uname -m)" == *"64"* ]]; then
            arch_suffix="_x64"
        else
            arch_suffix="_x86"
        fi
    fi

    # Ensure we have the correct binary
    winpmem_path="${winpmem_path%.*}${arch_suffix}.exe"

    # Format parameter
    local format_param=""
    case "$FORMAT" in
        raw) format_param="-r" ;;
        aff4) format_param="-a" ;;
        *)
            log_warn "Unsupported format ${FORMAT} for WinPmem, defaulting to raw"
            format_param="-r"
            ;;
    esac

    # Build WinPmem command
    if [[ -n "$TARGET_HOST" ]]; then
        # For remote Windows acquisition, we need to:
        # 1. Copy WinPmem to the remote system
        # 2. Execute WinPmem on the remote system
        # 3. Copy the memory image back
        # 4. Clean up

        local remote_winpmem="C:\\Windows\\Temp\\winpmem_$$.exe"
        local remote_output="C:\\Windows\\Temp\\memory_$$.raw"
        local remote_winpmem_unix="/cygdrive/c/Windows/Temp/winpmem_$$.exe"
        local remote_output_unix="/cygdrive/c/Windows/Temp/memory_$$.raw"

        # Copy WinPmem to remote system (ensure Windows style paths)
        local scp_tool_cmd="scp"
        [[ -n "$SSH_KEY" ]] && scp_tool_cmd+=" -i $SSH_KEY"
        [[ -n "$SSH_PORT" ]] && scp_tool_cmd+=" -P $SSH_PORT"
        scp_tool_cmd+=" ${winpmem_path} ${TARGET_USER}@${TARGET_HOST}:${remote_winpmem_unix}"

        # Execute WinPmem on remote system
        local run_cmd="${remote_winpmem//\\/\\\\} ${format_param} -o ${remote_output//\\/\\\\} ${CUSTOM_PARAMS}"

        # Copy memory image back
        local scp_output_cmd="scp"
        [[ -n "$SSH_KEY" ]] && scp_output_cmd+=" -i $SSH_KEY"
        [[ -n "$SSH_PORT" ]] && scp_output_cmd+=" -P $SSH_PORT"
        scp_output_cmd+=" ${TARGET_USER}@${TARGET_HOST}:${remote_output_unix} ${output}"

        # Clean up remote files
        local cleanup_cmd="del /F /Q \"${remote_winpmem}\" \"${remote_output}\""

        ACQUISITION_COMMAND="${scp_tool_cmd} && execute_remote_command \"${run_cmd}\" && ${scp_output_cmd} && execute_remote_command \"${cleanup_cmd}\""
    else
        # Local acquisition on Windows
        ACQUISITION_COMMAND="${winpmem_path} ${format_param} -o ${output} ${CUSTOM_PARAMS}"
    fi

    log_debug "WinPmem acquisition command: $ACQUISITION_COMMAND"
    return 0
}

# Build command for dd-based acquisition (fallback)
build_dd_command() {
    local output="$1"
    local dd_path
    dd_path=$(get_tool_path "memory_acquisition" "dd")

    if [[ -z "$dd_path" ]]; then
        log_warn "dd binary path not found in config, using fallback"
        dd_path="/bin/dd"

        # Check for ddrescue as a better alternative
        local ddrescue_path
        ddrescue_path=$(get_tool_path "memory_acquisition" "ddrescue")
        if [[ -n "$ddrescue_path" ]]; then
            log_info "Using ddrescue instead of dd for more reliable acquisition"
            dd_path="$ddrescue_path"
        fi
    fi

    # Define memory device based on OS
    local memory_device=""
    if [[ -e "/dev/crash" ]]; then
        memory_device="/dev/crash"
    elif [[ -e "/proc/kcore" ]]; then
        memory_device="/proc/kcore"
    elif [[ -e "/dev/mem" ]]; then
        memory_device="/dev/mem"
    else
        log_error "No memory device found for acquisition"
        return 1
    fi

    # Set block size and other options
    local bs="1M"
    local conv_opts="sync,noerror"
    local count_opt=""

    # For /proc/kcore, we don't want to use a count, just copy until EOF
    if [[ "$memory_device" != "/proc/kcore" ]]; then
        # Try to determine memory size
        local mem_size
        mem_size=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}')
        if [[ -n "$mem_size" ]]; then
            # Convert to blocks
            local block_count=$(( (mem_size * 1024) / (1024 * 1024) + 1 ))
            count_opt="count=${block_count}"
        fi
    fi

    # Build dd command
    if [[ -n "$TARGET_HOST" ]]; then
        # Remote acquisition
        local remote_output="/tmp/memory_$$.raw"
        local scp_output_cmd

        # Build remote dd command
        local dd_cmd
        if [[ "$dd_path" == *"ddrescue"* ]]; then
            dd_cmd="sudo ${dd_path} ${memory_device} ${remote_output}"
        else
            dd_cmd="sudo ${dd_path} if=${memory_device} of=${remote_output} bs=${bs} ${count_opt} conv=${conv_opts}"
        fi

        # Copy memory image back
        scp_output_cmd="scp"
        [[ -n "$SSH_KEY" ]] && scp_output_cmd+=" -i $SSH_KEY"
        [[ -n "$SSH_PORT" ]] && scp_output_cmd+=" -P $SSH_PORT"
        scp_output_cmd+=" ${TARGET_USER}@${TARGET_HOST}:${remote_output} ${output}"

        # Clean up remote file
        local cleanup_cmd="rm -f ${remote_output}"

        ACQUISITION_COMMAND="execute_remote_command \"${dd_cmd}\" && ${scp_output_cmd} && execute_remote_command \"${cleanup_cmd}\""
    else
        # Local acquisition
        if [[ "$dd_path" == *"ddrescue"* ]]; then
            ACQUISITION_COMMAND="sudo ${dd_path} ${memory_device} ${output}"
        else
            ACQUISITION_COMMAND="sudo ${dd_path} if=${memory_device} of=${output} bs=${bs} ${count_opt} conv=${conv_opts} status=progress"
        fi
    fi

    log_debug "DD acquisition command: $ACQUISITION_COMMAND"
    return 0
}

# Build command for macOS memory acquisition
build_mac_memory_command() {
    local output="$1"

    # Check for macOS memory acquisition tools
    local osxpmem_path
    osxpmem_path=$(get_tool_path "memory_acquisition" "osxpmem")

    if [[ -z "$osxpmem_path" ]]; then
        log_warn "OSXPmem binary path not found in config, checking alternatives"

        # Try to locate macOS memory acquisition tools
        for tool in "/usr/local/bin/osxpmem" "/opt/forensic_tools/osxpmem/osxpmem"; do
            if [[ -x "$tool" ]]; then
                osxpmem_path="$tool"
                log_debug "Found OSXPmem at: $osxpmem_path"
                break
            fi
        done

        if [[ -z "$osxpmem_path" ]]; then
            log_error "No macOS memory acquisition tools found"
            return 1
        fi
    fi

    # Build OSXPmem command
    if [[ -n "$TARGET_HOST" ]]; then
        # Remote macOS acquisition
        local remote_output="/tmp/memory_$$.raw"
        local scp_tool_cmd
        local scp_output_cmd

        # Copy OSXPmem to remote system if needed
        scp_tool_cmd="scp"
        [[ -n "$SSH_KEY" ]] && scp_tool_cmd+=" -i $SSH_KEY"
        [[ -n "$SSH_PORT" ]] && scp_tool_cmd+=" -P $SSH_PORT"
        scp_tool_cmd+=" ${osxpmem_path} ${TARGET_USER}@${TARGET_HOST}:/tmp/osxpmem_$$"

        # Execute OSXPmem on remote system
        local run_cmd="chmod +x /tmp/osxpmem_$$ && sudo /tmp/osxpmem_$$ -o ${remote_output} ${CUSTOM_PARAMS}"

        # Copy memory image back
        scp_output_cmd="scp"
        [[ -n "$SSH_KEY" ]] && scp_output_cmd+=" -i $SSH_KEY"
        [[ -n "$SSH_PORT" ]] && scp_output_cmd+=" -P $SSH_PORT"
        scp_output_cmd+=" ${TARGET_USER}@${TARGET_HOST}:${remote_output} ${output}"

        # Clean up remote files
        local cleanup_cmd="rm -f /tmp/osxpmem_$$ ${remote_output}"

        ACQUISITION_COMMAND="${scp_tool_cmd} && execute_remote_command \"${run_cmd}\" && ${scp_output_cmd} && execute_remote_command \"${cleanup_cmd}\""
    else
        # Local acquisition on macOS
        ACQUISITION_COMMAND="sudo ${osxpmem_path} -o ${output} ${CUSTOM_PARAMS}"
    fi

    log_debug "macOS acquisition command: $ACQUISITION_COMMAND"
    return 0
}

# Perform memory acquisition
perform_acquisition() {
    log_info "Starting memory acquisition"

    # Create start timestamp for timing
    local start_time=$(date +%s)

    # Build acquisition command for the selected output
    build_acquisition_command "$OUTPUT_FILE" || {
        log_error "Failed to build acquisition command"
        return 1
    }

    # Log start of acquisition for chain of custody
    log_coc_event "Started" "Memory Acquisition" "Method: $METHOD, Target: ${TARGET_HOST:-local}, Output: $OUTPUT_FILE"

    # Execute the acquisition command
    log_info "Executing memory acquisition command, this may take some time..."
    eval "$ACQUISITION_COMMAND"
    local acquisition_status=$?

    if [[ $acquisition_status -ne 0 ]]; then
        log_error "Memory acquisition failed with status code $acquisition_status"
        log_coc_event "Failed" "Memory Acquisition" "Method: $METHOD, Status: $acquisition_status"
        return $acquisition_status
    fi

    # Calculate acquisition duration
    local end_time=$(date +%s)
    local elapsed=$(format_elapsed_time "$start_time" "$end_time")

    # Check if file exists and has content
    if [[ ! -f "$OUTPUT_FILE" ]]; then
        log_error "Acquisition command completed successfully but output file was not created: $OUTPUT_FILE"
        return 1
    fi

    local file_size
    file_size=$(stat -c %s "$OUTPUT_FILE" 2>/dev/null || stat -f %z "$OUTPUT_FILE")

    if [[ $file_size -eq 0 ]]; then
        log_error "Acquisition completed but output file is empty: $OUTPUT_FILE"
        return 1
    fi

    log_success "Memory acquisition completed successfully in $elapsed"
    log_info "Memory image saved to: $OUTPUT_FILE (Size: $(numfmt --to=iec-i --suffix=B $file_size))"

    # Calculate hash for verification and chain of custody
    log_info "Calculating hash of memory image for verification..."
    local image_hash
    image_hash=$(calculate_hash "$OUTPUT_FILE" "$DEFAULT_HASH_ALGO")

    if [[ -n "$image_hash" ]]; then
        log_info "Memory image hash ($DEFAULT_HASH_ALGO): $image_hash"

        # Save hash to a separate file for verification
        echo "$image_hash  $(basename "$OUTPUT_FILE")" > "${OUTPUT_FILE}.${DEFAULT_HASH_ALGO}"
        chmod "$DEFAULT_EVIDENCE_PERMS" "${OUTPUT_FILE}.${DEFAULT_HASH_ALGO}" || log_warn "Failed to set permissions on hash file"

        log_coc_event "Completed" "Memory Acquisition" "Method: $METHOD, Size: $file_size bytes, Hash: $image_hash, Time: $elapsed"
    else
        log_warn "Failed to calculate hash of memory image"
        log_coc_event "Completed" "Memory Acquisition" "Method: $METHOD, Size: $file_size bytes, Time: $elapsed, Note: Hash calculation failed"
    fi

    # Compress the memory image if requested
    if [[ "$COMPRESS" == "true" ]]; then
        log_info "Compressing memory image..."
        local compressed_file
        compressed_file=$(compress_evidence_file "$OUTPUT_FILE" "" "$COMPRESSION_ALGO")

        if [[ $? -eq 0 && -n "$compressed_file" ]]; then
            # Update OUTPUT_FILE to the compressed file
            log_success "Memory image compressed to: $compressed_file"
            OUTPUT_FILE="$compressed_file"
        else
            log_warn "Failed to compress memory image, using uncompressed file"
        fi
    fi

    # Split the file into chunks if requested or if it's too large
    if [[ -n "$CHUNK_SIZE" ]]; then
        local file_size
        file_size=$(stat -c %s "$OUTPUT_FILE" 2>/dev/null || stat -f %z "$OUTPUT_FILE")
        local chunk_size_bytes
        chunk_size_bytes=$(numfmt --from=auto "$CHUNK_SIZE")

        if [[ $file_size -gt $chunk_size_bytes ]]; then
            log_info "Splitting memory image into chunks of $CHUNK_SIZE..."
            local split_dir
            split_dir="$(dirname "$OUTPUT_FILE")/$(basename "$OUTPUT_FILE")_chunks"

            split_large_file "$OUTPUT_FILE" "$split_dir" "$CHUNK_SIZE"

            if [[ $? -eq 0 ]]; then
                log_success "Memory image split into chunks in directory: $split_dir"
                # Original file is preserved, chunks are in split_dir
                log_coc_event "Split" "Memory Image" "Original: $OUTPUT_FILE, Chunk Directory: $split_dir, Chunk Size: $CHUNK_SIZE"
            else
                log_warn "Failed to split memory image, using single file"
            fi
        else
            log_debug "Memory image size ($file_size bytes) is smaller than chunk size, no splitting needed"
        fi
    fi

    # Acquire pagefile/swap if requested
    if [[ "$ACQUIRE_PAGEFILE" == "true" ]]; then
        acquire_pagefile
    fi

    # Run post-acquisition command if specified
    if [[ -n "$POST_ACQUISITION_CMD" ]]; then
        log_info "Running post-acquisition command"

        if [[ -n "$TARGET_HOST" ]]; then
            # Run on remote target
            execute_remote_command "$POST_ACQUISITION_CMD" ||
                log_warn "Post-acquisition command failed on remote target"
        else
            # Run locally
            eval "$POST_ACQUISITION_CMD" ||
                log_warn "Post-acquisition command failed"
        fi
    fi

    # Perform volatility analysis if requested
    if [[ "$ANALYZE_VOLATILITY" == "true" ]]; then
        analyze_with_volatility
    fi

    log_info "Memory acquisition process completed"
    return 0
}

# Acquire pagefile or swap space
acquire_pagefile() {
    log_info "Attempting to acquire pagefile/swap space..."

    local pagefile_output="${OUTPUT_FILE%.*}.pagefile.raw"
    local pagefile_path
    local pagefile_cmd
    local status=0

    # Determine OS and pagefile location
    if [[ -n "$TARGET_HOST" ]]; then
        # Remote target - try to determine OS
        local os_check="uname -s"
        local os_type
        os_type=$(execute_remote_command "$os_check" 2>/dev/null)

        if [[ "$os_type" == "Linux" ]]; then
            # Get swap partitions
            local swap_parts
            swap_parts=$(execute_remote_command "cat /proc/swaps | grep -v Filename | awk '{print \$1}'")

            if [[ -z "$swap_parts" ]]; then
                log_warn "No swap partitions found on remote Linux target"
                return 1
            fi

            # Use first swap partition
            pagefile_path=$(echo "$swap_parts" | head -n1)

            # Build dd command for remote Linux
            pagefile_cmd="sudo dd if=${pagefile_path} of=/tmp/swap_$$.raw bs=1M status=progress"

            # Execute command, get the file, and clean up
            if execute_remote_command "$pagefile_cmd"; then
                # Copy swap file back
                local scp_cmd="scp"
                [[ -n "$SSH_KEY" ]] && scp_cmd+=" -i $SSH_KEY"
                [[ -n "$SSH_PORT" ]] && scp_cmd+=" -P $SSH_PORT"
                scp_cmd+=" ${TARGET_USER}@${TARGET_HOST}:/tmp/swap_$$.raw ${pagefile_output}"

                eval "$scp_cmd" || status=1

                # Clean up remote file
                execute_remote_command "rm -f /tmp/swap_$$.raw" || log_warn "Failed to clean up remote swap file"
            else
                log_warn "Failed to acquire swap from remote Linux target"
                status=1
            fi

        elif [[ "$os_type" == *"MINGW"* || "$os_type" == *"MSYS"* || "$os_type" == *"Windows"* ]]; then
            # Windows remote target

            # Check if WinPmem can acquire pagefile
            local winpmem_path
            winpmem_path=$(get_tool_path "memory_acquisition" "winpmem")

            if [[ -n "$winpmem_path" ]]; then
                # Copy WinPmem to target
                local remote_winpmem="C:\\Windows\\Temp\\winpmem_$$.exe"
                local remote_winpmem_unix="/cygdrive/c/Windows/Temp/winpmem_$$.exe"
                local remote_output="C:\\Windows\\Temp\\pagefile_$$.raw"
                local remote_output_unix="/cygdrive/c/Windows/Temp/pagefile_$$.raw"

                # Copy WinPmem
                local scp_tool_cmd="scp"
                [[ -n "$SSH_KEY" ]] && scp_tool_cmd+=" -i $SSH_KEY"
                [[ -n "$SSH_PORT" ]] && scp_tool_cmd+=" -P $SSH_PORT"
                scp_tool_cmd+=" ${winpmem_path} ${TARGET_USER}@${TARGET_HOST}:${remote_winpmem_unix}"

                # Execute WinPmem with pagefile flag
                local run_cmd="${remote_winpmem//\\/\\\\} -p -o ${remote_output//\\/\\\\}"

                # Copy pagefile back
                local scp_output_cmd="scp"
                [[ -n "$SSH_KEY" ]] && scp_output_cmd+=" -i $SSH_KEY"
                [[ -n "$SSH_PORT" ]] && scp_output_cmd+=" -P $SSH_PORT"
                scp_output_cmd+=" ${TARGET_USER}@${TARGET_HOST}:${remote_output_unix} ${pagefile_output}"

                # Clean up remote files
                local cleanup_cmd="del /F /Q \"${remote_winpmem}\" \"${remote_output}\""

                eval "${scp_tool_cmd} && execute_remote_command \"${run_cmd}\" && ${scp_output_cmd} && execute_remote_command \"${cleanup_cmd}\"" || status=1
            else
                # Try to use raw dd-like copy of pagefile (may fail due to locks)
                log_warn "WinPmem not available for remote Windows pagefile acquisition, attempting raw copy"

                local pagefile_copy_cmd="copy /B C:\\pagefile.sys C:\\Windows\\Temp\\pagefile_$$.raw"
                local remote_output_unix="/cygdrive/c/Windows/Temp/pagefile_$$.raw"

                execute_remote_command "$pagefile_copy_cmd"

                # Copy pagefile back if it exists
                if execute_remote_command "if exist C:\\Windows\\Temp\\pagefile_$$.raw echo exists" | grep -q "exists"; then
                    # Copy back
                    local scp_cmd="scp"
                    [[ -n "$SSH_KEY" ]] && scp_cmd+=" -i $SSH_KEY"
                    [[ -n "$SSH_PORT" ]] && scp_cmd+=" -P $SSH_PORT"
                    scp_cmd+=" ${TARGET_USER}@${TARGET_HOST}:${remote_output_unix} ${pagefile_output}"

                    eval "$scp_cmd" || status=1

                    # Clean up remote file
                    execute_remote_command "del /F /Q C:\\Windows\\Temp\\pagefile_$$.raw" || log_warn "Failed to clean up remote pagefile"
                else
                    log_warn "Failed to copy pagefile from remote Windows target"
                    status=1
                fi
            fi
        else
            log_warn "Pagefile/swap acquisition not supported for remote OS: $os_type"
            status=1
        fi
    else
        # Local target
        local os_type=$(uname -s)

        if [[ "$os_type" == "Linux" ]]; then
            # Get swap partitions
            local swap_parts
            swap_parts=$(cat /proc/swaps 2>/dev/null | grep -v Filename | awk '{print $1}')

            if [[ -z "$swap_parts" ]]; then
                log_warn "No swap partitions found on local Linux system"
                return 1
            fi

            # Use first swap partition
            pagefile_path=$(echo "$swap_parts" | head -n1)
            log_info "Acquiring swap from: $pagefile_path"

            # Use dd to copy swap
            sudo dd if="$pagefile_path" of="$pagefile_output" bs=1M status=progress || status=1

        elif [[ "$os_type" == "Darwin" ]]; then
            # macOS swap/sleepimage acquisition
            log_info "Attempting to acquire macOS swap files and sleepimage..."

            # Swap files are in /private/var/vm/
            local swap_dir="/private/var/vm"
            local swap_output_dir="${OUTPUT_FILE%.*}.swap"

            # Create output directory
            ensure_output_dir "$swap_output_dir"

            # Copy all swap files (swapfile0, swapfile1, etc.) and sleepimage
            for swap_file in "$swap_dir"/swapfile* "$swap_dir"/sleepimage; do
                if [[ -f "$swap_file" ]]; then
                    local swap_name=$(basename "$swap_file")
                    log_info "Copying $swap_name..."
                    sudo cp -p "$swap_file" "${swap_output_dir}/${swap_name}" || {
                        log_warn "Failed to copy $swap_file"
                        status=1
                    }
                fi
            done

            # If any files were copied, create success marker
            if [[ $(find "$swap_output_dir" -type f | wc -l) -gt 0 ]]; then
                log_success "macOS swap files acquired to: $swap_output_dir"
                pagefile_output="$swap_output_dir"
            else
                log_warn "No macOS swap files were successfully acquired"
                status=1
            fi

        elif [[ "$os_type" == *"MINGW"* || "$os_type" == *"MSYS"* || "$os_type" == *"Windows"* ]]; then
            # Local Windows system

            # Check if WinPmem can acquire pagefile
            local winpmem_path
            winpmem_path=$(get_tool_path "memory_acquisition" "winpmem")

            if [[ -n "$winpmem_path" ]]; then
                # Use WinPmem to acquire pagefile
                eval "${winpmem_path} -p -o ${pagefile_output}" || status=1
            else
                # Try direct copy (likely to fail due to locks)
                log_warn "WinPmem not available for Windows pagefile acquisition, attempting raw copy"
                cp /cygdrive/c/pagefile.sys "$pagefile_output" 2>/dev/null || {
                    log_warn "Failed to copy pagefile directly"
                    status=1
                }
            fi
        else
            log_warn "Pagefile/swap acquisition not supported for OS: $os_type"
            status=1
        fi
    fi

    # Check if acquisition was successful
    if [[ $status -eq 0 && -f "$pagefile_output" ]]; then
        local file_size
        file_size=$(stat -c %s "$pagefile_output" 2>/dev/null || stat -f %z "$pagefile_output")

        if [[ $file_size -eq 0 ]]; then
            log_warn "Pagefile/swap acquisition succeeded but file is empty"
            status=1
        else
            log_success "Pagefile/swap acquired successfully: $pagefile_output (Size: $(numfmt --to=iec-i --suffix=B $file_size))"

            # Calculate hash for chain of custody
            local pagefile_hash
            pagefile_hash=$(calculate_hash "$pagefile_output" "$DEFAULT_HASH_ALGO")

            if [[ -n "$pagefile_hash" ]]; then
                echo "$pagefile_hash  $(basename "$pagefile_output")" > "${pagefile_output}.${DEFAULT_HASH_ALGO}"
                chmod "$DEFAULT_EVIDENCE_PERMS" "${pagefile_output}.${DEFAULT_HASH_ALGO}" || log_warn "Failed to set permissions on pagefile hash file"

                log_coc_event "Acquired" "Pagefile/Swap" "Path: $pagefile_path, Output: $pagefile_output, Size: $file_size bytes, Hash: $pagefile_hash"
            else
                log_warn "Failed to calculate hash of pagefile/swap"
                log_coc_event "Acquired" "Pagefile/Swap" "Path: $pagefile_path, Output: $pagefile_output, Size: $file_size bytes"
            }

            # Compress pagefile if requested
            if [[ "$COMPRESS" == "true" ]]; then
                log_info "Compressing pagefile/swap..."
                compress_evidence_file "$pagefile_output" "" "$COMPRESSION_ALGO" ||
                    log_warn "Failed to compress pagefile/swap"
            }
        }
    } else {
        log_warn "Failed to acquire pagefile/swap"
        return 1
    }

    return $status
}

# Collect system metadata before acquisition
collect_system_metadata() {
    log_info "Collecting system metadata..."

    local metadata="{}"
    local system_info
    local os_info
    local kernel_info
    local cpu_info
    local memory_info

    if [[ -n "$TARGET_HOST" ]]; then
        # Remote target metadata collection

        # Create a temporary script to collect system info
        local temp_script
        temp_script=$(create_temp_file "metadata_collector")

        # Write metadata collection script
        cat << 'EOF' > "$temp_script"
#!/bin/bash
# System metadata collection script

echo "{"

# OS info
echo '  "os_info": {'
if [ -f /etc/os-release ]; then
    # Linux with os-release
    echo '    "name": "'$(grep ^NAME= /etc/os-release | cut -d= -f2 | sed 's/"//g')'",'
    echo '    "version": "'$(grep ^VERSION= /etc/os-release | cut -d= -f2 | sed 's/"//g')'",'
    echo '    "id": "'$(grep ^ID= /etc/os-release | cut -d= -f2 | sed 's/"//g')'"'
elif [ -f /etc/redhat-release ]; then
    # RHEL/CentOS
    echo '    "name": "'$(cat /etc/redhat-release)'",'
    echo '    "version": "'$(cat /etc/redhat-release | grep -o '[0-9\.]*')'",'
    echo '    "id": "rhel"'
elif [ -x /usr/bin/sw_vers ]; then
    # macOS
    echo '    "name": "macOS",'
    echo '    "version": "'$(/usr/bin/sw_vers -productVersion)'",'
    echo '    "build": "'$(/usr/bin/sw_vers -buildVersion)'"'
elif [ -n "$(uname -s | grep -i mingw)" ] || [ -n "$(uname -s | grep -i msys)" ]; then
    # Windows (MINGW/MSYS)
    if [ -x /c/Windows/System32/systeminfo.exe ]; then
        os_name=$(/c/Windows/System32/systeminfo.exe | grep -i "OS Name:" | sed 's/.*: *//')
        os_ver=$(/c/Windows/System32/systeminfo.exe | grep -i "OS Version:" | sed 's/.*: *//')
        echo '    "name": "'"$os_name"'",'
        echo '    "version": "'"$os_ver"'",'
        echo '    "id": "windows"'
    else
        echo '    "name": "Windows",'
        echo '    "version": "Unknown",'
        echo '    "id": "windows"'
    fi
else
    # Generic fallback
    echo '    "name": "'$(uname -s)'",'
    echo '    "version": "'$(uname -r)'",'
    echo '    "id": "unknown"'
fi
echo '  },'

# Kernel info
echo '  "kernel_info": {'
echo '    "name": "'$(uname -s)'",'
echo '    "release": "'$(uname -r)'",'
echo '    "version": "'$(uname -v)'",'
echo '    "machine": "'$(uname -m)'"'
echo '  },'

# CPU info
echo '  "cpu_info": {'
if [ -f /proc/cpuinfo ]; then
    # Linux
    model=$(grep "model name" /proc/cpuinfo | head -1 | sed 's/.*: *//')
    cores=$(grep -c processor /proc/cpuinfo)
    echo '    "model": "'"$model"'",'
    echo '    "cores": '"$cores"''
elif [ -x /usr/sbin/sysctl ]; then
    # macOS and some Unix
    model=$(/usr/sbin/sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "Unknown")
    cores=$(/usr/sbin/sysctl -n hw.ncpu 2>/dev/null || echo 0)
    echo '    "model": "'"$model"'",'
    echo '    "cores": '"$cores"''
else
    # Generic fallback
    echo '    "model": "Unknown",'
    echo '    "cores": 0'
fi
echo '  },'

# Memory info
echo '  "memory_info": {'
if [ -f /proc/meminfo ]; then
    # Linux
    total_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    free_kb=$(grep MemFree /proc/meminfo | awk '{print $2}')
    available_kb=$(grep MemAvailable /proc/meminfo 2>/dev/null | awk '{print $2}')
    # Convert to MB for easier reading
    total_mb=$((total_kb / 1024))
    free_mb=$((free_kb / 1024))
    available_mb=${available_kb:+$((available_kb / 1024))}
    echo '    "total_kb": '"$total_kb"','
    echo '    "free_kb": '"$free_kb"','
    if [ -n "$available_mb" ]; then
        echo '    "available_kb": '"$available_kb"','
    fi
    echo '    "total_mb": '"$total_mb"','
    echo '    "free_mb": '"$free_mb"''
    if [ -n "$available_mb" ]; then
        echo '    ,"available_mb": '"$available_mb"''
    fi
elif [ -x /usr/sbin/sysctl ]; then
    # macOS and some Unix
    total_bytes=$(/usr/sbin/sysctl -n hw.memsize 2>/dev/null)
    page_size=$(/usr/sbin/sysctl -n hw.pagesize 2>/dev/null || echo 4096)
    if [ -x /usr/bin/vm_stat ]; then
        # macOS specific
        pages_free=$(/usr/bin/vm_stat | grep "Pages free:" | awk '{print $3}' | tr -d '.')
        free_bytes=$((pages_free * page_size))
        # Convert to KB and MB
        total_kb=$((total_bytes / 1024))
        free_kb=$((free_bytes / 1024))
        total_mb=$((total_kb / 1024))
        free_mb=$((free_kb / 1024))
        echo '    "total_kb": '"$total_kb"','
        echo '    "free_kb": '"$free_kb"','
        echo '    "total_mb": '"$total_mb"','
        echo '    "free_mb": '"$free_mb"''
    else
        # Just total memory
        total_kb=$((total_bytes / 1024))
        total_mb=$((total_kb / 1024))
        echo '    "total_kb": '"$total_kb"','
        echo '    "total_mb": '"$total_mb"''
    fi
else
    # Generic fallback
    echo '    "total_mb": 0,'
    echo '    "free_mb": 0'
fi
echo '  },'

# Network interfaces info
echo '  "network_info": {'
echo '    "interfaces": ['
if [ -x /sbin/ifconfig ]; then
    # Unix-like with ifconfig
    interfaces=$(/sbin/ifconfig -a 2>/dev/null | grep -E "^[a-zA-Z0-9]+" | cut -d: -f1)
    first=true
    for iface in $interfaces; do
        if $first; then
            first=false
        else
            echo ','
        fi
        echo '      {'
        echo '        "name": "'"$iface"'",'
        ip_addr=$(/sbin/ifconfig $iface 2>/dev/null | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*')
        mac_addr=$(/sbin/ifconfig $iface 2>/dev/null | grep -Eo '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -1)
        echo '        "ipv4": "'${ip_addr:-None}'",'
        echo '        "mac": "'${mac_addr:-None}'"'
        echo -n '      }'
    done
elif [ -x /sbin/ip ]; then
    # Linux with ip command
    interfaces=$(/sbin/ip link show | grep -E "^[0-9]+:" | cut -d: -f2 | awk '{print $1}')
    first=true
    for iface in $interfaces; do
        if $first; then
            first=false
        else
            echo ','
        fi
        echo '      {'
        echo '        "name": "'"$iface"'",'
        ip_addr=$(/sbin/ip addr show $iface 2>/dev/null | grep -Eo 'inet ([0-9]*\.){3}[0-9]*' | awk '{print $2}')
        mac_addr=$(/sbin/ip link show $iface 2>/dev/null | grep -Eo '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -1)
        echo '        "ipv4": "'${ip_addr:-None}'",'
        echo '        "mac": "'${mac_addr:-None}'"'
        echo -n '      }'
    done
else
    # Generic fallback
    echo '      {'
    echo '        "name": "unknown",'
    echo '        "ipv4": "None",'
    echo '        "mac": "None"'
    echo -n '      }'
fi
echo ''  # End of interfaces array
echo '    ]'
echo '  },'

# Acquisition metadata
echo '  "acquisition_metadata": {'
echo '    "timestamp": "'$(date -u "+%Y-%m-%dT%H:%M:%SZ")'",'
echo '    "hostname": "'$(hostname)'",'
echo '    "current_user": "'$(id -un 2>/dev/null || echo "unknown")'"'
echo '  }'

echo "}"
EOF

        # Make script executable
        chmod +x "$temp_script"

        # Transfer script to remote host
        local remote_script="/tmp/metadata_collector_$$.sh"
        local scp_cmd="scp"
        [[ -n "$SSH_KEY" ]] && scp_cmd+=" -i $SSH_KEY"
        [[ -n "$SSH_PORT" ]] && scp_cmd+=" -P $SSH_PORT"
        scp_cmd+=" ${temp_script} ${TARGET_USER}@${TARGET_HOST}:${remote_script}"

        eval "$scp_cmd" || {
            log_warn "Failed to transfer metadata collection script to remote host"
            return 1
        }

        # Execute script on remote host
        execute_remote_command "chmod +x ${remote_script} && ${remote_script}" > "$METADATA_FILE" || {
            log_warn "Failed to execute metadata collection script on remote host"
            return 1
        }

        # Clean up
        execute_remote_command "rm -f ${remote_script}" || log_warn "Failed to clean up remote script"
        rm -f "$temp_script"

    else
        # Local metadata collection
        {
            echo "{"

            # OS information
            echo '  "os_info": {'
            if [[ -f /etc/os-release ]]; then
                # Linux with os-release
                os_name=$(grep ^NAME= /etc/os-release | cut -d= -f2 | sed 's/"//g')
                os_version=$(grep ^VERSION= /etc/os-release | cut -d= -f2 | sed 's/"//g')
                os_id=$(grep ^ID= /etc/os-release | cut -d= -f2 | sed 's/"//g')
                echo '    "name": "'"$os_name"'",'
                echo '    "version": "'"$os_version"'",'
                echo '    "id": "'"$os_id"'"'
            elif [[ -f /etc/redhat-release ]]; then
                # RHEL/CentOS
                echo '    "name": "'$(cat /etc/redhat-release)'",'
                echo '    "version": "'$(cat /etc/redhat-release | grep -o '[0-9\.]*')'",'
                echo '    "id": "rhel"'
            elif [[ -x /usr/bin/sw_vers ]]; then
                # macOS
                echo '    "name": "macOS",'
                echo '    "version": "'$(/usr/bin/sw_vers -productVersion)'",'
                echo '    "build": "'$(/usr/bin/sw_vers -buildVersion)'"'
            elif [[ "$(uname -s)" == *"MINGW"* || "$(uname -s)" == *"MSYS"* ]]; then
                # Windows (MINGW/MSYS)
                if [[ -x /c/Windows/System32/systeminfo.exe ]]; then
                    os_name=$(/c/Windows/System32/systeminfo.exe | grep -i "OS Name:" | sed 's/.*: *//')
                    os_ver=$(/c/Windows/System32/systeminfo.exe | grep -i "OS Version:" | sed 's/.*: *//')
                    echo '    "name": "'"$os_name"'",'
                    echo '    "version": "'"$os_ver"'",'
                    echo '    "id": "windows"'
                else
                    echo '    "name": "Windows",'
                    echo '    "version": "Unknown",'
                    echo '    "id": "windows"'
                fi
            else
                # Generic fallback
                echo '    "name": "'$(uname -s)'",'
                echo '    "version": "'$(uname -r)'",'
                echo '    "id": "unknown"'
            fi
            echo '  },'

            # Kernel info
            echo '  "kernel_info": {'
            echo '    "name": "'$(uname -s)'",'
            echo '    "release": "'$(uname -r)'",'
            echo '    "version": "'$(uname -v)'",'
            echo '    "machine": "'$(uname -m)'"'
            echo '  },'

            # CPU info
            echo '  "cpu_info": {'
            if [[ -f /proc/cpuinfo ]]; then
                # Linux
                model=$(grep "model name" /proc/cpuinfo | head -1 | sed 's/.*: *//')
                cores=$(grep -c processor /proc/cpuinfo)
                echo '    "model": "'"$model"'",'
                echo '    "cores": '"$cores"
            elif [[ -x /usr/sbin/sysctl ]]; then
                # macOS and some Unix
                model=$(/usr/sbin/sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "Unknown")
                cores=$(/usr/sbin/sysctl -n hw.ncpu 2>/dev/null || echo 0)
                echo '    "model": "'"$model"'",'
                echo '    "cores": '"$cores"
            else
                # Generic fallback
                echo '    "model": "Unknown",'
                echo '    "cores": 0'
            fi
            echo '  },'

            # Memory info
            echo '  "memory_info": {'
            if [[ -f /proc/meminfo ]]; then
                # Linux
                total_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
                free_kb=$(grep MemFree /proc/meminfo | awk '{print $2}')
                available_kb=$(grep MemAvailable /proc/meminfo 2>/dev/null | awk '{print $2}')
                # Convert to MB for easier reading
                total_mb=$((total_kb / 1024))
                free_mb=$((free_kb / 1024))
                available_mb=${available_kb:+$((available_kb / 1024))}
                echo '    "total_kb": '"$total_kb"','
                echo '    "free_kb": '"$free_kb"','
                if [[ -n "$available_mb" ]]; then
                    echo '    "available_kb": '"$available_kb"','
                fi
                echo '    "total_mb": '"$total_mb"','
                echo '    "free_mb": '"$free_mb"''
                if [[ -n "$available_mb" ]]; then
                    echo '    ,"available_mb": '"$available_mb"''
                fi
            elif [[ -x /usr/sbin/sysctl ]]; then
                # macOS and some Unix
                total_bytes=$(/usr/sbin/sysctl -n hw.memsize 2>/dev/null)
                page_size=$(/usr/sbin/sysctl -n hw.pagesize 2>/dev/null || echo 4096)
                if [[ -x /usr/bin/vm_stat ]]; then
                    # macOS specific
                    pages_free=$(/usr/bin/vm_stat | grep "Pages free:" | awk '{print $3}' | tr -d '.')
                    free_bytes=$((pages_free * page_size))
                    # Convert to KB and MB
                    total_kb=$((total_bytes / 1024))
                    free_kb=$((free_bytes / 1024))
                    total_mb=$((total_kb / 1024))
                    free_mb=$((free_kb / 1024))
                    echo '    "total_kb": '"$total_kb"','
                    echo '    "free_kb": '"$free_kb"','
                    echo '    "total_mb": '"$total_mb"','
                    echo '    "free_mb": '"$free_mb"''
                else
                    # Just total memory
                    total_kb=$((total_bytes / 1024))
                    total_mb=$((total_kb / 1024))
                    echo '    "total_kb": '"$total_kb"','
                    echo '    "total_mb": '"$total_mb"''
                fi
            else
                # Generic fallback
                echo '    "total_mb": 0,'
                echo '    "free_mb": 0'
            fi
            echo '  },'

            # Network interfaces
            echo '  "network_info": {'
            echo '    "interfaces": ['

            if [[ -x /sbin/ifconfig ]]; then
                # Unix-like with ifconfig
                interfaces=$(/sbin/ifconfig -a 2>/dev/null | grep -E "^[a-zA-Z0-9]+" | cut -d: -f1)
                first=true
                for iface in $interfaces; do
                    if [[ "$first" != "true" ]]; then
                        echo ','
                    else
                        first=false
                    fi
                    echo '      {'
                    echo '        "name": "'"$iface"'",'
                    ip_addr=$(/sbin/ifconfig $iface 2>/dev/null | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*')
                    mac_addr=$(/sbin/ifconfig $iface 2>/dev/null | grep -Eo '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -1)
                    echo '        "ipv4": "'${ip_addr:-None}'",'
                    echo '        "mac": "'${mac_addr:-None}'"'
                    echo -n '      }'
                done
            elif [[ -x /sbin/ip ]]; then
                # Linux with ip command
                interfaces=$(/sbin/ip link show | grep -E "^[0-9]+:" | cut -d: -f2 | awk '{print $1}')
                first=true
                for iface in $interfaces; do
                    if [[ "$first" != "true" ]]; then
                        echo ','
                    else
                        first=false
                    fi
                    echo '      {'
                    echo '        "name": "'"$iface"'",'
                    ip_addr=$(/sbin/ip addr show $iface 2>/dev/null | grep -Eo 'inet ([0-9]*\.){3}[0-9]*' | awk '{print $2}')
                    mac_addr=$(/sbin/ip link show $iface 2>/dev/null | grep -Eo '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -1)
                    echo '        "ipv4": "'${ip_addr:-None}'",'
                    echo '        "mac": "'${mac_addr:-None}'"'
                    echo -n '      }'
                done
            else
                # Generic fallback
                echo '      {'
                echo '        "name": "unknown",'
                echo '        "ipv4": "None",'
                echo '        "mac": "None"'
                echo -n '      }'
            fi
            echo ''  # End of interfaces array
            echo '    ]'
            echo '  },'

            # Acquisition metadata
            echo '  "acquisition_metadata": {'
            echo '    "timestamp": "'$(date -u "+%Y-%m-%dT%H:%M:%SZ")'",'
            echo '    "hostname": "'$(hostname)'",'
            echo '    "current_user": "'$(id -un 2>/dev/null || echo "unknown")'"'
            echo '  }'

            echo "}"
        } > "$METADATA_FILE"
    fi

    # Verify metadata file was created and has content
    if [[ ! -f "$METADATA_FILE" ]]; then
        log_error "Failed to create metadata file"
        return 1
    fi

    local file_size
    file_size=$(stat -c %s "$METADATA_FILE" 2>/dev/null || stat -f %z "$METADATA_FILE")
    if [[ $file_size -eq 0 ]]; then
        log_error "Metadata file is empty"
        return 1
    fi

    log_success "System metadata collected and saved to: $METADATA_FILE"
    log_coc_event "Created" "System Metadata" "File: $METADATA_FILE, Size: $file_size bytes"

    # Set appropriate permissions
    chmod "$DEFAULT_EVIDENCE_PERMS" "$METADATA_FILE" ||
        log_warn "Failed to set permissions on metadata file"

    return 0
}

# Analyze memory dump with Volatility
analyze_with_volatility() {
    log_info "Starting memory analysis with Volatility..."

    # Check if Volatility exists
    local volatility_path
    if command -v volatility3 &>/dev/null; then
        volatility_path=$(which volatility3)
    elif command -v vol3 &>/dev/null; then
        volatility_path=$(which vol3)
    elif command -v vol.py &>/dev/null; then
        volatility_path=$(which vol.py)
    else
        volatility_path=$(get_tool_path "memory_acquisition" "volatility")
        if [[ -z "$volatility_path" ]]; then
            log_error "Volatility not found in PATH or tool dependencies"
            return 1
        fi
    fi

    log_info "Using Volatility at: $volatility_path"

    # Determine proper output directory
    local analysis_output="${OUTPUT_FILE%.*}_volatility"
    ensure_output_dir "$analysis_output" || {
        log_error "Failed to create output directory for Volatility analysis"
        return 1
    }

    # Determine if we're using Volatility 2 or 3
    local volatility_version=3
    if [[ "$volatility_path" == *"vol.py"* ]]; then
        volatility_version=2
    fi
    log_info "Detected Volatility version: $volatility_version"

    # Additional environment setup based on version
    local volatility_cmd="$volatility_path"
    if [[ $volatility_version -eq 2 ]]; then
        # Set Python path if needed for Volatility 2
        if [[ -z "$PYTHONPATH" && -d "/usr/local/lib/python2.7/dist-packages" ]]; then
            export PYTHONPATH="/usr/local/lib/python2.7/dist-packages"
        fi
        # Use python2 if available
        if command -v python2 &>/dev/null; then
            volatility_cmd="python2 $volatility_path"
        fi
    fi

    # Determine the profile if not provided
    local profile_arg=""
    if [[ -z "$PROFILE" && $volatility_version -eq 2 ]]; then
        log_info "No profile specified, attempting profile detection..."
        local detected_profile
        detected_profile=$($volatility_cmd -f "$OUTPUT_FILE" imageinfo 2>/dev/null | grep "Suggested Profile" | head -1 | cut -d ":" -f2 | cut -d "," -f1 | tr -d ' ')
        if [[ -n "$detected_profile" ]]; then
            PROFILE="$detected_profile"
            log_info "Detected profile: $PROFILE"
        else
            log_warn "Could not automatically detect profile"
            # Fall back to Linux profile if it's likely Linux
            if file "$OUTPUT_FILE" | grep -qi "linux"; then
                PROFILE="LinuxDefault"
                log_info "Using default Linux profile"
            else
                PROFILE="WinDefault"
                log_info "Using default Windows profile"
            fi
        fi
    fi

    # Set up profile arguments based on version
    if [[ $volatility_version -eq 2 ]]; then
        if [[ -n "$PROFILE" ]]; then
            profile_arg="--profile=$PROFILE"
        fi
    fi

    # Common plugins to run based on Volatility version
    local base_plugins=()
    if [[ $volatility_version -eq 2 ]]; then
        base_plugins=(
            "pslist"
            "pstree"
            "netscan"
            "cmdscan"
            "consoles"
            "filescan"
            "malfind"
            "svcscan"
            "dlllist"
        )
    else
        # Volatility 3 plugins
        base_plugins=(
            "windows.pslist"
            "windows.pstree"
            "windows.netscan"
            "windows.cmdline"
            "windows.filescan"
            "windows.malfind"
            "windows.svcscan"
            "windows.dlllist"
            "linux.pslist"
            "linux.pstree"
            "linux.bash"
        )
    fi

    # Run plugins
    local plugin_cmd
    for plugin in "${base_plugins[@]}"; do
        local output_file="${analysis_output}/${plugin}.txt"

        log_info "Running Volatility plugin: $plugin"

        # Build plugin command based on version
        if [[ $volatility_version -eq 2 ]]; then
            plugin_cmd="$volatility_cmd -f \"$OUTPUT_FILE\" $profile_arg $plugin"
        else
            plugin_cmd="$volatility_cmd -f \"$OUTPUT_FILE\" $plugin"
        fi

        # Run plugin and save output
        timeout 600 bash -c "$plugin_cmd" > "$output_file" 2>&1 || {
            log_warn "Plugin $plugin failed or timed out"
            echo "ERROR: Plugin execution failed or timed out" >> "$output_file"
        }

        if [[ -s "$output_file" ]]; then
            log_success "Plugin $plugin output saved to $output_file"
            chmod "$DEFAULT_EVIDENCE_PERMS" "$output_file"
        else
            log_warn "Plugin $plugin produced no output"
            echo "No output was generated for this plugin" > "$output_file"
        fi
    done

    # Check for IOCs if specified
    if [[ -n "$IOC_FILE" && -f "$IOC_FILE" ]]; then
        log_info "Checking memory dump against IOC file: $IOC_FILE"
        local ioc_output="${analysis_output}/ioc_matches.txt"

        {
            echo "IOC Analysis Results"
            echo "===================="
            echo "Memory Image: $OUTPUT_FILE"
            echo "IOC File: $IOC_FILE"
            echo "Date: $(date -u)"
            echo ""
            echo "Matches:"
            echo "-------"

            # Process each line in the IOC file
            while IFS= read -r ioc; do
                # Skip comments and empty lines
                [[ "$ioc" =~ ^[[:space:]]*# || -z "${ioc// }" ]] && continue

                echo "Checking IOC: $ioc"

                # Check strings output for IOC
                strings -a -t x "$OUTPUT_FILE" | grep -i "$ioc" >> "$ioc_output"
            done < "$IOC_FILE"

            echo ""
            echo "End of IOC Analysis Report"
        } > "$ioc_output"

        chmod "$DEFAULT_EVIDENCE_PERMS" "$ioc_output"
        log_success "IOC analysis complete, results saved to: $ioc_output"
    fi

    # Create a summary report
    local summary_file="${analysis_output}/analysis_summary.txt"
    {
        echo "MEMORY ANALYSIS SUMMARY"
        echo "======================"
        echo "Memory Image: $OUTPUT_FILE"
        echo "Analysis Date: $(date -u)"
        echo "Volatility Version: $volatility_version"
        if [[ -n "$PROFILE" ]]; then
            echo "Profile: $PROFILE"
        fi
        echo ""
        echo "EXECUTED PLUGINS:"
        echo "----------------"
        for plugin in "${base_plugins[@]}"; do
            if [[ -f "${analysis_output}/${plugin}.txt" ]]; then
                local size=$(stat -c %s "${analysis_output}/${plugin}.txt" 2>/dev/null || stat -f %z "${analysis_output}/${plugin}.txt")
                if grep -q "ERROR:" "${analysis_output}/${plugin}.txt" 2>/dev/null; then
                    echo "✗ $plugin (ERROR)"
                else
                    echo "✓ $plugin ($(numfmt --to=iec-i --suffix=B --format="%.1f" $size))"
                fi
            else
                echo "? $plugin (No output file)"
            fi
        done

        # Add IOC check results if applicable
        if [[ -n "$IOC_FILE" && -f "$IOC_FILE" ]]; then
            echo ""
            echo "IOC ANALYSIS:"
            echo "------------"
            local match_count=$(grep -v "^Checking IOC:" "$ioc_output" | grep -c .)
            echo "Found $match_count potential IOC matches"
        fi

        echo ""
        echo "For detailed results, examine individual plugin output files in:"
        echo "$analysis_output/"
    } > "$summary_file"

    chmod "$DEFAULT_EVIDENCE_PERMS" "$summary_file"
    log_success "Analysis summary saved to: $summary_file"

    log_coc_event "Completed" "Memory Analysis" "Directory: $analysis_output"
    return 0
}

# Parse command-line arguments
parse_arguments() {
    # Default values
    OUTPUT_FILE=""
    FORMAT="$DEFAULT_OUTPUT_FORMAT"
    METHOD="$DEFAULT_METHOD"
    TARGET_HOST=""
    TARGET_USER="$USER"
    SSH_KEY=""
    SSH_PORT="$DEFAULT_REMOTE_PORT"
    COMPRESS="$DEFAULT_COMPRESSION"
    COMPRESSION_ALGO="$DEFAULT_COMPRESSION_ALGO"
    CHUNK_SIZE="$DEFAULT_CHUNK_SIZE"
    VERIFY_ACQUISITION="$DEFAULT_VERIFY_ACQUISITION"
    COLLECT_METADATA="$DEFAULT_METADATA_COLLECTION"
    ACQUIRE_PAGEFILE="$DEFAULT_ACQUIRE_PAGEFILE"
    PRE_ACQUISITION_CMD=""
    POST_ACQUISITION_CMD=""
    TIMEOUT="$DEFAULT_TIMEOUT"
    CUSTOM_PARAMS=""
    ANALYZE_VOLATILITY=false
    PROFILE=""
    IOC_FILE=""
    METADATA_FILE=""
    CASE_ID=""
    EXAMINER_ID=""
    EVIDENCE_ID=""

    # Parse command-line arguments
    while [[ $# -gt 0 ]]; do
        key="$1"
        case $key in
            -h|--help)
                usage
                ;;
            --version)
                show_version
                ;;
            -o|--output)
                shift
                OUTPUT_FILE="$1"
                ;;
            -f|--format)
                shift
                FORMAT="$1"
                ;;
            -m|--method)
                shift
                METHOD="$1"
                ;;
            -t|--target)
                shift
                TARGET_HOST="$1"
                ;;
            -u|--user)
                shift
                TARGET_USER="$1"
                ;;
            -k|--key)
                shift
                SSH_KEY="$1"
                ;;
            -p|--port)
                shift
                SSH_PORT="$1"
                ;;
            -c|--compress)
                COMPRESS="true"
                ;;
            --no-compress)
                COMPRESS="false"
                ;;
            --compression-algo)
                shift
                COMPRESSION_ALGO="$1"
                ;;
            --chunk-size)
                shift
                CHUNK_SIZE="$1"
                ;;
            --verify)
                VERIFY_ACQUISITION="true"
                ;;
            --no-verify)
                VERIFY_ACQUISITION="false"
                ;;
            --acquire-pagefile)
                ACQUIRE_PAGEFILE="true"
                ;;
            --no-pagefile)
                ACQUIRE_PAGEFILE="false"
                ;;
            --case-id)
                shift
                CASE_ID="$1"
                ;;
            --examiner)
                shift
                EXAMINER_ID="$1"
                ;;
            --evidence-id)
                shift
                EVIDENCE_ID="$1"
                ;;
            --pre-acquisition-cmd)
                shift
                PRE_ACQUISITION_CMD="$1"
                ;;
            --post-acquisition-cmd)
                shift
                POST_ACQUISITION_CMD="$1"
                ;;
            --timeout)
                shift
                TIMEOUT="$1"
                ;;
            --hash-algo)
                shift
                DEFAULT_HASH_ALGO="$1"
                ;;
            --custom-params)
                shift
                CUSTOM_PARAMS="$1"
                ;;
            --analyze-volatility)
                ANALYZE_VOLATILITY=true
                ;;
            --profile)
                shift
                PROFILE="$1"
                ;;
            --ioc-file)
                shift
                IOC_FILE="$1"
                ;;
            --metadata-file)
                shift
                METADATA_FILE="$1"
                ;;
            --no-metadata)
                COLLECT_METADATA="false"
                ;;
            -v|--verbose)
                VERBOSE=true
                ;;
            -q|--quiet)
                QUIET=true
                ;;
            --log)
                shift
                LOG_FILE="$1"
                ;;
            --audit-log)
                shift
                AUDIT_LOG_FILE="$1"
                ;;
            *)
                log_error "Unknown option: $key"
                usage
                ;;
        esac
        shift
    done

    # Validate required parameters
    if [[ -n "$TARGET_HOST" ]]; then
        log_info "Remote acquisition target: $TARGET_HOST"
    else
        log_info "Local acquisition target (this system)"
    fi

    return 0
}

# Main function
main() {
    # Initialize environment and parse arguments
    init_common_functions
    parse_arguments "$@"
    init_acquisition_environment

    # Prepare for acquisition
    prepare_acquisition || {
        log_error "Failed to prepare for memory acquisition"
        return 1
    }

    # Perform memory acquisition
    perform_acquisition || {
        log_error "Memory acquisition failed"
        return 1
    }

    log_success "Memory acquisition process completed successfully"
    return 0
}

# Run main function
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Execute main function and exit with its status
    main "$@"
    exit $?
fi
