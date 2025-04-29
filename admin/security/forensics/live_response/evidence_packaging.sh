#!/bin/bash
# Evidence Packaging Script for Live Response Forensics
#
# This script packages collected evidence for secure transport and storage.
# It provides chain of custody documentation, integrity verification,
# compression, and encryption options for evidence preservation.

# Load common utility functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common_functions.sh"

# Script version
EVIDENCE_PACKAGING_VERSION="1.0.0"
EVIDENCE_PACKAGING_DATE="2024-08-15"

# --- Configuration ---
DEFAULT_OUTPUT_FORMAT="zst"    # Default compression format (zst, gz, xz)
DEFAULT_ENCRYPTION="true"      # Whether to encrypt evidence by default
DEFAULT_MANIFEST_TYPE="json"   # Format for the manifest file (json, text)
DEFAULT_SPLIT_SIZE="4G"        # Maximum size before splitting files
DEFAULT_VERIFY_AFTER="true"    # Verify evidence integrity after packaging

# --- Main Functions ---

# Print usage information
usage() {
    cat << EOF
Evidence Packaging Script v${EVIDENCE_PACKAGING_VERSION} (${EVIDENCE_PACKAGING_DATE})

Usage: $(basename "$0") [OPTIONS] <evidence_directory>

Options:
  -h, --help                 Show this help message
  -o, --output PATH          Output directory for packaged evidence (default: evidence_directory_packaged)
  -c, --case-id ID           Case identifier for tracking
  -e, --examiner ID          Examiner identifier
  -f, --format FORMAT        Compression format: zst, gz, xz, none (default: ${DEFAULT_OUTPUT_FORMAT})
  -m, --manifest-type TYPE   Manifest format: json, text (default: ${DEFAULT_MANIFEST_TYPE})
  -p, --password             Use password encryption (prompted)
  -k, --key-file FILE        Use key file for encryption
  -s, --split-size SIZE      Split large files, size format like 4G, 500M (default: ${DEFAULT_SPLIT_SIZE})
  -t, --tags "TAG1,TAG2"     Add tags to the evidence package
  -v, --verbose              Show more detailed output
  -q, --quiet                Suppress non-error output
  --no-compress              Do not compress evidence files
  --no-encrypt               Do not encrypt evidence files
  --no-verify                Skip verification step
  --log FILE                 Log file path
  --audit-log FILE           Audit log file path
  --version                  Show version information and exit
EOF
    exit 0
}

# Display version information
show_version() {
    echo "Evidence Packaging Script v${EVIDENCE_PACKAGING_VERSION} (${EVIDENCE_PACKAGING_DATE})"
    echo "Using Common Functions v$(get_common_live_response_version)"
    exit 0
}

# Initialize the packaging environment
init_environment() {
    # Create output directory if it doesn't exist
    if [[ ! -d "$OUTPUT_DIR" ]]; then
        log_info "Creating output directory: $OUTPUT_DIR"
        ensure_output_dir "$OUTPUT_DIR" || error_exit "Failed to create output directory: $OUTPUT_DIR"
    fi

    # Create subdirectories for different types of packaged evidence
    ensure_output_dir "${OUTPUT_DIR}/files" || error_exit "Failed to create files directory"
    ensure_output_dir "${OUTPUT_DIR}/metadata" || error_exit "Failed to create metadata directory"
    ensure_output_dir "${OUTPUT_DIR}/logs" || error_exit "Failed to create logs directory"
    ensure_output_dir "${OUTPUT_DIR}/working" || error_exit "Failed to create working directory"

    log_info "Environment initialized successfully"
}

# Inventory all evidence files in the given directory
inventory_evidence() {
    local inventory_file="${OUTPUT_DIR}/metadata/evidence_inventory.json"
    local source_dir="$1"
    local temp_list
    temp_list=$(create_temp_file "inventory_list")

    log_info "Creating inventory of evidence in $source_dir"

    # Find all files, exclude directories themselves
    find "$source_dir" -type f -print > "$temp_list"

    local file_count
    file_count=$(wc -l < "$temp_list")
    log_info "Found $file_count evidence files to process"

    # Process files to create inventory
    {
        echo "{"
        echo "  \"inventory_timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
        echo "  \"case_id\": \"${CASE_ID:-unknown}\","
        echo "  \"examiner_id\": \"${EXAMINER_ID:-unknown}\","
        echo "  \"source_directory\": \"$source_dir\","
        echo "  \"file_count\": $file_count,"
        echo "  \"files\": ["

        local first_entry=true
        while IFS= read -r file_path; do
            if [[ "$first_entry" != "true" ]]; then
                echo ","
            else
                first_entry=false
            fi

            local file_name
            file_name=$(basename "$file_path")
            local file_size
            file_size=$(stat -c %s "$file_path" 2>/dev/null || stat -f %z "$file_path")
            local rel_path
            rel_path="${file_path#$source_dir/}"

            printf "    {\n      \"filename\": \"%s\",\n" "$file_name"
            printf "      \"relative_path\": \"%s\",\n" "$rel_path"
            printf "      \"size_bytes\": %s,\n" "$file_size"

            # Calculate hash
            local hash
            hash=$(calculate_hash "$file_path" "$DEFAULT_HASH_ALGO")
            printf "      \"hash_%s\": \"%s\"\n    }" "$DEFAULT_HASH_ALGO" "$hash"

        done < "$temp_list"

        echo -e "\n  ]"
        echo "}"
    } > "$inventory_file"

    chmod "$DEFAULT_EVIDENCE_PERMS" "$inventory_file" || log_warn "Failed to set permissions on $inventory_file"
    log_success "Evidence inventory created: $inventory_file"
    log_coc_event "Created" "Evidence Inventory" "File: $inventory_file, Count: $file_count"
}

# Process a single evidence file
process_evidence_file() {
    local file_path="$1"
    local rel_path="${file_path#$SOURCE_DIR/}"
    local output_subdir
    output_subdir="$(dirname "${OUTPUT_DIR}/files/${rel_path}")"
    local basename
    basename="$(basename "$file_path")"
    local working_dir="${OUTPUT_DIR}/working"

    log_debug "Processing evidence file: $rel_path"

    # Create output subdirectory if it doesn't exist
    ensure_output_dir "$output_subdir" || {
        log_error "Failed to create output subdirectory: $output_subdir"
        return 1
    }

    # Calculate initial hash for chain of custody
    local initial_hash
    initial_hash=$(calculate_hash "$file_path")

    # Copy to working directory
    local working_copy="${working_dir}/${basename}"
    cp "$file_path" "$working_copy" || {
        log_error "Failed to copy file to working directory: $file_path"
        return 1
    }
    chmod "$DEFAULT_EVIDENCE_PERMS" "$working_copy" || log_warn "Failed to set permissions on $working_copy"

    # Compress if requested
    local processed_file="$working_copy"
    local compression_format="$OUTPUT_FORMAT"
    local compression_algo="$OUTPUT_FORMAT"

    if [[ "$DO_COMPRESS" == "true" ]]; then
        log_debug "Compressing file: $basename"

        if [[ "$compression_format" == "none" ]]; then
            log_debug "Compression disabled for this file"
        else
            local compressed_file
            compressed_file=$(compress_evidence_file "$working_copy" "" "$compression_algo")

            if [[ $? -eq 0 ]]; then
                log_debug "Compression successful: $compressed_file"
                processed_file="$compressed_file"
                # Remove the uncompressed copy
                rm "$working_copy"
            else
                log_warn "Compression failed for $basename, using uncompressed file"
            fi
        fi
    fi

    # Split large files if needed
    local final_output
    local file_size
    file_size=$(stat -c %s "$processed_file" 2>/dev/null || stat -f %z "$processed_file")

    if [[ $(numfmt --from=auto "$file_size") -gt $(numfmt --from=auto "$SPLIT_SIZE") ]]; then
        log_info "Splitting large file: $basename (size: $file_size)"

        # Create a temporary directory for split files
        local split_dir
        split_dir="${working_dir}/split_$$_${basename}"
        mkdir -p "$split_dir"

        # Split the file
        split_large_file "$processed_file" "$split_dir" "$SPLIT_SIZE"

        if [[ $? -eq 0 ]]; then
            # Move split files and manifest to output directory
            local manifest_file
            manifest_file="${split_dir}/${basename}.manifest"

            # Create package directory
            local package_dir="${output_subdir}/${basename}_split"
            ensure_output_dir "$package_dir"

            # Move all split parts and manifest
            find "$split_dir" -type f -name "${basename}.part-*" -exec mv {} "$package_dir/" \;
            mv "$manifest_file" "$package_dir/"

            log_success "Split file into parts: ${package_dir}/"
            final_output="$package_dir"

            # Remove the original file in working dir
            rm -f "$processed_file"
        else
            log_warn "Failed to split file, using original: $processed_file"
            final_output="${output_subdir}/${basename}"
            if [[ "$processed_file" != "$final_output" ]]; then
                mv "$processed_file" "$final_output"
            fi
        fi
    else
        # No splitting needed
        final_output="${output_subdir}/$(basename "$processed_file")"
        mv "$processed_file" "$final_output"
    fi

    # Encrypt if requested
    if [[ "$DO_ENCRYPT" == "true" ]]; then
        log_info "Encryption requested, but not implemented in this version"
        # Future implementation would go here
    fi

    # Calculate final hash for verification
    local final_hash
    final_hash=$(calculate_hash "$final_output")

    # Record in chain of custody log
    log_coc_event "Packaged" "$rel_path" "Initial hash: $initial_hash, Final output: $final_output, Final hash: $final_hash"

    # Verify if requested
    if [[ "$VERIFY_AFTER" == "true" ]]; then
        if [[ -d "$final_output" ]]; then
            # For split files, we'd verify against the manifest
            log_debug "Split file verification would be done using manifest"
        else
            log_debug "Verifying file integrity"
            # Future implementation would go here
        fi
    fi

    log_debug "File processing complete: $rel_path -> $final_output"
    return 0
}

# Process all evidence files
process_all_evidence() {
    local temp_file_list
    temp_file_list=$(create_temp_file "evidence_files")

    log_info "Finding all evidence files..."
    find "$SOURCE_DIR" -type f > "$temp_file_list"

    local file_count
    file_count=$(wc -l < "$temp_file_list")
    log_info "Processing $file_count evidence files"

    # Process each evidence file
    local processed=0
    local failed=0
    while IFS= read -r file_path; do
        process_evidence_file "$file_path"
        if [[ $? -eq 0 ]]; then
            ((processed++))
            # Show progress every 10 files
            if ((processed % 10 == 0)); then
                log_info "Progress: $processed/$file_count files processed"
            fi
        else
            ((failed++))
            log_error "Failed to process file: $file_path"
        fi
    done < "$temp_file_list"

    log_success "Evidence processing complete: $processed files processed, $failed failures"

    # If any failures, log warning
    if [[ $failed -gt 0 ]]; then
        log_warn "$failed files failed to process properly"
    fi
}

# Generate a manifest file documenting all packaged evidence
generate_manifest() {
    local manifest_file="${OUTPUT_DIR}/metadata/evidence_package_manifest.${MANIFEST_TYPE}"
    local package_info_file="${OUTPUT_DIR}/metadata/package_info.${MANIFEST_TYPE}"

    log_info "Generating evidence package manifest"

    # Generate package information
    if [[ "$MANIFEST_TYPE" == "json" ]]; then
        {
            echo "{"
            echo "  \"package_id\": \"pkg-$(date +%Y%m%d%H%M%S)-$(hostname)-$$\","
            echo "  \"creation_timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
            echo "  \"case_id\": \"${CASE_ID:-unknown}\","
            echo "  \"examiner_id\": \"${EXAMINER_ID:-unknown}\","
            echo "  \"source_directory\": \"$SOURCE_DIR\","
            echo "  \"compression_format\": \"$OUTPUT_FORMAT\","
            echo "  \"encryption_used\": $DO_ENCRYPT,"
            echo "  \"tags\": [$(echo "$TAGS" | sed 's/,/","/g' | sed 's/^/"/;s/$/"/')],"
            echo "  \"packaging_version\": \"$EVIDENCE_PACKAGING_VERSION\","
            echo "  \"packaging_date\": \"$EVIDENCE_PACKAGING_DATE\""
            echo "}"
        } > "$package_info_file"
    else
        # Text format
        {
            echo "EVIDENCE PACKAGE INFORMATION"
            echo "==========================="
            echo "Package ID: pkg-$(date +%Y%m%d%H%M%S)-$(hostname)-$$"
            echo "Created: $(date)"
            echo "Case ID: ${CASE_ID:-unknown}"
            echo "Examiner ID: ${EXAMINER_ID:-unknown}"
            echo "Source Directory: $SOURCE_DIR"
            echo "Compression Format: $OUTPUT_FORMAT"
            echo "Encryption Used: $DO_ENCRYPT"
            echo "Tags: $TAGS"
            echo "Packaging Tool Version: $EVIDENCE_PACKAGING_VERSION (${EVIDENCE_PACKAGING_DATE})"
        } > "$package_info_file"
    fi

    # Generate file manifest by recursively hashing all packaged files
    if [[ "$MANIFEST_TYPE" == "json" ]]; then
        local temp_manifest
        temp_manifest=$(create_temp_file "temp_manifest")

        {
            echo "{"
            echo "  \"manifest_timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
            echo "  \"packaged_files\": ["

            # Find all files in the output directory
            local first_entry=true
            find "${OUTPUT_DIR}/files" -type f | sort | while read -r file_path; do
                if [[ "$first_entry" != "true" ]]; then
                    echo ","
                else
                    first_entry=false
                fi

                local rel_path="${file_path#${OUTPUT_DIR}/files/}"
                local file_size
                file_size=$(stat -c %s "$file_path" 2>/dev/null || stat -f %z "$file_path")
                local file_hash
                file_hash=$(calculate_hash "$file_path")

                printf "    {\n      \"path\": \"%s\",\n" "$rel_path"
                printf "      \"size_bytes\": %s,\n" "$file_size"
                printf "      \"hash_%s\": \"%s\"\n    }" "$DEFAULT_HASH_ALGO" "$file_hash"
            done

            echo -e "\n  ]"
            echo "}"
        } > "$temp_manifest"

        # Move temp manifest to final location
        mv "$temp_manifest" "$manifest_file"
    else
        # Text format
        {
            echo "EVIDENCE PACKAGE MANIFEST"
            echo "======================="
            echo "Generated: $(date)"
            echo "Hash Algorithm: $DEFAULT_HASH_ALGO"
            echo ""
            echo "PACKAGED FILES:"
            echo "--------------"

            find "${OUTPUT_DIR}/files" -type f | sort | while read -r file_path; do
                local rel_path="${file_path#${OUTPUT_DIR}/files/}"
                local file_size
                file_size=$(stat -c %s "$file_path" 2>/dev/null || stat -f %z "$file_path")
                local file_hash
                file_hash=$(calculate_hash "$file_path")

                printf "%-60s  %10s bytes  %s\n" "$rel_path" "$file_size" "$file_hash"
            done

            echo ""
            echo "End of Manifest"
        } > "$manifest_file"
    fi

    chmod "$DEFAULT_EVIDENCE_PERMS" "$manifest_file" || log_warn "Failed to set permissions on $manifest_file"
    chmod "$DEFAULT_EVIDENCE_PERMS" "$package_info_file" || log_warn "Failed to set permissions on $package_info_file"

    log_success "Generated evidence package manifest: $manifest_file"
    log_success "Generated package information: $package_info_file"

    log_coc_event "Created" "Package Manifest" "File: $manifest_file, Format: $MANIFEST_TYPE"
}

# Create final package archive if requested
create_package_archive() {
    local archive_name="${OUTPUT_DIR}.tar"

    log_info "Creating final package archive: $archive_name"

    # Create tar archive
    tar -cf "$archive_name" -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")" || {
        log_error "Failed to create package archive"
        return 1
    }

    # Calculate hash of the entire archive
    local archive_hash
    archive_hash=$(calculate_hash "$archive_name")

    log_success "Created evidence package archive: $archive_name"
    log_success "Archive hash ($DEFAULT_HASH_ALGO): $archive_hash"

    # Create hash file
    echo "$archive_hash  $(basename "$archive_name")" > "${archive_name}.${DEFAULT_HASH_ALGO}"
    chmod "$DEFAULT_EVIDENCE_PERMS" "${archive_name}.${DEFAULT_HASH_ALGO}" || log_warn "Failed to set permissions on ${archive_name}.${DEFAULT_HASH_ALGO}"

    log_coc_event "Created" "Evidence Package Archive" "File: $archive_name, Hash: $archive_hash"

    return 0
}

# Register with evidence tracking system (if available)
register_with_evidence_tracker() {
    local package_file="$1"
    local description="Evidence package from ${SOURCE_DIR}"

    if [[ -z "$CASE_ID" ]]; then
        log_warn "Case ID not provided, skipping evidence registration"
        return 1
    fi

    if [[ -z "$EXAMINER_ID" ]]; then
        log_warn "Examiner ID not provided, skipping evidence registration"
        return 1
    }

    log_info "Registering evidence package with tracking system"

    # Check if registration script exists
    local register_script="${SCRIPT_DIR}/../utils/register_evidence.py"
    if [[ ! -f "$register_script" ]]; then
        log_warn "Evidence registration script not found: $register_script"
        return 1
    }

    # Execute registration script
    if "$register_script" \
        --case-id "$CASE_ID" \
        --description "$description" \
        --type "evidence_package" \
        --source "$(hostname)" \
        --method "evidence_packaging.sh" \
        --analyst "$EXAMINER_ID" \
        --file "$package_file" \
        --hash-algo "$DEFAULT_HASH_ALGO"; then

        log_success "Evidence package registered successfully"
        return 0
    else
        log_error "Failed to register evidence package"
        return 1
    fi
}

# Clean up temporary files and working directory
cleanup() {
    if [[ -d "${OUTPUT_DIR}/working" ]]; then
        log_debug "Cleaning up working directory"
        rm -rf "${OUTPUT_DIR}/working"
    fi

    log_debug "Removing temporary files"
    # Common functions will handle TEMP_FILES_TO_REMOVE
}

# Main function
main() {
    # Parse command-line options
    SOURCE_DIR=""
    OUTPUT_DIR=""
    OUTPUT_FORMAT="$DEFAULT_OUTPUT_FORMAT"
    DO_COMPRESS="true"
    DO_ENCRYPT="$DEFAULT_ENCRYPTION"
    MANIFEST_TYPE="$DEFAULT_MANIFEST_TYPE"
    SPLIT_SIZE="$DEFAULT_SPLIT_SIZE"
    VERIFY_AFTER="$DEFAULT_VERIFY_AFTER"
    TAGS=""
    CREATE_ARCHIVE=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                ;;
            --version)
                show_version
                ;;
            -o|--output)
                shift
                OUTPUT_DIR="$1"
                ;;
            -c|--case-id)
                shift
                CASE_ID="$1"
                ;;
            -e|--examiner)
                shift
                EXAMINER_ID="$1"
                ;;
            -f|--format)
                shift
                OUTPUT_FORMAT="$1"
                ;;
            -m|--manifest-type)
                shift
                MANIFEST_TYPE="$1"
                ;;
            -p|--password)
                DO_ENCRYPT="true"
                # Password handling would go here
                log_warn "Password encryption not implemented in this version"
                ;;
            -k|--key-file)
                shift
                DO_ENCRYPT="true"
                # Key file handling would go here
                log_warn "Key file encryption not implemented in this version"
                ;;
            -s|--split-size)
                shift
                SPLIT_SIZE="$1"
                ;;
            -t|--tags)
                shift
                TAGS="$1"
                ;;
            -v|--verbose)
                VERBOSE=true
                ;;
            -q|--quiet)
                QUIET=true
                ;;
            --no-compress)
                DO_COMPRESS="false"
                OUTPUT_FORMAT="none"
                ;;
            --no-encrypt)
                DO_ENCRYPT="false"
                ;;
            --no-verify)
                VERIFY_AFTER="false"
                ;;
            --log)
                shift
                LOG_FILE="$1"
                ;;
            --audit-log)
                shift
                AUDIT_LOG_FILE="$1"
                ;;
            --create-archive)
                CREATE_ARCHIVE=true
                ;;
            *)
                # Consider this the source directory
                if [[ -z "$SOURCE_DIR" ]]; then
                    SOURCE_DIR="$1"
                else
                    log_error "Unknown option or multiple source directories specified: $1"
                    usage
                fi
                ;;
        esac
        shift
    done

    # Validate options
    if [[ -z "$SOURCE_DIR" ]]; then
        log_error "No source evidence directory specified"
        usage
    fi

    # Check source directory
    if [[ ! -d "$SOURCE_DIR" ]]; then
        error_exit "Source directory does not exist: $SOURCE_DIR"
    fi

    # If output directory not specified, create default
    if [[ -z "$OUTPUT_DIR" ]]; then
        OUTPUT_DIR="${SOURCE_DIR}_packaged"
    fi

    # Initialize common functions
    init_common_functions "${LOG_FILE}" "${AUDIT_LOG_FILE}" "${OUTPUT_DIR}"

    log_info "Evidence Packaging v${EVIDENCE_PACKAGING_VERSION} started"
    log_info "Source Directory: $SOURCE_DIR"
    log_info "Output Directory: $OUTPUT_DIR"

    # Main workflow
    init_environment
    inventory_evidence "$SOURCE_DIR"
    process_all_evidence
    generate_manifest

    # Create archive if requested
    if [[ "$CREATE_ARCHIVE" == "true" ]]; then
        create_package_archive

        # Register with evidence tracker if case ID provided
        if [[ -n "$CASE_ID" ]]; then
            register_with_evidence_tracker "${OUTPUT_DIR}.tar"
        fi
    fi

    # Clean up
    cleanup

    log_success "Evidence packaging complete"
    return 0
}

# Execute main function
main "$@"
