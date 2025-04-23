#!/bin/bash
# filepath: scripts/utils/dev_tools/generate_docs.sh
#
# Documentation Generator for Cloud Infrastructure Platform
#
# This script automates the generation of various documentation types:
# - API documentation from source files
# - Markdown documentation from code comments
# - User guides from templates
# - Command-line help documentation
#
# Usage: ./generate_docs.sh [OPTIONS] [DIRECTORIES]

set -o pipefail
set -o nounset

# Script version and metadata
VERSION="1.0.0"
SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")" && pwd)"
PYTHON_SCRIPTS_DIR="${SCRIPT_DIR}/python"

# Default configuration values
CONFIG_FILE="${PROJECT_ROOT}/config/documentation.conf"
OUTPUT_DIR="${PROJECT_ROOT}/docs"
TEMPLATE_DIR="${PROJECT_ROOT}/scripts/utils/dev_tools/templates"
LOG_FILE="${PROJECT_ROOT}/logs/doc_generation.log"

# Target directories
API_DIR="${PROJECT_ROOT}/api"
BLUEPRINTS_DIR="${PROJECT_ROOT}/blueprints"
CLI_DIR="${PROJECT_ROOT}/cli"
MODELS_DIR="${PROJECT_ROOT}/models"
SCRIPTS_DIR="${PROJECT_ROOT}/scripts"
SERVICES_DIR="${PROJECT_ROOT}/services"

# Documentation organization
API_DOCS_DIR="${OUTPUT_DIR}/api"
USER_GUIDES_DIR="${OUTPUT_DIR}/user_guides"
DEV_DOCS_DIR="${OUTPUT_DIR}/dev"
CLI_DOCS_DIR="${OUTPUT_DIR}/cli"

# Tools and commands - can be overridden in config
SPHINX_CMD="sphinx-build"
SPHINX_APIDOC="sphinx-apidoc"
MKDOCS_CMD="mkdocs"
PDOC_CMD="pdoc"
PYDOC_CMD="pydoc"

# Default formats
DEFAULT_FORMAT="markdown"
SUPPORTED_FORMATS=("markdown" "html" "rst" "pdf")

# Default document types to generate
GENERATE_API_DOCS=true
GENERATE_CODE_DOCS=true
GENERATE_USER_GUIDES=true
GENERATE_CLI_DOCS=true

# Control flags
VERBOSE=false
CLEAN_FIRST=false
FORCE=false
DRY_RUN=false
INCLUDE_PRIVATE=false
INCLUDE_DEPRECATED=false

# Colors for terminal output
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
BLUE="\033[0;34m"
CYAN="\033[0;36m"
NC="\033[0m"  # No color

# Import common functions from the utilities library
if [[ -f "${PROJECT_ROOT}/scripts/utils/common_functions.sh" ]]; then
    # shellcheck source=/dev/null
    source "${PROJECT_ROOT}/scripts/utils/common_functions.sh" --quiet core
fi

#######################################
# HELPER FUNCTIONS
#######################################

# Use common functions if available or define minimal versions
if ! command -v log_info &>/dev/null; then
    # Write log message
    # Arguments:
    #   $1 - Log level (INFO, WARN, ERROR, DEBUG)
    #   $2 - Message to log
    log() {
        local level="$1"
        local message="$2"
        local timestamp
        timestamp=$(date "+%Y-%m-%d %H:%M:%S")

        # Create log directory if it doesn't exist
        mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null

        # Log to file
        echo "[$timestamp] [$level] $message" >> "$LOG_FILE"

        # Log to console based on verbosity and level
        case "$level" in
            INFO)
                echo -e "${GREEN}[$level]${NC} $message"
                ;;
            WARN)
                echo -e "${YELLOW}[$level]${NC} $message" >&2
                ;;
            ERROR)
                echo -e "${RED}[$level]${NC} $message" >&2
                ;;
            DEBUG)
                [[ "$VERBOSE" == true ]] && echo -e "${BLUE}[$level]${NC} $message"
                ;;
            *)
                echo -e "[$level] $message"
                ;;
        esac
    }

    log_info() { log "INFO" "$1"; }
    log_warn() { log "WARN" "$1"; }
    log_error() { log "ERROR" "$1"; }
    log_debug() { log "DEBUG" "$1"; }
fi

# Check if a command exists if not defined in common_functions
if ! command -v command_exists &>/dev/null; then
    command_exists() {
        command -v "$1" >/dev/null 2>&1
    }
fi

# Create directory if it doesn't exist if not defined in common_functions
if ! command -v ensure_directory &>/dev/null; then
    ensure_directory() {
        local dir="$1"
        if [[ ! -d "$dir" ]]; then
            if [[ "$DRY_RUN" == true ]]; then
                log_debug "Would create directory: $dir"
            else
                log_debug "Creating directory: $dir"
                mkdir -p "$dir" || {
                    log_error "Failed to create directory: $dir"
                    return 1
                }
            fi
        fi
    }
fi

# Display help message
show_help() {
    cat << EOF
${SCRIPT_NAME} - Documentation Generator for Cloud Infrastructure Platform v${VERSION}

USAGE:
    ${SCRIPT_NAME} [OPTIONS] [DIRECTORIES]

OPTIONS:
    -h, --help                 Show this help message
    -v, --verbose              Enable verbose output
    -c, --config FILE          Use custom config file (default: ${CONFIG_FILE})
    -o, --output DIR           Set output directory (default: ${OUTPUT_DIR})
    -f, --format FORMAT        Output format: markdown, html, rst, pdf (default: ${DEFAULT_FORMAT})
    -t, --template DIR         Template directory (default: ${TEMPLATE_DIR})
    -p, --private              Include private members in documentation
    -d, --deprecated           Include deprecated features in documentation
    --clean                    Clean output directory before generating docs
    --force                    Overwrite existing files without prompting
    --dry-run                  Show what would be done without making changes

    --api                      Generate API documentation only
    --code                     Generate code documentation only
    --user-guides              Generate user guides only
    --cli                      Generate CLI documentation only
    --no-api                   Skip API documentation
    --no-code                  Skip code documentation
    --no-user-guides           Skip user guides
    --no-cli                   Skip CLI documentation

DIRECTORIES:
    Specific directories to document (default: document all)

EXAMPLES:
    ${SCRIPT_NAME} --verbose                     # Generate all docs with detailed output
    ${SCRIPT_NAME} --format html --clean         # Generate HTML docs, cleaning first
    ${SCRIPT_NAME} --api api/endpoints           # Document only the endpoints directory
    ${SCRIPT_NAME} --user-guides --cli           # Generate only user guides and CLI docs

The script reads configuration from ${CONFIG_FILE} if available.
EOF
}

# Load configuration file
# Arguments:
#   $1 - Path to config file
load_config() {
    local config="$1"

    if [[ ! -f "$config" ]]; then
        log_warn "Config file not found: $config. Using defaults."
        return 1
    fi

    log_debug "Loading configuration from $config"

    # shellcheck source=/dev/null
    source "$config" || {
        log_error "Failed to load config file: $config"
        return 1
    }

    log_debug "Loaded configuration from $config"
    return 0
}

# Parse command line arguments
# Arguments:
#   $@ - Command line arguments
parse_arguments() {
    local skip_next=false
    local dirs=()

    while [[ $# -gt 0 ]]; do
        if [[ "$skip_next" == true ]]; then
            skip_next=false
            shift
            continue
        fi

        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                ;;
            -c|--config)
                if [[ -z "${2:-}" ]]; then
                    log_error "No config file specified for --config"
                    exit 1
                fi
                CONFIG_FILE="$2"
                skip_next=true
                ;;
            -o|--output)
                if [[ -z "${2:-}" ]]; then
                    log_error "No output directory specified for --output"
                    exit 1
                fi
                OUTPUT_DIR="$2"
                skip_next=true
                ;;
            -f|--format)
                if [[ -z "${2:-}" ]]; then
                    log_error "No format specified for --format"
                    exit 1
                fi
                local format="$2"
                # Check if format is supported
                local format_supported=false
                for supported in "${SUPPORTED_FORMATS[@]}"; do
                    if [[ "$supported" == "$format" ]]; then
                        format_supported=true
                        break
                    fi
                done
                if [[ "$format_supported" != true ]]; then
                    log_error "Unsupported format: $format. Use one of: ${SUPPORTED_FORMATS[*]}"
                    exit 1
                fi
                DEFAULT_FORMAT="$format"
                skip_next=true
                ;;
            -t|--template)
                if [[ -z "${2:-}" ]]; then
                    log_error "No template directory specified for --template"
                    exit 1
                fi
                TEMPLATE_DIR="$2"
                skip_next=true
                ;;
            -p|--private)
                INCLUDE_PRIVATE=true
                ;;
            -d|--deprecated)
                INCLUDE_DEPRECATED=true
                ;;
            --clean)
                CLEAN_FIRST=true
                ;;
            --force)
                FORCE=true
                ;;
            --dry-run)
                DRY_RUN=true
                ;;
            --api)
                GENERATE_API_DOCS=true
                GENERATE_CODE_DOCS=false
                GENERATE_USER_GUIDES=false
                GENERATE_CLI_DOCS=false
                ;;
            --code)
                GENERATE_API_DOCS=false
                GENERATE_CODE_DOCS=true
                GENERATE_USER_GUIDES=false
                GENERATE_CLI_DOCS=false
                ;;
            --user-guides)
                GENERATE_API_DOCS=false
                GENERATE_CODE_DOCS=false
                GENERATE_USER_GUIDES=true
                GENERATE_CLI_DOCS=false
                ;;
            --cli)
                GENERATE_API_DOCS=false
                GENERATE_CODE_DOCS=false
                GENERATE_USER_GUIDES=false
                GENERATE_CLI_DOCS=true
                ;;
            --no-api)
                GENERATE_API_DOCS=false
                ;;
            --no-code)
                GENERATE_CODE_DOCS=false
                ;;
            --no-user-guides)
                GENERATE_USER_GUIDES=false
                ;;
            --no-cli)
                GENERATE_CLI_DOCS=false
                ;;
            -*)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
            *)
                # Assume it's a directory to document
                dirs+=("$1")
                ;;
        esac
        shift
    done

    # If specific directories were provided, use only those
    if [[ ${#dirs[@]} -gt 0 ]]; then
        log_debug "Using specified directories: ${dirs[*]}"
        TARGET_DIRS=("${dirs[@]}")
    fi

    return 0
}

# Clean output directory
clean_output_directory() {
    if [[ "$CLEAN_FIRST" != true ]]; then
        return 0
    fi

    log_info "Cleaning output directory: $OUTPUT_DIR"

    if [[ "$DRY_RUN" == true ]]; then
        log_debug "Would clean directory: $OUTPUT_DIR"
        return 0
    fi

    if [[ -d "$OUTPUT_DIR" ]]; then
        log_debug "Removing existing files in $OUTPUT_DIR"
        rm -rf "${OUTPUT_DIR:?}"/* || {
            log_error "Failed to clean output directory: $OUTPUT_DIR"
            return 1
        }
    fi

    return 0
}

# Check for required tools
check_requirements() {
    local missing_tools=()

    if [[ "$GENERATE_API_DOCS" == true ]]; then
        if ! command_exists "$SPHINX_CMD" && ! command_exists "$PDOC_CMD"; then
            missing_tools+=("sphinx-build or pdoc (for API docs)")
        fi
    fi

    if [[ "$GENERATE_CODE_DOCS" == true ]]; then
        if ! command_exists "$PDOC_CMD" && ! command_exists "$PYDOC_CMD"; then
            missing_tools+=("pdoc or pydoc (for code docs)")
        fi
    fi

    if [[ "$GENERATE_USER_GUIDES" == true ]]; then
        if ! command_exists "$MKDOCS_CMD"; then
            missing_tools+=("mkdocs (for user guides)")
        fi
    fi

    if [[ "$GENERATE_CLI_DOCS" == true ]]; then
        if ! command_exists "python3"; then
            missing_tools+=("python3 (for CLI docs)")
        fi
    fi

    if [[ "${#missing_tools[@]}" -gt 0 ]]; then
        log_warn "Missing required tools: ${missing_tools[*]}"
        log_warn "Some documentation may not be generated correctly."
    fi

    return 0
}

# Check if Python helper scripts exist, and use existing ones or create symbolic links
check_python_helpers() {
    # Create Python scripts directory if it doesn't exist
    ensure_directory "$PYTHON_SCRIPTS_DIR" || return 1

    # Check for existing utility scripts in project
    local utils_python_dir="${PROJECT_ROOT}/scripts/utils/python"
    local missing_scripts=()
    local required_scripts=("process_template.py" "generate_cli_docs.py" "convert_format.py")

    for script in "${required_scripts[@]}"; do
        if [[ ! -f "${PYTHON_SCRIPTS_DIR}/${script}" ]]; then
            # Look for script in the project's Python utils directory
            if [[ -f "${utils_python_dir}/${script}" ]]; then
                log_debug "Using project's ${script}"
                ln -sf "${utils_python_dir}/${script}" "${PYTHON_SCRIPTS_DIR}/${script}"
            else
                # Special case for convert_format.py - can use json_yaml_converter.py
                if [[ "$script" == "convert_format.py" && -f "${utils_python_dir}/json_yaml_converter.py" ]]; then
                    log_debug "Using project's JSON/YAML converter for basic format conversion"
                    ln -sf "${utils_python_dir}/json_yaml_converter.py" "${PYTHON_SCRIPTS_DIR}/json_yaml_converter.py"
                fi

                missing_scripts+=("$script")
            fi
        fi
    done

    # If any scripts are missing, use the utility script to create them
    if [[ ${#missing_scripts[@]} -gt 0 ]]; then
        local python_generator="${SCRIPT_DIR}/python/create_doc_utils.py"

        # Check if we have the generator script
        if [[ -f "$python_generator" && -x "$python_generator" ]]; then
            for script in "${missing_scripts[@]}"; do
                log_info "Creating missing helper script: $script"
                "$python_generator" --create "$script" --output "${PYTHON_SCRIPTS_DIR}/$script" || {
                    log_error "Failed to create $script"
                    return 1
                }
            done
        else
            log_error "Cannot find helper script generator. Missing required scripts: ${missing_scripts[*]}"
            return 1
        fi
    fi

    # Make all scripts executable
    chmod +x "${PYTHON_SCRIPTS_DIR}"/*.py 2>/dev/null

    return 0
}

# Generate API documentation
generate_api_documentation() {
    if [[ "$GENERATE_API_DOCS" != true ]]; then
        log_debug "Skipping API documentation generation"
        return 0
    fi

    log_info "Generating API documentation in format: $DEFAULT_FORMAT"
    ensure_directory "$API_DOCS_DIR" || return 1

    # Use the dedicated API doc generator if available
    local api_doc_gen="${PROJECT_ROOT}/scripts/utils/dev_tools/python/generate_api_docs.py"

    if [[ -f "$api_doc_gen" && -x "$api_doc_gen" ]]; then
        log_debug "Using dedicated API documentation generator"

        if [[ "$DRY_RUN" == true ]]; then
            log_debug "Would generate API docs using $api_doc_gen"
            return 0
        fi

        "$api_doc_gen" \
            --dirs "$API_DIR" "$BLUEPRINTS_DIR" \
            --output "$API_DOCS_DIR" \
            --format "$DEFAULT_FORMAT" \
            $([ "$INCLUDE_PRIVATE" == "true" ] && echo "--private") \
            $([ "$INCLUDE_DEPRECATED" == "true" ] && echo "--deprecated") || {
                log_error "API documentation generation failed"
                return 1
            }

        log_info "API documentation generation complete"
        return 0
    fi

    # Fall back to using Sphinx or pdoc
    if command_exists "$SPHINX_CMD"; then
        log_debug "Using Sphinx for API documentation"
        # Sphinx code would go here, but offloaded to a separate script
        log_error "API documentation generation requires the dedicated generator script"
        return 1
    elif command_exists "$PDOC_CMD"; then
        log_debug "Using pdoc for API documentation"
        # pdoc code would go here, but offloaded to a separate script
        log_error "API documentation generation requires the dedicated generator script"
        return 1
    else
        log_error "No suitable tool found for generating API documentation"
        return 1
    fi
}

# Generate code documentation from comments
generate_code_documentation() {
    if [[ "$GENERATE_CODE_DOCS" != true ]]; then
        log_debug "Skipping code documentation generation"
        return 0
    fi

    log_info "Generating code documentation in format: $DEFAULT_FORMAT"
    ensure_directory "$DEV_DOCS_DIR" || return 1

    # Use the dedicated code doc generator if available
    local code_doc_gen="${PROJECT_ROOT}/scripts/utils/dev_tools/python/generate_code_docs.py"

    if [[ -f "$code_doc_gen" && -x "$code_doc_gen" ]]; then
        log_debug "Using dedicated code documentation generator"

        if [[ "$DRY_RUN" == true ]]; then
            log_debug "Would generate code docs using $code_doc_gen"
            return 0
        }

        "$code_doc_gen" \
            --dirs "$MODELS_DIR" "$SERVICES_DIR" "$SCRIPTS_DIR/core" "$SCRIPTS_DIR/utils" \
            --output "$DEV_DOCS_DIR" \
            --format "$DEFAULT_FORMAT" \
            --scripts \
            $([ "$INCLUDE_PRIVATE" == "true" ] && echo "--private") \
            $([ "$FORCE" == "true" ] && echo "--force") || {
                log_error "Code documentation generation failed"
                return 1
            }

        log_info "Code documentation generation complete"
        return 0
    fi

    # Fall back to bare implementation
    log_warn "Code documentation generation requires the dedicated generator script"
    log_warn "Limited code documentation will be generated"

    # Generate documentation for shell scripts
    local shell_doc_gen="${SCRIPT_DIR}/extract_shell_docs.sh"

    if [[ -f "$shell_doc_gen" && -x "$shell_doc_gen" ]]; then
        log_debug "Using shell documentation generator"

        if [[ "$DRY_RUN" == true ]]; then
            log_debug "Would generate shell script docs from: $SCRIPTS_DIR"
            return 0
        }

        while IFS= read -r -d '' script; do
            local rel_path="${script#$PROJECT_ROOT/}"
            local output_dir="${DEV_DOCS_DIR}/$(dirname "$rel_path")"
            local output_file="$output_dir/$(basename "$script").md"

            ensure_directory "$output_dir"

            log_debug "Extracting documentation from $rel_path"

            "$shell_doc_gen" --input "$script" --output "$output_file" --format "$DEFAULT_FORMAT" || {
                log_warn "Failed to extract documentation from $rel_path"
                continue
            }
        done < <(find "$SCRIPTS_DIR" -name "*.sh" -type f -print0)
    else
        log_warn "Shell documentation generator not found: $shell_doc_gen"
    }

    log_info "Basic code documentation generation complete"
    return 0
}

# Generate user guides from templates
generate_user_guides() {
    if [[ "$GENERATE_USER_GUIDES" != true ]]; then
        log_debug "Skipping user guide generation"
        return 0
    fi

    log_info "Generating user guides in format: $DEFAULT_FORMAT"
    ensure_directory "$USER_GUIDES_DIR" || return 1

    # Check if template directory exists
    if [[ ! -d "$TEMPLATE_DIR" ]]; then
        log_error "Template directory not found: $TEMPLATE_DIR"
        return 1
    }

    # Make sure required Python scripts exist
    check_python_helpers || {
        log_error "Failed to set up required Python helper scripts"
        return 1
    }

    # Use the dedicated user guide generator if available
    local guide_gen="${PROJECT_ROOT}/scripts/utils/dev_tools/python/generate_user_guides.py"

    if [[ -f "$guide_gen" && -x "$guide_gen" ]]; then
        log_debug "Using dedicated user guide generator"

        if [[ "$DRY_RUN" == true ]]; then
            log_debug "Would generate user guides using $guide_gen"
            return 0
        }

        "$guide_gen" \
            --template-dir "$TEMPLATE_DIR" \
            --output-dir "$USER_GUIDES_DIR" \
            --format "$DEFAULT_FORMAT" \
            $([ "$FORCE" == "true" ] && echo "--force") || {
                log_error "User guide generation failed"
                return 1
            }

        log_info "User guide generation complete"
        return 0
    fi

    # Find template files
    local templates=()
    while IFS= read -r -d '' template; do
        templates+=("$template")
    done < <(find "$TEMPLATE_DIR" -name "*.md.tmpl" -type f -print0 2>/dev/null)

    if [[ ${#templates[@]} -eq 0 ]]; then
        log_warn "No template files found in $TEMPLATE_DIR"
        return 0
    }

    if [[ "$DRY_RUN" == true ]]; then
        log_debug "Would process ${#templates[@]} templates"
        return 0
    }

    # Process each template using the process_template.py script
    local python_script="${PYTHON_SCRIPTS_DIR}/process_template.py"

    for template in "${templates[@]}"; do
        local template_name
        template_name=$(basename "$template")
        template_name="${template_name%.tmpl}"  # Remove .tmpl

        local rel_path="${template#$TEMPLATE_DIR/}"
        local output_dir="${USER_GUIDES_DIR}/$(dirname "$rel_path")"
        local output_file="$output_dir/${template_name}"

        ensure_directory "$output_dir"
        log_debug "Processing template: $rel_path"

        # Look for template variables
        local vars_file="${template%.tmpl}.vars"
        local global_vars_file="${TEMPLATE_DIR}/variables.json"
        local template_data="{}"

        if [[ -f "$vars_file" ]]; then
            template_data=$(<"$vars_file")
        elif [[ -f "$global_vars_file" ]]; then
            template_data=$(<"$global_vars_file")
        fi

        # Add common variables
        if command_exists "jq"; then
            template_data=$(echo "$template_data" | jq '. + {"generation_date":"'"$(date +"%Y-%m-%d")"'","generation_time":"'"$(date +"%H:%M:%S")"'","generator":"'"$SCRIPT_NAME"'"}')
        fi

        "$python_script" "$template" "$output_file" "$DEFAULT_FORMAT" "$template_data" || {
            log_error "Failed to process template: $rel_path"
            continue
        }

        log_info "Processed user guide template: $rel_path"
    done

    log_info "User guide generation complete"
    return 0
}

# Generate CLI documentation
generate_cli_documentation() {
    if [[ "$GENERATE_CLI_DOCS" != true ]]; then
        log_debug "Skipping CLI documentation generation"
        return 0
    fi

    log_info "Generating CLI documentation in format: $DEFAULT_FORMAT"
    ensure_directory "$CLI_DOCS_DIR" || return 1

    if [[ ! -d "$CLI_DIR" ]]; then
        log_warn "CLI directory not found: $CLI_DIR"
        return 0
    }

    if [[ "$DRY_RUN" == true ]]; then
        log_debug "Would generate CLI documentation from: $CLI_DIR"
        return 0
    }

    # Create the Python scripts directory if needed
    check_python_helpers || {
        log_error "Failed to set up Python helper scripts"
        return 1
    }

    # Use the cli_doc_script to generate docs
    local cli_doc_script="${PYTHON_SCRIPTS_DIR}/generate_cli_docs.py"

    # Look for an existing script in the project's Python utilities
    if [[ ! -f "$cli_doc_script" ]]; then
        local existing_script="${PROJECT_ROOT}/scripts/utils/python/generate_cli_docs.py"
        if [[ -f "$existing_script" ]]; then
            log_debug "Using existing CLI documentation generator: $existing_script"
            cli_doc_script="$existing_script"
        fi
    }

    # Generate CLI documentation using the Python script
    "$cli_doc_script" "$CLI_DIR" "$CLI_DOCS_DIR" "$DEFAULT_FORMAT" "$INCLUDE_PRIVATE" "$INCLUDE_DEPRECATED" "$PROJECT_ROOT" || {
        log_error "Failed to generate CLI documentation"
        return 1
    }

    # Convert to the requested format if needed
    if [[ "$DEFAULT_FORMAT" != "markdown" ]]; then
        convert_directory_format "$CLI_DOCS_DIR" "markdown" "$DEFAULT_FORMAT" || {
            log_error "Failed to convert CLI documentation to $DEFAULT_FORMAT"
            return 1
        }
    }

    log_info "CLI documentation generation complete"
    return 0
}

# Convert all files in a directory from one format to another
# Arguments:
#   $1 - Directory containing files
#   $2 - Input format
#   $3 - Output format
#   $4 - Whether to process recursively (true/false)
convert_directory_format() {
    local directory="$1"
    local input_format="$2"
    local output_format="$3"
    local recursive="${4:-true}"

    # Use the dedicated format converter if available
    local converter_script="${PYTHON_SCRIPTS_DIR}/convert_format.py"

    if [[ -f "$converter_script" && -x "$converter_script" ]]; then
        log_debug "Converting directory using convert_format.py"
        "$converter_script" "$directory" "$input_format" "$output_format" "$recursive" || {
            log_error "Failed to convert files in $directory to $output_format"
            return 1
        }
        return 0
    }

    # Fall back to using pandoc directly
    log_debug "Using pandoc for format conversion"

    if ! command_exists "pandoc"; then
        log_error "Pandoc not available for format conversion"
        return 1
    }

    local find_args=("-type" "f")
    [[ "$recursive" != "true" ]] && find_args+=("-maxdepth" "1")
    find_args+=("-name" "*.${input_format}")

    # Find and convert each file
    while IFS= read -r -d '' file; do
        local out_file="${file%.*}.${output_format}"
        log_debug "Converting $file to $output_format"

        pandoc "$file" -o "$out_file" || {
            log_error "Failed to convert ${file} to ${output_format}"
            continue
        }

        rm "$file"
    done < <(find "$directory" "${find_args[@]}" -print0)

    return 0
}

# Generate index page
# Arguments:
#   $1 - Duration in seconds
#   $2 - Success count
#   $3 - Error count
#   $4 - Skipped count
generate_index_page() {
    local duration="$1"
    local success_count="$2"
    local errors="$3"
    local skipped_count="$4"

    log_info "Generating index page"

    if [[ "$DRY_RUN" == true ]]; then
        log_debug "Would generate index page"
        return 0
    }

    # Create basic index content
    local index_output="${OUTPUT_DIR}/index.md"

    cat > "$index_output" << EOF
# Cloud Infrastructure Platform Documentation

Documentation generated on $(date "+%Y-%m-%d at %H:%M:%S") by $SCRIPT_NAME v$VERSION

## Available Documentation

EOF

    if [[ "$GENERATE_API_DOCS" == true && -d "$API_DOCS_DIR" ]]; then
        echo "- [API Documentation](api/index.md) - Reference documentation for APIs" >> "$index_output"
    fi

    if [[ "$GENERATE_CODE_DOCS" == true && -d "$DEV_DOCS_DIR" ]]; then
        echo "- [Developer Documentation](dev/index.md) - Code documentation for developers" >> "$index_output"
    fi

    if [[ "$GENERATE_USER_GUIDES" == true && -d "$USER_GUIDES_DIR" ]]; then
        echo "- [User Guides](user_guides/index.md) - User-oriented documentation" >> "$index_output"
    fi

    if [[ "$GENERATE_CLI_DOCS" == true && -d "$CLI_DOCS_DIR" ]]; then
        echo "- [CLI Reference](cli/index.md) - Command-line interface documentation" >> "$index_output"
    fi

    cat >> "$index_output" << EOF

## Generation Summary

- Execution time: $duration seconds
- Documentation types generated: $success_count
- Documentation types skipped: $skipped_count
- Errors encountered: $errors
- Format: $DEFAULT_FORMAT

### Settings Used

- Include private members: $INCLUDE_PRIVATE
- Include deprecated features: $INCLUDE_DEPRECATED
EOF

    # Convert to the requested format if needed
    if [[ "$DEFAULT_FORMAT" != "markdown" ]]; then
        local converter_script="${PYTHON_SCRIPTS_DIR}/convert_format.py"
        if [[ -f "$converter_script" ]]; then
            "$converter_script" "$OUTPUT_DIR" "md" "$DEFAULT_FORMAT" "false" || log_warn "Failed to convert index page format"
        elif command_exists "pandoc"; then
            pandoc "$index_output" -o "${index_output%.md}.${DEFAULT_FORMAT}" && rm "$index_output" || log_warn "Failed to convert index page format"
        fi
    }

    return 0
}

# Send notifications if available
# Arguments:
#   $1 - Priority (low, medium, high)
#   $2 - Subject
#   $3 - Message
#   $4 - Optional attachment
send_notification() {
    local priority="$1"
    local subject="$2"
    local message="$3"
    local attachment="${4:-}"

    # Skip if dry run
    [[ "$DRY_RUN" == true ]] && return 0

    # Look for a notification utility
    local notification_script=""
    local candidates=(
        "${PROJECT_ROOT}/scripts/utils/send-notification.sh"
        "${PROJECT_ROOT}/scripts/utils/notification.sh"
        "${PROJECT_ROOT}/scripts/core/notification.py"
    )

    for candidate in "${candidates[@]}"; do
        if [[ -x "$candidate" ]]; then
            notification_script="$candidate"
            break
        fi
    done

    # If found, use it
    if [[ -n "$notification_script" ]]; then
        log_debug "Sending notification using: $notification_script"

        if [[ "$notification_script" == *".py" ]]; then
            python3 "$notification_script" \
                --priority "$priority" \
                --subject "$subject" \
                --message "$message" \
                ${attachment:+--attachment "$attachment"} \
                ${NOTIFICATION_EMAIL:+--recipient "$NOTIFICATION_EMAIL"} || {
                log_debug "Failed to send notification (non-critical)"
            }
        else
            "$notification_script" \
                --priority "$priority" \
                --subject "$subject" \
                --message "$message" \
                ${attachment:+--attachment "$attachment"} \
                ${NOTIFICATION_EMAIL:+--recipient "$NOTIFICATION_EMAIL"} || {
                log_debug "Failed to send notification (non-critical)"
            }
        fi
    else
        log_debug "No notification utility found (non-critical)"
    }
}

#######################################
# MAIN
#######################################

main() {
    # Banner
    cat << EOF

${CYAN}=================================================================================${NC}
${BLUE}                   CLOUD INFRASTRUCTURE PLATFORM DOCUMENTATION GENERATOR${NC}
${CYAN}=================================================================================${NC}
${GREEN}Version:${NC} ${VERSION}
${GREEN}Script:${NC} ${SCRIPT_NAME}

EOF

    # Parse command line arguments
    parse_arguments "$@"

    # Load configuration
    if [[ -f "$CONFIG_FILE" ]]; then
        load_config "$CONFIG_FILE"
    fi

    # Check for required tools
    check_requirements

    # Check Python helper scripts
    check_python_helpers || {
        log_error "Failed to set up required Python helper scripts"
        exit 1
    }

    # Print summary of what will be done
    log_info "Documentation generation starting with the following settings:"
    log_info "  Output directory: $OUTPUT_DIR"
    log_info "  Format: $DEFAULT_FORMAT"
    log_info "  Generate API docs: $GENERATE_API_DOCS"
    log_info "  Generate code docs: $GENERATE_CODE_DOCS"
    log_info "  Generate user guides: $GENERATE_USER_GUIDES"
    log_info "  Generate CLI docs: $GENERATE_CLI_DOCS"
    log_info "  Include private: $INCLUDE_PRIVATE"
    log_info "  Include deprecated: $INCLUDE_DEPRECATED"

    # Create output directory if it doesn't exist
    ensure_directory "$OUTPUT_DIR" || exit 1

    # Clean output directory if requested
    clean_output_directory

    # Start time
    local start_time
    start_time=$(date +%s)

    # Generate documentation
    local errors=0
    local success_count=0
    local skipped_count=0

    if [[ "$GENERATE_API_DOCS" == true ]]; then
        generate_api_documentation && ((success_count++)) || ((errors++))
    else
        log_info "Skipping API documentation generation"
        ((skipped_count++))
    fi

    if [[ "$GENERATE_CODE_DOCS" == true ]]; then
        generate_code_documentation && ((success_count++)) || ((errors++))
    else
        log_info "Skipping code documentation generation"
        ((skipped_count++))
    fi

    if [[ "$GENERATE_USER_GUIDES" == true ]]; then
        generate_user_guides && ((success_count++)) || ((errors++))
    else
        log_info "Skipping user guide generation"
        ((skipped_count++))
    fi

    if [[ "$GENERATE_CLI_DOCS" == true ]]; then
        generate_cli_documentation && ((success_count++)) || ((errors++))
    else
        log_info "Skipping CLI documentation generation"
        ((skipped_count++))
    fi

    # End time
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))

    # Generate index page
    generate_index_page "$duration" "$success_count" "$errors" "$skipped_count"

    # Print summary
    if [[ $errors -eq 0 ]]; then
        local summary_message="Documentation generation completed successfully in $duration seconds"
        log_info "${GREEN}${summary_message}${NC}"
        log_info "Documentation types generated: $success_count, Skipped: $skipped_count"
        log_info "Output directory: $OUTPUT_DIR"

        send_notification "low" "Documentation Generation Complete" "$summary_message"
    else
        local summary_message="Documentation generation completed with $errors errors in $duration seconds"
        log_error "${RED}${summary_message}${NC}"
        log_error "Documentation types generated: $success_count, Failed: $errors, Skipped: $skipped_count"
        log_error "Check the log file for details: $LOG_FILE"

        send_notification "high" "Documentation Generation Failed" "$summary_message" "$LOG_FILE"
    fi

    return $errors
}

# Execute main function
main "$@"
exit $?
