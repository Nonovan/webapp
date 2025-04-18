#!/bin/bash
# Collect and optimize static files for production deployment
# Usage: ./scripts/collect_static.sh

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
STATIC_SRC="${PROJECT_ROOT}/static"
STATIC_DEST="${PROJECT_ROOT}/instance/static"
JS_DIR="js"
CSS_DIR="css"
IMG_DIR="img"

log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $1"
}

log "Starting static files collection and optimization"

# Ensure destination directory exists
mkdir -p "$STATIC_DEST"
mkdir -p "${STATIC_DEST}/${JS_DIR}"
mkdir -p "${STATIC_DEST}/${CSS_DIR}"
mkdir -p "${STATIC_DEST}/${IMG_DIR}"

# Copy all static files
log "Copying all static files"
cp -r "$STATIC_SRC"/* "$STATIC_DEST/"

# Generate SRI hashes for JS and CSS files
log "Generating SRI hashes for JS and CSS files"
SRI_FILE="${PROJECT_ROOT}/instance/sri_hashes.json"
echo "{" > "$SRI_FILE"

# Process JS files
first_file=true
for file in $(find "${STATIC_SRC}/${JS_DIR}" -name "*.js" -type f | sort); do
    filename=$(basename "$file")
    rel_path="${JS_DIR}/${filename}"
    
    if [ "$first_file" = false ]; then
        echo "," >> "$SRI_FILE"
    fi
    first_file=false
    
    hash=$(cat "$file" | openssl dgst -sha384 -binary | openssl base64 -A)
    echo "  \"${rel_path}\": \"sha384-${hash}\"" >> "$SRI_FILE"
done

# Process CSS files
for file in $(find "${STATIC_SRC}/${CSS_DIR}" -name "*.css" -type f | sort); do
    filename=$(basename "$file")
    rel_path="${CSS_DIR}/${filename}"
    
    echo "," >> "$SRI_FILE"
    
    hash=$(cat "$file" | openssl dgst -sha384 -binary | openssl base64 -A)
    echo "  \"${rel_path}\": \"sha384-${hash}\"" >> "$SRI_FILE"
done

echo "}" >> "$SRI_FILE"

# Minify JS files if uglifyjs is available
if command -v uglifyjs &>/dev/null; then
    log "Minifying JavaScript files"
    for file in $(find "${STATIC_DEST}/${JS_DIR}" -name "*.js" ! -name "*.min.js" -type f); do
        min_file="${file%.js}.min.js"
        uglifyjs "$file" -c -m -o "$min_file"
        # Only replace with minified version in production
        if [ "${FLASK_ENV}" == "production" ]; then
            mv "$min_file" "$file"
        fi
    done
else
    log "WARNING: uglifyjs not found, skipping JavaScript minification"
fi

# Minify CSS files if cleancss is available
if command -v cleancss &>/dev/null; then
    log "Minifying CSS files"
    for file in $(find "${STATIC_DEST}/${CSS_DIR}" -name "*.css" ! -name "*.min.css" -type f); do
        min_file="${file%.css}.min.css"
        cleancss -o "$min_file" "$file"
        # Only replace with minified version in production
        if [ "${FLASK_ENV}" == "production" ]; then
            mv "$min_file" "$file"
        fi
    done
else
    log "WARNING: cleancss not found, skipping CSS minification"
fi

# Optimize images if optipng and jpegoptim are available
if command -v optipng &>/dev/null && command -v jpegoptim &>/dev/null; then
    log "Optimizing images"
    # Optimize PNGs
    find "${STATIC_DEST}/${IMG_DIR}" -name "*.png" -type f -exec optipng -quiet -strip all {} \;
    # Optimize JPGs
    find "${STATIC_DEST}/${IMG_DIR}" -name "*.jpg" -o -name "*.jpeg" -type f -exec jpegoptim --strip-all {} \;
else
    log "WARNING: optipng or jpegoptim not found, skipping image optimization"
fi

# Set proper permissions
chmod -R 755 "$STATIC_DEST"

log "Static files collection and optimization complete"