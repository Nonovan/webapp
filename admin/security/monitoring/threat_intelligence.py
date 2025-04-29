#!/usr/bin/env python3
"""
Threat Intelligence Integration Tool for Cloud Infrastructure Platform

This script fetches, processes, and manages threat intelligence data from configured
feeds. It allows checking indicators (IPs, domains, hashes) against the collected
intelligence and can be used to update security systems based on threat data.
Designed for security operations personnel.
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

# --- Project Setup ---
# Assuming the script is run from the project root or its path is correctly handled
try:
    # Try adding the project root to the path for module imports
    PROJECT_ROOT = Path(__file__).resolve().parents[3]
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.append(str(PROJECT_ROOT))

    from core.security.cs_audit import log_security_event
    from core.security.cs_utils import is_valid_ip, is_valid_domain, is_valid_hash
    AUDIT_AVAILABLE = True
except ImportError:
    PROJECT_ROOT = Path(__file__).resolve().parents[3] # Fallback
    print("Warning: Could not import core security modules. Audit logging and validation might be limited.", file=sys.stderr)
    # Define dummy functions if core modules are unavailable
    def log_security_event(*args, **kwargs): pass
    def is_valid_ip(ip): return True # Basic fallback
    def is_valid_domain(domain): return True # Basic fallback
    def is_valid_hash(h): return True # Basic fallback
    AUDIT_AVAILABLE = False

# --- Configuration ---
ADMIN_CONFIG_DIR = PROJECT_ROOT / "admin" / "security" / "monitoring" / "config"
DEFAULT_CONFIG_FILE = ADMIN_CONFIG_DIR / "threat_feeds.json"
LOG_DIR = Path(os.environ.get("SECURITY_LOG_DIR", "/var/log/cloud-platform/security"))
DEFAULT_LOG_FILE = LOG_DIR / "threat_intelligence.log"
DEFAULT_CACHE_DIR = Path(os.environ.get("THREAT_CACHE_DIR", "/var/cache/cloud-platform/threat_intel"))
REPORT_DIR = Path(os.environ.get("THREAT_REPORT_DIR", "/var/reports/cloud-platform/threat_intel"))

# Ensure directories exist
LOG_DIR.mkdir(parents=True, exist_ok=True)
DEFAULT_CACHE_DIR.mkdir(parents=True, exist_ok=True) # Default cache dir
REPORT_DIR.mkdir(parents=True, exist_ok=True) # Default report dir

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# --- Constants ---
SUPPORTED_FEED_TYPES = ["ip_list", "domain_list", "hash_list", "structured"] # Add more as needed
IOC_TYPES = ["ip", "domain", "hash", "url"]
REQUEST_TIMEOUT = 30 # seconds

# --- Helper Functions ---

def load_config(config_file: Path = DEFAULT_CONFIG_FILE) -> Dict[str, Any]:
    """Loads the threat intelligence configuration file."""
    if not config_file.is_file():
        logger.error(f"Configuration file not found: {config_file}")
        sys.exit(1)
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
            logger.info(f"Loaded configuration from {config_file}")
            # Resolve cache directory, potentially from config
            config['local_cache_dir'] = Path(config.get('local_cache_dir', DEFAULT_CACHE_DIR))
            config['local_cache_dir'].mkdir(parents=True, exist_ok=True)
            return config
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON configuration file {config_file}: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to load configuration {config_file}: {e}")
        sys.exit(1)

def get_api_key(key_name: str) -> Optional[str]:
    """Retrieves API key from environment variables."""
    api_key = os.environ.get(key_name)
    if not api_key:
        logger.warning(f"API key '{key_name}' not found in environment variables.")
    return api_key

def fetch_feed_data(feed_config: Dict[str, Any]) -> Optional[List[str]]:
    """Fetches data from a single threat intelligence feed."""
    name = feed_config.get("name", "Unknown Feed")
    url = feed_config.get("url")
    feed_type = feed_config.get("type")
    api_key_name = feed_config.get("api_key")
    headers = feed_config.get("headers", {})
    params = feed_config.get("params", {})

    if not url or feed_type not in SUPPORTED_FEED_TYPES:
        logger.error(f"Invalid configuration for feed '{name}': Missing URL or unsupported type '{feed_type}'.")
        return None

    logger.info(f"Fetching data from feed: {name} ({url})")

    if api_key_name:
        api_key = get_api_key(api_key_name)
        if not api_key:
            logger.error(f"Skipping feed '{name}' due to missing API key '{api_key_name}'.")
            return None
        # Add API key to headers or params based on feed requirements (common patterns)
        if "Authorization" not in headers and "api_key" not in params:
             headers["Authorization"] = f"Bearer {api_key}" # Example: Bearer token
             # Or headers["X-Api-Key"] = api_key, etc. Adjust as needed per feed spec.

    try:
        response = requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        if feed_type in ["ip_list", "domain_list", "hash_list"]:
            # Expecting plain text list, one indicator per line
            lines = response.text.splitlines()
            # Basic filtering/cleaning
            indicators = [line.strip() for line in lines if line.strip() and not line.startswith('#')]
            logger.info(f"Fetched {len(indicators)} indicators from {name}.")
            return indicators
        elif feed_type == "structured":
            # Expecting JSON data, requires specific parsing logic per feed structure
            # This is a placeholder - needs implementation based on actual feed format
            try:
                data = response.json()
                # Example: Extract indicators based on a known structure
                indicators = []
                if isinstance(data, list): # e.g., AlienVault OTX export format
                    for item in data:
                        if 'indicator' in item and 'type' in item:
                             # Store as "type:value", e.g., "IPv4:1.2.3.4"
                             indicators.append(f"{item['type']}:{item['indicator']}")
                # Add more parsing logic here based on specific structured feeds
                logger.info(f"Fetched and parsed {len(indicators)} structured indicators from {name}.")
                return indicators
            except json.JSONDecodeError:
                logger.error(f"Failed to decode JSON response from structured feed {name}.")
                return None
        else:
            logger.error(f"Feed type '{feed_type}' processing not implemented for feed {name}.")
            return None

    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching feed {name}: {e}")
        return None
    except Exception as e:
        logger.error(f"An unexpected error occurred while fetching feed {name}: {e}")
        return None

def update_local_cache(cache_dir: Path, feed_name: str, indicators: List[str], retention_days: int) -> None:
    """Updates the local cache file for a given feed."""
    cache_file = cache_dir / f"{feed_name}.json"
    now = datetime.now(timezone.utc)
    timestamp = now.isoformat()

    # Load existing cache if it exists and is recent enough
    cache_data = {"indicators": {}, "metadata": {}}
    if cache_file.exists():
        try:
            with open(cache_file, 'r') as f:
                existing_cache = json.load(f)
            # Check if cache is too old (optional, could rely on update interval)
            last_update_str = existing_cache.get("metadata", {}).get("last_update")
            if last_update_str:
                last_update_dt = datetime.fromisoformat(last_update_str)
                if now - last_update_dt > timedelta(days=retention_days * 2): # Be lenient
                     logger.warning(f"Cache file {cache_file} is older than {retention_days*2} days. Rebuilding.")
                else:
                     cache_data = existing_cache
        except (json.JSONDecodeError, Exception) as e:
            logger.warning(f"Could not load or parse existing cache file {cache_file}. Rebuilding. Error: {e}")

    # Add new indicators with timestamp
    new_indicator_count = 0
    for indicator in indicators:
        if indicator not in cache_data["indicators"]:
            new_indicator_count += 1
        # Store indicator with first seen and last seen timestamps
        cache_data["indicators"][indicator] = {
            "first_seen": cache_data["indicators"].get(indicator, {}).get("first_seen", timestamp),
            "last_seen": timestamp
        }

    # Prune old indicators based on retention_days
    pruned_count = 0
    cutoff_date = now - timedelta(days=retention_days)
    indicators_to_keep = {}
    for indicator, data in cache_data["indicators"].items():
        last_seen_dt = datetime.fromisoformat(data["last_seen"])
        if last_seen_dt >= cutoff_date:
            indicators_to_keep[indicator] = data
        else:
            pruned_count += 1

    cache_data["indicators"] = indicators_to_keep
    cache_data["metadata"]["last_update"] = timestamp
    cache_data["metadata"]["feed_name"] = feed_name
    cache_data["metadata"]["indicator_count"] = len(indicators_to_keep)

    try:
        with open(cache_file, 'w') as f:
            json.dump(cache_data, f, indent=2)
        logger.info(f"Updated cache for {feed_name}: Added {new_indicator_count}, pruned {pruned_count}, total {len(indicators_to_keep)}.")
    except IOError as e:
        logger.error(f"Failed to write cache file {cache_file}: {e}")

def check_indicator(cache_dir: Path, indicator: str, ioc_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """Checks a single indicator against all cached feed data."""
    findings = []
    normalized_indicator = indicator.strip().lower()

    # Validate indicator based on type if provided
    if ioc_type == "ip" and not is_valid_ip(normalized_indicator):
        logger.warning(f"Invalid IP address format: {indicator}")
        return findings
    if ioc_type == "domain" and not is_valid_domain(normalized_indicator):
        logger.warning(f"Invalid domain format: {indicator}")
        return findings
    if ioc_type == "hash" and not is_valid_hash(normalized_indicator): # Basic length check
        logger.warning(f"Invalid hash format: {indicator}")
        return findings

    for cache_file in cache_dir.glob("*.json"):
        try:
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)
            feed_name = cache_data.get("metadata", {}).get("feed_name", cache_file.stem)
            indicators_dict = cache_data.get("indicators", {})

            # Direct lookup
            if normalized_indicator in indicators_dict:
                findings.append({
                    "indicator": indicator,
                    "feed": feed_name,
                    "found": True,
                    "details": indicators_dict[normalized_indicator],
                    "match_type": "direct"
                })
                continue

            # Check structured indicators (e.g., "IPv4:1.2.3.4")
            for structured_indicator, details in indicators_dict.items():
                 if ":" in structured_indicator:
                     st_type, st_value = structured_indicator.split(":", 1)
                     st_value_lower = st_value.lower()
                     # Match if type matches (or no type specified) and value matches
                     if (not ioc_type or ioc_type.lower() in st_type.lower()) and st_value_lower == normalized_indicator:
                         findings.append({
                             "indicator": indicator,
                             "feed": feed_name,
                             "found": True,
                             "details": details,
                             "match_type": "structured",
                             "matched_indicator": structured_indicator
                         })
                         break # Found in this feed

        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Failed to read or parse cache file {cache_file}: {e}")
            continue

    if not findings:
        logger.info(f"Indicator '{indicator}' not found in any threat intelligence feeds.")
    else:
        logger.warning(f"Indicator '{indicator}' found in {len(findings)} threat intelligence feed(s).")

    return findings

def generate_html_report(findings: List[Dict[str, Any]], output_file: Optional[str] = None) -> str:
    """
    Generates an HTML report for threat intelligence findings.

    Args:
        findings: List of threat intelligence findings
        output_file: Optional path to save the HTML report

    Returns:
        str: Path to the generated report file
    """
    if not findings:
        logger.warning("No findings to generate report from")
        return ""

    # Use default output location if not specified
    if not output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(REPORT_DIR, f"threat_intel_report_{timestamp}.html")

    # Ensure directory exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    # Group findings by feed name
    findings_by_feed = {}
    for finding in findings:
        feed_name = finding.get("feed", "Unknown")
        if feed_name not in findings_by_feed:
            findings_by_feed[feed_name] = []
        findings_by_feed[feed_name].append(finding)

    # Prepare summary counts
    total_findings = len(findings)
    feeds_with_matches = len(findings_by_feed)

    # Get earliest and latest timestamps
    first_seen_dates = []
    last_seen_dates = []
    for finding in findings:
        details = finding.get("details", {})
        if details.get("first_seen"):
            try:
                first_seen_dates.append(datetime.fromisoformat(details["first_seen"]))
            except ValueError:
                pass
        if details.get("last_seen"):
            try:
                last_seen_dates.append(datetime.fromisoformat(details["last_seen"]))
            except ValueError:
                pass

    earliest_date = min(first_seen_dates).strftime("%Y-%m-%d") if first_seen_dates else "N/A"
    latest_date = max(last_seen_dates).strftime("%Y-%m-%d") if last_seen_dates else "N/A"

    # Generate HTML report
    try:
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Intelligence Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #fff;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        header {{
            background-color: #0078d4;
            color: white;
            padding: 20px;
            margin-bottom: 20px;
        }}
        h1, h2, h3 {{
            margin-top: 0;
        }}
        .timestamp {{
            font-size: 0.9em;
            color: #ddd;
        }}
        .summary {{
            background-color: #f8f8f8;
            padding: 15px;
            margin-bottom: 20px;
            border-left: 5px solid #0078d4;
        }}
        .summary p {{
            margin: 5px 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        th, td {{
            padding: 10px;
            border: 1px solid #ddd;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .feed-section {{
            margin-bottom: 30px;
            padding: 15px;
            border-left: 5px solid #0078d4;
            background-color: #f9f9f9;
        }}
        .footer {{
            margin-top: 30px;
            padding-top: 15px;
            border-top: 1px solid #ddd;
            text-align: center;
            font-size: 0.9em;
            color: #777;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Threat Intelligence Report</h1>
            <p class="timestamp">Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </header>

        <div class="summary">
            <h2>Summary</h2>
            <p><strong>Total Indicators Found:</strong> {total_findings}</p>
            <p><strong>Feeds with Matches:</strong> {feeds_with_matches}</p>
            <p><strong>Earliest Indicator Date:</strong> {earliest_date}</p>
            <p><strong>Latest Indicator Date:</strong> {latest_date}</p>
        </div>
"""

        # Add each feed section
        for feed_name, feed_findings in findings_by_feed.items():
            html_content += f"""
        <div class="feed-section">
            <h2>Feed: {feed_name}</h2>
            <p><strong>Indicators Found:</strong> {len(feed_findings)}</p>

            <table>
                <thead>
                    <tr>
                        <th>Indicator</th>
                        <th>Match Type</th>
                        <th>First Seen</th>
                        <th>Last Seen</th>
                    </tr>
                </thead>
                <tbody>
"""

            for finding in feed_findings:
                indicator = finding.get("indicator", "N/A")
                match_type = finding.get("match_type", "N/A")
                if match_type == "structured":
                    match_type = f"Structured ({finding.get('matched_indicator', 'N/A')})"

                details = finding.get("details", {})
                first_seen = details.get("first_seen", "N/A")
                last_seen = details.get("last_seen", "N/A")

                html_content += f"""
                    <tr>
                        <td>{indicator}</td>
                        <td>{match_type}</td>
                        <td>{first_seen}</td>
                        <td>{last_seen}</td>
                    </tr>
"""

            html_content += """
                </tbody>
            </table>
        </div>
"""

        # Close HTML document
        html_content += """
        <div class="footer">
            <p>Generated by Cloud Infrastructure Platform Threat Intelligence Tool</p>
        </div>
    </div>
</body>
</html>
"""

        # Write HTML to file
        with open(output_file, "w") as f:
            f.write(html_content)

        logger.info(f"HTML report generated successfully: {output_file}")
        return output_file

    except Exception as e:
        logger.error(f"Error generating HTML report: {e}")
        return ""

# --- Main Execution ---

def main():
    parser = argparse.ArgumentParser(description="Threat Intelligence Integration Tool")
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_FILE,
        help=f"Path to the configuration file (default: {DEFAULT_CONFIG_FILE})"
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=None, # Default handled later
        help="Path to the log file (overrides default)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging (DEBUG level)"
    )

    subparsers = parser.add_subparsers(dest="command", required=True, help="Action to perform")

    # --- Update Command ---
    parser_update = subparsers.add_parser("update", help="Update local threat intelligence cache from configured feeds")
    parser_update.add_argument(
        "--feed",
        type=str,
        default=None,
        help="Update only a specific feed by name"
    )
    parser_update.add_argument(
        "--force",
        action="store_true",
        help="Force update even if update interval hasn't passed (not implemented yet)"
    )

    # --- Check Command ---
    parser_check = subparsers.add_parser("check", help="Check an indicator against the local cache")
    parser_check.add_argument(
        "indicator",
        type=str,
        help="The indicator to check (IP, domain, hash, URL)"
    )
    parser_check.add_argument(
        "--type",
        choices=IOC_TYPES,
        default=None,
        help="Specify the type of indicator for more accurate matching"
    )
    parser_check.add_argument(
        "--output",
        choices=["json", "text"],
        default="text",
        help="Output format for check results (default: text)"
    )
    parser_check.add_argument(
        "--report",
        action="store_true",
        help="Generate an HTML report of the findings"
    )
    parser_check.add_argument(
        "--report-file",
        type=str,
        default=None,
        help="Path to save the HTML report (default: auto-generated path)"
    )

    # --- List Command ---
    parser_list = subparsers.add_parser("list", help="List configured feeds or cached indicators")
    parser_list.add_argument(
        "--feeds",
        action="store_true",
        help="List configured feeds"
    )
    parser_list.add_argument(
        "--indicators",
        type=str,
        metavar="FEED_NAME",
        default=None,
        help="List cached indicators for a specific feed"
    )

    # --- Report Command ---
    parser_report = subparsers.add_parser("report", help="Generate a report for multiple indicators")
    parser_report.add_argument(
        "indicators_file",
        type=Path,
        help="Path to a file containing indicators to check (one per line)"
    )
    parser_report.add_argument(
        "--output",
        type=str,
        default=None,
        help="Path to save the HTML report (default: auto-generated path)"
    )
    parser_report.add_argument(
        "--check-all",
        action="store_true",
        help="Check all indicators even if some are invalid"
    )

    args = parser.parse_args()

    # --- Configure Logging ---
    log_file_path = args.log_file if args.log_file else DEFAULT_LOG_FILE
    file_handler = logging.FileHandler(log_file_path)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(file_handler)

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        # Also set level for root logger's handlers if needed
        for handler in logging.getLogger().handlers:
             handler.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled.")

    # --- Load Configuration ---
    config = load_config(args.config)
    cache_dir = config.get('local_cache_dir', DEFAULT_CACHE_DIR)
    retention_days = config.get('retention_days', 90)

    # --- Execute Command ---
    start_time = time.time()
    logger.info(f"Executing command: {args.command}")
    if AUDIT_AVAILABLE:
         log_security_event(
             event_type="admin_tool_execution",
             description=f"Threat intelligence tool executed with command: {args.command}",
             severity="info",
             details={"args": vars(args)}
         )

    if args.command == "update":
        feeds_to_update = config.get("feeds", [])
        if args.feed:
            feeds_to_update = [f for f in feeds_to_update if f.get("name") == args.feed]
            if not feeds_to_update:
                logger.error(f"Feed '{args.feed}' not found in configuration.")
                sys.exit(1)

        update_count = 0
        for feed in feeds_to_update:
            if not feed.get("enabled", False):
                logger.info(f"Skipping disabled feed: {feed.get('name')}")
                continue

            # TODO: Implement check against update_interval and --force flag

            indicators = fetch_feed_data(feed)
            if indicators is not None:
                update_local_cache(cache_dir, feed.get("name"), indicators, retention_days)
                update_count += 1
            else:
                 logger.error(f"Failed to fetch or process data for feed: {feed.get('name')}")

        logger.info(f"Update command finished. Updated {update_count} feed(s).")

    elif args.command == "check":
        findings = check_indicator(cache_dir, args.indicator, args.type)
        if args.output == "json":
            print(json.dumps(findings, indent=2))
        else: # text output
            if findings:
                print(f"Indicator '{args.indicator}' found in the following feeds:")
                for finding in findings:
                    print(f"  - Feed: {finding['feed']}")
                    print(f"    Match Type: {finding['match_type']}")
                    if finding['match_type'] == 'structured':
                        print(f"    Matched Indicator: {finding['matched_indicator']}")
                    print(f"    First Seen: {finding['details'].get('first_seen', 'N/A')}")
                    print(f"    Last Seen: {finding['details'].get('last_seen', 'N/A')}")
            else:
                print(f"Indicator '{args.indicator}' not found.")

        # Generate HTML report if requested
        if args.report and findings:
            report_path = generate_html_report(findings, args.report_file)
            if report_path:
                print(f"HTML report generated: {report_path}")

    elif args.command == "list":
        if args.feeds:
            print("Configured Threat Intelligence Feeds:")
            for feed in config.get("feeds", []):
                print(f"  - Name: {feed.get('name')}")
                print(f"    URL: {feed.get('url')}")
                print(f"    Type: {feed.get('type')}")
                print(f"    Enabled: {feed.get('enabled', False)}")
                print(f"    Update Interval: {feed.get('update_interval', 'N/A')} seconds")
        elif args.indicators:
            cache_file = cache_dir / f"{args.indicators}.json"
            if not cache_file.is_file():
                logger.error(f"Cache file for feed '{args.indicators}' not found at {cache_file}")
                sys.exit(1)
            try:
                with open(cache_file, 'r') as f:
                    cache_data = json.load(f)
                print(f"Cached indicators for feed '{args.indicators}' (Last Update: {cache_data.get('metadata', {}).get('last_update')}):")
                count = 0
                for indicator, details in cache_data.get("indicators", {}).items():
                    print(f"  - {indicator} (Last Seen: {details.get('last_seen')})")
                    count += 1
                    if count >= 100: # Limit output for brevity
                         print(f"  ... (truncated, total {cache_data.get('metadata', {}).get('indicator_count')})")
                         break
                if count == 0:
                     print("  No indicators found in cache for this feed.")
            except (json.JSONDecodeError, IOError) as e:
                logger.error(f"Failed to read or parse cache file {cache_file}: {e}")
                sys.exit(1)
        else:
            logger.error("Specify either --feeds or --indicators FEED_NAME for list command.")
            parser.print_help()
            sys.exit(1)

    elif args.command == "report":
        indicators_file = args.indicators_file
        if not indicators_file.is_file():
            logger.error(f"Indicators file not found: {indicators_file}")
            sys.exit(1)

        # Read indicators from file
        indicators = []
        try:
            with open(indicators_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        indicators.append(line)

            if not indicators:
                logger.error("No valid indicators found in file")
                sys.exit(1)

            logger.info(f"Loaded {len(indicators)} indicators from {indicators_file}")

            # Process all indicators
            all_findings = []
            for indicator in indicators:
                logger.info(f"Checking indicator: {indicator}")
                findings = check_indicator(cache_dir, indicator, None)
                all_findings.extend(findings)

            if all_findings:
                logger.info(f"Found {len(all_findings)} matches across {len(indicators)} indicators")
                report_path = generate_html_report(all_findings, args.output)
                if report_path:
                    print(f"HTML report generated: {report_path}")
            else:
                logger.warning("No matches found for any indicators")
                print("No matches found for any indicators.")

        except Exception as e:
            logger.error(f"Error processing indicators: {e}")
            sys.exit(1)

    end_time = time.time()
    logger.info(f"Command '{args.command}' completed in {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    main()
