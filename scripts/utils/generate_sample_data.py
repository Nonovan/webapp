#!/usr/bin/env python3
"""
Sample Data Generator for Cloud Infrastructure Platform

This script generates realistic sample data for testing and development purposes.
It creates records with various data types and save them to JSON, CSV, or YAML formats.

Usage:
    python generate_sample_data.py [--num-records NUM] [--output FILE] [--format FORMAT]
"""

import random
import json
import csv
import os
import sys
import argparse
import logging
import datetime
import uuid
from typing import Dict, List, Any, Optional, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("sample-data-generator")

# Define constants
DEFAULT_NUM_RECORDS = 100
DEFAULT_OUTPUT_FILE = "sample_data.json"
VALID_FORMATS = ["json", "csv", "yaml"]
DEFAULT_FORMAT = "json"

# Sample data configuration
FIRST_NAMES = ["James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael", "Linda", "William",
               "Elizabeth", "David", "Barbara", "Richard", "Susan", "Joseph", "Jessica", "Thomas", "Sarah",
               "Charles", "Karen", "Christopher", "Nancy", "Daniel", "Lisa", "Matthew", "Margaret"]

LAST_NAMES = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez",
              "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor",
              "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez"]

DOMAINS = ["example.com", "test.org", "sample.net", "demo.io", "mock.co"]

DEPARTMENTS = ["Engineering", "Marketing", "Sales", "Finance", "HR", "Operations", "Support", "Research",
               "Legal", "Product"]

STATUSES = ["active", "inactive", "pending", "suspended", "archived"]


def generate_sample_data(num_records: int = DEFAULT_NUM_RECORDS,
                         output_file: str = DEFAULT_OUTPUT_FILE,
                         output_format: str = DEFAULT_FORMAT) -> List[Dict[str, Any]]:
    """
    Generate sample data and save it to a file in the specified format.

    Args:
        num_records: Number of records to generate
        output_file: Path to the output file
        output_format: Format of the output file (json, csv, or yaml)

    Returns:
        List of generated records as dictionaries

    Raises:
        ValueError: If an invalid output format is specified
    """
    logger.info(f"Generating {num_records} sample records in {output_format} format")

    # Validate output format
    if output_format not in VALID_FORMATS:
        raise ValueError(f"Invalid output format: {output_format}. Valid formats are: {', '.join(VALID_FORMATS)}")

    # Generate sample records
    sample_data = []
    current_date = datetime.date.today()

    for i in range(num_records):
        # Generate a random date within the last 5 years
        days_ago = random.randint(0, 5 * 365)
        random_date = current_date - datetime.timedelta(days=days_ago)

        # Generate a realistic name
        first_name = random.choice(FIRST_NAMES)
        last_name = random.choice(LAST_NAMES)
        full_name = f"{first_name} {last_name}"

        # Generate a realistic email
        email = f"{first_name.lower()}.{last_name.lower()}@{random.choice(DOMAINS)}"

        # Build the record with various data types
        record = {
            "id": i + 1,
            "uuid": str(uuid.uuid4()),
            "name": full_name,
            "email": email,
            "age": random.randint(18, 65),
            "score": round(random.uniform(0, 100), 2),
            "is_active": random.choice([True, False]),
            "department": random.choice(DEPARTMENTS),
            "status": random.choice(STATUSES),
            "created_at": random_date.isoformat(),
            "updated_at": current_date.isoformat(),
            "tags": random.sample(["web", "mobile", "api", "database", "security", "cloud", "network"],
                                random.randint(1, 3)),
            "metadata": {
                "login_count": random.randint(1, 500),
                "last_login_ip": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
                "preferences": {
                    "notifications": random.choice([True, False]),
                    "theme": random.choice(["light", "dark", "system"]),
                    "language": random.choice(["en", "es", "fr", "de", "zh"])
                }
            }
        }
        sample_data.append(record)

    # Ensure the output directory exists
    os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)

    # Write the data to the appropriate file format
    save_data(sample_data, output_file, output_format)

    logger.info(f"Sample data generated and saved to {output_file}")
    return sample_data


def save_data(data: List[Dict[str, Any]], output_file: str, output_format: str) -> None:
    """
    Save data to a file in the specified format.

    Args:
        data: The data to save
        output_file: Path to the output file
        output_format: Format of the output file (json, csv, or yaml)

    Raises:
        ImportError: If yaml module is not installed when yaml format is specified
    """
    if output_format == "json":
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    elif output_format == "csv":
        # If we have data, get the keys from the first record
        if data:
            # Extract non-nested keys from the first record
            fieldnames = [key for key, value in data[0].items()
                        if not isinstance(value, (dict, list))]

            with open(output_file, "w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for record in data:
                    # Only write non-nested fields
                    row = {k: v for k, v in record.items() if k in fieldnames}
                    writer.writerow(row)

    elif output_format == "yaml":
        try:
            import yaml
        except ImportError:
            logger.error("PyYAML is not installed. Please install it with 'pip install PyYAML'")
            raise ImportError("PyYAML is required for YAML output. Install with: pip install PyYAML")

        with open(output_file, "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, default_flow_style=False)


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate sample data for testing and development",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "--num-records", "-n",
        type=int,
        default=DEFAULT_NUM_RECORDS,
        help=f"Number of records to generate (default: {DEFAULT_NUM_RECORDS})"
    )

    parser.add_argument(
        "--output", "-o",
        type=str,
        default=DEFAULT_OUTPUT_FILE,
        help=f"Path to the output file (default: {DEFAULT_OUTPUT_FILE})"
    )

    parser.add_argument(
        "--format", "-f",
        type=str,
        choices=VALID_FORMATS,
        default=DEFAULT_FORMAT,
        help=f"Format of the output file (default: {DEFAULT_FORMAT})"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )

    return parser.parse_args()


def main() -> int:
    """Main entry point for the script."""
    args = parse_args()

    # Configure logging level based on verbose flag
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    try:
        # Extract file extension from output path for format detection
        if args.output and "." in args.output and args.format == DEFAULT_FORMAT:
            ext = args.output.split(".")[-1].lower()
            if ext in VALID_FORMATS:
                logger.debug(f"Detected format from file extension: {ext}")
                output_format = ext
            else:
                output_format = args.format
        else:
            output_format = args.format

        # Generate the sample data
        generate_sample_data(
            num_records=args.num_records,
            output_file=args.output,
            output_format=output_format
        )
        return 0

    except ValueError as e:
        logger.error(f"Value error: {e}")
        return 1
    except ImportError as e:
        logger.error(f"Import error: {e}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
