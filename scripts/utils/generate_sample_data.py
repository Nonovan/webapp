import random
import json
import os

def generate_sample_data(num_records=100, output_file="sample_data.json"):
    """
    Generate sample data and save it to a JSON file.

    Args:
        num_records (int): Number of records to generate.
        output_file (str): Path to the output JSON file.
    """
    sample_data = []

    for i in range(num_records):
        record = {
            "id": i + 1,
            "name": f"SampleName{i + 1}",
            "age": random.randint(18, 65),
            "email": f"user{i + 1}@example.com",
            "is_active": random.choice([True, False]),
        }
        sample_data.append(record)

    # Ensure the output directory exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    # Write the data to a JSON file
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(sample_data, f, indent=4)

    print(f"Sample data generated and saved to {output_file}")


if __name__ == "__main__":
    generate_sample_data()
