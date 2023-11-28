import csv,json,datetime
import json

# Your list of dictionaries
data = []

# Function to handle complex data types
def format_complex_data(value):
    if isinstance(value, list):
        # Convert list items to string and join with ';'
        return '; '.join(str(item) for item in value)
    elif isinstance(value, dict):
        # Convert dict to a JSON string
        return json.dumps(value)
    else:
        return value

#current_datetime = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
# Path to your CSV file
#csv_file_path = f'rule_analysis-{current_datetime}.csv'
def save_file(data):
    current_datetime = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    csv_file_path = f'rule_analysis-{current_datetime}.csv'
    with open(csv_file_path, mode='w', newline='') as file:
        # Creating a CSV writer object
        csv_writer = csv.DictWriter(file, fieldnames=data[0].keys())

        # Writing the headers
        csv_writer.writeheader()

        # Writing data rows
        for row in data:
            # Formatting complex data types before writing
            formatted_row = {k: format_complex_data(v) for k, v in row.items()}
            csv_writer.writerow(formatted_row)
