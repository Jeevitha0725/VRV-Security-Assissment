import pandas as pd
from collections import Counter

try:
    # Step 1: Reading Log Data
    with open("sample.log", "r") as log_file:
        log_entries = log_file.read().strip().split("\n")

    # Step 2: Parse Log Data and Collect Details using List Comprehension
    parsed_logs = []
    ip_addresses = []
    endpoints = []
    failed_logins = []

    for entry in log_entries:
        parts = entry.split(" ")
        ip_address = parts[0]
        timestamp = parts[3].strip("[").replace(":", " ", 1)
        method = parts[5].strip('"')
        endpoint = parts[6]
        protocol = parts[7].strip('"')
        status_code = parts[8]
        response_size = parts[9]

        # Store relevant data
        parsed_logs.append([ip_address, timestamp, method, endpoint, protocol, status_code, response_size])
        ip_addresses.append(ip_address)
        endpoints.append(endpoint)

        # Track failed login attempts
        if method == "POST" and status_code == "401":
            failed_logins.append(ip_address)

    # Step 3: Convert to DataFrame for efficient processing
    logs_df = pd.DataFrame(parsed_logs, columns=["IP Address", "Timestamp", "Method", "Endpoint", "Protocol", "Status Code", "Response Size"])

    # Step 4: Use Pandas built-in methods to process counts
    ip_count_df = pd.DataFrame(Counter(ip_addresses).items(), columns=["IP Address", "Request Count"]).sort_values(by="Request Count", ascending=False)
    endpoint_count_df = pd.DataFrame(Counter(endpoints).items(), columns=["Endpoint", "Access Count"]).sort_values(by="Access Count", ascending=False)
    failed_login_count_df = pd.DataFrame(Counter(failed_logins).items(), columns=["IP Address", "Failed Login Count"]).sort_values(by="Failed Login Count", ascending=False)

    # Step 5: Capture Most Accessed Endpoint
    most_accessed_endpoint = endpoint_count_df.iloc[0]  # Top accessed endpoint
    most_accessed_endpoint_result = f"{most_accessed_endpoint['Endpoint']} (Accessed {most_accessed_endpoint['Access Count']} times)"

    # Step 6: Writing Results to CSV
    csv_file = "log_analysis_results.csv"

    with open(csv_file, mode="w", newline="", encoding="utf-8") as file:
        # Write Requests per IP
        ip_count_df.to_csv(file, index=False, header=["IP Address", "Request Count"])
        file.write("\n")

        # Write Most Accessed Endpoint
        file.write(f"Most Frequently Accessed Endpoint:\n{most_accessed_endpoint_result}\n")
        file.write("\n")

        # Write Suspicious Activity (Failed Logins)
        failed_login_count_df.to_csv(file, index=False, header=["IP Address", "Failed Login Count"])

    print(f"Analysis results have been successfully written to {csv_file}")

except Exception as e:
    print(f"500 Internal Server Error: {str(e)}")
