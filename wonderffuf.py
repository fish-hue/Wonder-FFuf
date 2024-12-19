import subprocess
import shlex
from tqdm import tqdm
import os
import time
import json
import shutil
import re

def parse_ffuf_output(output):
    """Process FFUF output to identify success, errors, or other relevant status codes."""
    status_codes = {
        '200': 'OK',
        '201': 'Created',
        '204': 'No Content',
        '301': 'Moved Permanently',
        '302': 'Found',
        '403': 'Forbidden',
        '404': 'Not Found',
        '500': 'Internal Server Error',
        '502': 'Bad Gateway',
        '503': 'Service Unavailable',
    }
    
    match = re.search(r'HTTP/[\d.]+\s+(\d+)', output)
    if match:
        status_code = match.group(1)
        return status_codes.get(status_code, 'unknown')

    if re.search(r'\bFound\b', output):
        return "success"
    elif re.search(r'\bError\b|\bfailure\b', output, re.IGNORECASE):
        return "error"
    
    return "unknown"

def display_menu():
    print("\n----- FFUF Fuzzing Tool -----")
    print("1. Set Target URL")
    print("2. Set Wordlist")
    print("3. Set HTTP Method (default: GET)")
    print("4. Set Additional Options")
    print("5. Set Custom Headers")
    print("6. Set Cookies")
    print("7. Set Timeout (default: 10 seconds)")
    print("8. Set Output File Names")
    print("9. Start Fuzzing")
    print("10. Exit")

def build_ffuf_command(target_url, wordlist, http_method, additional_options, cookies, headers):
    cookies_option = f'-H "Cookie: {cookies}"' if cookies else ''
    headers_option = ' '.join([f'-H "{header.strip()}"' for header in headers.split(',') if header.strip()])
    return f"ffuf -u {target_url}/FUZZ -w {wordlist} -X {http_method} {additional_options} {cookies_option} {headers_option}"

def validate_command(ffuf_command):
    """Validate the FFUF command syntax before execution."""
    try:
        subprocess.check_call(shlex.split(ffuf_command), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        print("Error: The FFUF command is invalid or contains errors.")
        return False

def save_results_to_file(results, file_path):
    try:
        with open(file_path, "w") as file:
            json.dump(results, file, indent=4)
        print(f"Results saved to {file_path}")
    except IOError as e:
        print(f"Error saving results to file: {e}")

def log_ffuf_output(output, log_file):
    try:
        with open(log_file, "a") as file:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            file.write(f"[{timestamp}] {output}\n")
    except IOError as e:
        print(f"Error writing to log file: {e}")

def process_ffuf_output(output_decoded, results):
    """Process FFUF output line and append structured result."""
    status = parse_ffuf_output(output_decoded)

    result_entry = {
        "output": output_decoded,
        "status": status,
        "details": {}
    }

    if "HTTP" in output_decoded:
        parts = output_decoded.split()
        if len(parts) > 1 and parts[1].isdigit():
            result_entry["details"]["status_code"] = parts[1]
            result_entry["details"]["status_message"] = " ".join(parts[2:])
    
    results.append(result_entry)
    return status

def generate_summary_report(results, report_file):
    summary = {}
    detailed_summary = []
    for result in results:
        status = result.get("status", "unknown")
        summary[status] = summary.get(status, 0) + 1
        if status == "success":
            detailed_summary.append(result["output"])

    try:
        with open(report_file, "w") as file:
            file.write("\n----- Post-Processing Report -----\n")
            for status, count in summary.items():
                file.write(f"{status.capitalize()}: {count}\n")

            if detailed_summary:
                file.write("\n----- Successful Requests -----\n")
                file.write("\n".join(detailed_summary))
        print(f"Summary report saved to {report_file}")
    except IOError as e:
        print(f"Error saving summary report: {e}")

def check_dependencies():
    """Check if necessary dependencies are installed."""
    if not shutil.which("ffuf"):
        print("Error: FFUF is not installed or not in PATH.")
        return False
    return True

def start_fuzzing(target_url, wordlist, http_method, additional_options, cookies, headers, timeout, result_file, log_file, report_file):
    ffuf_command = build_ffuf_command(target_url, wordlist, http_method, additional_options, cookies, headers)

    if not validate_command(ffuf_command):
        return

    print(f"Generated FFUF Command: {ffuf_command}")
    confirm = input("Do you want to proceed with this command? (y/n): ").strip().lower()
    if confirm != 'y':
        print("Fuzzing canceled by the user.")
        return

    total_entries = sum(1 for _ in open(wordlist))
    with tqdm(total=total_entries, desc="Processing", unit="entry") as pbar:
        try:
            process = subprocess.Popen(shlex.split(ffuf_command), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            requests_made, successful_responses, error_count = 0, 0, 0
            start_time = time.time()
            results = []

            while True:
                output = process.stdout.readline()
                if output == b'' and process.poll() is not None:
                    break
                if output:
                    output_decoded = output.decode(errors="replace").strip()
                    log_ffuf_output(output_decoded, log_file)
                    print(output_decoded)

                    # Process and store result
                    status = process_ffuf_output(output_decoded, results)

                    # Update response counts based on the status
                    requests_made += 1
                    if status == "success":
                        successful_responses += 1
                    elif status == "error":
                        error_count += 1
                        
                    pbar.update(1)

                # Check for timeout
                if time.time() - start_time > timeout:
                    print(f"\nTimeout exceeded after {timeout} seconds. Stopping the process.")
                    process.terminate()
                    break

            print("\n----- Results Summary -----")
            print(f"Total Requests Made: {requests_made}")
            print(f"Total Successful Responses: {successful_responses}")
            print(f"Total Errors: {error_count}")

            save_results_to_file(results, result_file)
            generate_summary_report(results, report_file)

        except Exception as e:
            print(f"An unexpected error occurred: {e}")

def main():
    print("Welcome to the FFUF Python Integration Script!")

    if not check_dependencies():
        return

    target_url = None
    wordlist = None
    http_method = "GET"
    additional_options = ""
    headers = ""
    cookies = ""
    timeout = 10  # Default timeout
    result_file = "ffuf_results.json"
    log_file = "ffuf_output.log"
    report_file = "ffuf_summary_report.txt"

    while True:
        display_menu()
        choice = input("Select an option (1-10): ").strip()

        if choice == '1':
            target_url = input("Enter the target URL (e.g., http://example.com): ").strip()
            while not target_url.startswith(("http://", "https://")):
                print("Invalid URL. Please ensure it starts with http:// or https://.")
                target_url = input("Enter the target URL (e.g., http://example.com): ").strip()

        elif choice == '2':
            wordlist = input("Enter the wordlist path (e.g., /path/to/wordlist.txt): ").strip()
            while not os.path.isfile(wordlist):
                print("Wordlist file does not exist or cannot be accessed.")
                wordlist = input("Enter the wordlist path (e.g., /path/to/wordlist.txt): ").strip()

        elif choice == '3':
            http_method = input("Enter the HTTP method (default is GET, press Enter to skip): ").strip() or "GET"
            if http_method not in ["GET", "POST", "PUT", "DELETE", "HEAD"]:
                print("Invalid HTTP method. Defaulting to GET.")
                http_method = "GET"

        elif choice == '4':
            additional_options = input("Enter any additional FFUF options (press Enter to skip): ").strip()

        elif choice == '5':
            headers = input("Enter custom headers (comma-separated key=value pairs, press Enter to skip): ").strip()

        elif choice == '6':
            cookies = input("Enter cookies (comma-separated key=value pairs, press Enter to skip): ").strip()

        elif choice == '7':
            timeout_input = input("Enter the timeout in seconds for each request (default is 10s, press Enter to skip): ").strip()
            timeout = int(timeout_input) if timeout_input.isdigit() else 10

        elif choice == '8':
            result_file = input("Enter the result file path (default is 'ffuf_results.json', press Enter to use default): ").strip() or "ffuf_results.json"
            log_file = input("Enter the log file path (default is 'ffuf_output.log', press Enter to use default): ").strip() or "ffuf_output.log"
            report_file = input("Enter the report file path (default is 'ffuf_summary_report.txt', press Enter to use default): ").strip() or "ffuf_summary_report.txt"

        elif choice == '9':
            if not target_url or not wordlist:
                print("Target URL and wordlist are required before starting fuzzing.")
                continue

            start_fuzzing(target_url, wordlist, http_method, additional_options, cookies, headers, timeout, result_file, log_file, report_file)

        elif choice == '10':
            confirm_exit = input("Are you sure you want to exit? (y/n): ").strip().lower()
            if confirm_exit == 'y':
                print("Exiting the script.")
                break

        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()
