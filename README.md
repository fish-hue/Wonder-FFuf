# Wonder-FFUF Python Integration Script

This Python script is a user-friendly integration for the **FFUF** (Fuzz Faster U Fool) web application fuzzer. It allows you to perform directory brute-forcing and other penetration testing tasks with ease. You can configure various parameters such as the target URL, wordlists, HTTP methods, and output file names.

## Features

- Set the target URL for fuzzing.
- Specify a wordlist for enumeration.
- Choose HTTP methods (GET, POST, etc.).
- Add custom headers and cookies.
- Specify additional FFUF options.
- Set a timeout for requests.
- Log outputs and save results in JSON format.
- Generate a summary report of the fuzzing process.

## Prerequisites

- Python 3.x
- FFUF installed and accessible in your system's PATH.

### Installation

To install FFUF rin the following command:

   ```bash
   git clone https://github.com/fish-hue/Wonder-FFuf.git
   ```

### Getting Started

1. Clone this repository or download the script.
2. Run the script using Python:

   ```bash
   python wonderffuf.py
   ```

3. Follow the prompts to configure your fuzzing session.

## Usage

Once the script is running, you will see a menu interface with the following options:

1. **Set Target URL**: Enter the URL to target (must start with `http://` or `https://`).
2. **Set Wordlist**: Provide the path to a wordlist file.
3. **Set HTTP Method**: Choose the HTTP method to use for requests (default is GET).
4. **Set Additional Options**: Input any extra FFUF command-line options.
5. **Set Custom Headers**: Specify any custom headers separated by commas.
6. **Set Cookies**: Enter cookies as key=value pairs separated by commas.
7. **Set Timeout**: Define the timeout for each request (default is 10 seconds).
8. **Set Output File Names**: Customize the filenames for results, logs, and reports.
9. **Start Fuzzing**: Execute the configured fuzzing session.
10. **Exit**: Exit the script.

After completing the fuzzing session, results are saved in the specified output formats, and a summary report is generated.

## Output

The script will create and save the following files based on user input:

- **Results File**: In JSON format containing detailed output of each fuzzing attempt.
- **Log File**: Logs all outputs with timestamps for tracking.
- **Summary Report**: A text file summarizing the successful, error, and total requests.


