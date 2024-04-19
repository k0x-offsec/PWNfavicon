# PWNfavicon for WAF Bypass

![banner](https://github.com/offensive-security-pwncat/PWNfavicon/blob/main/banner.png)

## Overview

The PWNfavicon is a Python-based reconnaissance tool designed to identify websites that potentially mirror the content of a specified URL, aiding in Web Application Firewall (WAF) bypass techniques. It operates by leveraging the analysis of favicon hashes, small icons associated with websites that are often overlooked in security assessments.

## Features

- **Favicon Hash Comparison** 🔍: Analyzes the hash values of favicons across different websites.
- **Multi-threaded Crawling** 🕷️: Utilizes multi-threading for concurrent fetching and analysis of multiple URLs.
- **Timeout Handling** ⏱️: Customizable timeout settings prevent delays while waiting for responses from unresponsive servers.
- **Verbose Logging** 📝: Detailed logging capabilities for monitoring the crawling process and diagnosing issues.
- **Input Parsing** 📥: Supports input in the form of CIDR ranges, domain names, or a base URL.
- **Result Reporting** 📊: Identifies matching URLs indicating potential content similarity to the base URL.

## Use Cases

- **WAF Bypass** 🛡️: Helps evade detection or filtering mechanisms implemented by WAFs by identifying websites with similar content.
- **Red Team Engagements** 🚩: Discovers additional entry points or shadow IT assets during red team operations.
- **Vulnerability Research** 🔍: Analyzes the prevalence of specific web assets across different domains to identify common vulnerabilities.

## Usage

```bash
python PWNfavicon.py -u <base_url> -t <num_threads> -d <domain> -c <cidr>
```

## Options

- `-u, --url`: Specify the base URL directly.
- `-t, --threads`: Specify the number of threads to use (default is 10).
- `-h, --help`: Show the help message and exit.

Additional options:

- `-p, --ports`: Specify ports to check separated by commas.
- `--timeout`: Specify timeout for HTTP requests in seconds (default is 10).
- `-v, --verbose`: Enable verbose mode for detailed logging.
- `-c, --cidr`: Specify CIDR ranges separated by commas.
- `-cf, --cidr-file`: Specify a file containing CIDR ranges.
- `-d, --domains`: Specify domains separated by commas.
- `-df, --domains-file`: Specify a file containing domains.

These options provide flexibility in customizing the crawling behavior according to specific requirements and scenarios.

## Requirements

- Python 3.x
- mmh3
- requests
- beautifulsoup4
- colorama
- tqdm

## Installation Guide

### 1. Clone the Repository

Clone the Favicon Crawler repository from GitHub to your local machine:

```bash
git clone https://github.com/your_username/favicon-crawler.git
```

### 2. Navigate to the Project Directory

Change into the directory containing the cloned repository:

```bash
cd PWNfavicon
```

### 3. Install Dependencies

Ensure you have Python 3.x installed on your system. Then, install the required Python packages using pip:

```bash
pip install -r requirements.txt
```

This will install the necessary dependencies such as `mmh3`, `requests`, `beautifulsoup4`, `colorama`, and `tqdm`.

### 4. Usage

Once the dependencies are installed, you can run the Favicon Crawler using the following command:

```bash
python PWNfavicon.py -u <base_url> -c <cidr>
```

Replace `<base_url>` with the target URL you want to analyze and `<cidr>` with the desired network change to scan.

### 5. Explore Options

Explore additional command-line options available for customization using the `--help` flag:

```bash
python PWNfavicon.py --help
```

This will display a list of available options such as specifying ports, setting timeouts, enabling verbose mode, and providing input via CIDR ranges or domain lists.

## Example Usage

```bash
python PWNfavicon.py -u "https://example.com" -c "199.98.50.0/24"
```

This command will crawl the target URL `https://example.com` and find if there is some page on the network `199.98.50.0/24`.

### Note

- Ensure that you have proper permissions and network access to crawl the target URLs.
- It is recommended to use this tool responsibly and ethically, respecting the terms of service and legal regulations governing web scraping and reconnaissance activities.
- Refer to the [LICENSE](LICENSE) file for details on the project's licensing terms.
- For any issues or feedback, please open an [issue](https://github.com/your_username/favicon-crawler/issues) on the GitHub repository.

# Planned Features

1. **Enhanced Logging** 📈
   - **Description:** Improve logging functionality to provide more detailed information about the crawling process, including progress updates, error messages, and status reports.
   - **Status:** Planned

2. **Integration with External Tools** 🛠️
   - **Description:** Integrate the tool with external vulnerability scanners or web application security testing frameworks to automate the identification of potential vulnerabilities based on favicon analysis.
   - **Status:** Planned

3. **Customizable Output Formats** 📄
   - **Description:** Add support for customizable output formats, allowing users to specify the format and structure of the output reports generated by the tool.
   - **Status:** Planned

# Proposed Improvements

1. **Error Handling Refinement** 🛠️
   - **Description:** Refine error handling mechanisms to gracefully handle a wider range of network errors, HTTP status codes, and unexpected exceptions, providing more informative error messages and recovery options.
   - **Status:** Proposed

2. **Performance Optimization** ⚡
   - **Description:** Optimize the tool's performance by implementing asynchronous processing or connection pooling techniques to improve concurrency and reduce processing time, especially when crawling large numbers of URLs.
   - **Status:** Proposed

3. **User Interface Enhancement** 🖥️
   - **Description:** Enhance the user interface by adding interactive features, such as progress bars, interactive prompts, or real-time updates, to improve user experience and feedback during the crawling process.
   - **Status:** Proposed

4. **Input Validation and Sanitization** 🔒
   - **Description:** Implement robust input validation and sanitization mechanisms to prevent common security vulnerabilities, such as injection attacks or directory traversal exploits, by ensuring that user-provided input is safe and properly sanitized before processing.
   - **Status:** Proposed

5. **Dockerization** 🐳
   - **Description:** Dockerize the application to simplify deployment and ensure consistent runtime environments across different platforms, making it easier for users to install and run the tool in various environments.
   - **Status:** Proposed

6. **Configuration File Support** ⚙️
   - **Description:** Add support for configuration files to allow users to specify custom settings, such as timeout values, port lists, or logging levels, without modifying command-line arguments, enhancing flexibility and customization options.
   - **Status:** Proposed

7. **Integration with Continuous Integration (CI) Pipelines** 🔄
   - **Description:** Integrate the project with popular CI/CD platforms like Travis CI or GitHub Actions to automate testing, code quality checks, and deployment processes, ensuring code stability and reliability across different environments.
   - **Status:** Proposed

8. **Unit Testing Suite** ✔️
   - **Description:** Develop a comprehensive unit testing suite to validate the functionality and behavior of individual components and modules, ensuring code correctness and preventing regressions during development and maintenance.
   - **Status:** Proposed

## How to Contribute

If you're interested in contributing to the project or have any feedback on these planned features and proposed improvements, please feel free to:

1. Select a feature or improvement from the list above that you'd like to work on or provide feedback on.
2. Fork the project repository to your GitHub account.
3. Create a new branch for your work based on the `master` branch.
4. Implement the feature or improvement in your branch.
5. Submit a pull request to the main repository's `master` branch.
6. Collaborate with project maintainers and other contributors to review and iterate on your changes until they're ready to be merged.

Your contributions and feedback are highly appreciated and will help make the project better for everyone!

## License

This project is licensed under the MIT License - see the LICENSE file for details.
