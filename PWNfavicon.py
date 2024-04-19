import mmh3
import argparse
import threading
import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style
from urllib.parse import urljoin
import ipaddress
from tqdm import tqdm


requests.packages.urllib3.disable_warnings()  # Disable warnings from urllib3 package
verbose = False  # Initialize verbose flag as a global variable
matching_urls = []  # Initialize an empty list to store matching URLs


def calculate_hash(data):
    """
    Calculate the MurmurHash3 hash value of the input data.

    Parameters:
    - data: The input data to be hashed.

    Returns:
    - The MurmurHash3 hash value of the input data, or None if an error occurs.

    Raises:
    - None.

    Notes:
    - This function uses the MurmurHash3 algorithm to compute the hash value of the input data.
    - If an error occurs during the hash calculation, the function prints an error message if the verbose flag is set and returns None.
    """
    try:
        return mmh3.hash(data)  # Calculate the MurmurHash3 hash value
    except Exception as e:
        if verbose:
            print(f"{Fore.RED}An error occurred while calculating hash: {e}{Style.RESET_ALL}")  # Print error message if verbose is True
        return None  # Return None if an error occurs


def calculate_favicon_hash(favicon_url, timeout):
    """
    Download the favicon from the given URL, calculate its hash value using MurmurHash3 algorithm, and return the hash value.

    Parameters:
    - favicon_url: The URL from which to download the favicon.
    - timeout: The timeout for the HTTP request.

    Returns:
    - The MurmurHash3 hash value of the favicon content, or None if an error occurs.

    Raises:
    - None.

    Notes:
    - This function downloads the favicon from the specified URL using an HTTP GET request.
    - It then calculates the hash value of the favicon content using the calculate_hash function.
    - If verbose is True, it prints messages indicating the progress of the download and any errors encountered.
    - If an error occurs during the download or hash calculation, it returns None.
    """
    try:
        if verbose:
            print(f"{Fore.YELLOW}Downloading favicon from {favicon_url}{Style.RESET_ALL}")  # Print message indicating favicon download if verbose is True
        response = requests.get(favicon_url, timeout=timeout, allow_redirects=True, verify=False)  # Make HTTP GET request to download the favicon
        response.raise_for_status()  # Raise an HTTPError if the response status code indicates an error
        
        favicon_content = response.content  # Get the content of the favicon
        hash_value = calculate_hash(favicon_content)  # Calculate the hash value of the favicon content using calculate_hash function
        
        if verbose:
            print(f"{Fore.YELLOW}Hash of favicon from {favicon_url}: {hash_value}{Style.RESET_ALL}")  # Print message indicating favicon hash value if verbose is True
        return hash_value  # Return the hash value of the favicon content
    except requests.RequestException as e:
        if verbose:
            print(f"{Fore.RED}An error occurred while fetching favicon from {favicon_url}: {e}{Style.RESET_ALL}")  # Print error message if an HTTP request error occurs and verbose is True
    except Exception as e:
        if verbose:
            print(f"{Fore.RED}An unexpected error occurred while fetching favicon from {favicon_url}: {e}{Style.RESET_ALL}")  # Print error message if an unexpected error occurs and verbose is True
    
    return None  # Return None if an error occurs during the download or hash calculation


def extract_favicon_url(html_content, base_url):
    """
    Extract the URL of the favicon from the given HTML content and base URL.

    Parameters:
    - html_content: The HTML content from which to extract the favicon URL.
    - base_url: The base URL used for resolving relative URLs.

    Returns:
    - The URL of the favicon if found, or None if not found.

    Raises:
    - None.

    Notes:
    - This function parses the HTML content using BeautifulSoup library.
    - It searches for a 'link' tag with 'rel' attribute set to 'icon', which typically contains the favicon URL.
    - If such a tag is found, it extracts the 'href' attribute value, resolves it against the base URL, and returns the absolute URL of the favicon.
    - If no favicon link is found, it returns None.
    """
    soup = BeautifulSoup(html_content, 'html.parser')  # Parse the HTML content using BeautifulSoup
    favicon_link = soup.find('link', rel='icon')  # Find the favicon link tag
    if favicon_link:
        favicon_url = favicon_link.get('href')  # Get the value of the 'href' attribute
        return urljoin(base_url, favicon_url)  # Resolve the URL against the base URL and return the absolute URL
    else:
        return None  # Return None if no favicon link is found


def crawl_targets(targets, base_url, ports, timeout, num_threads):
    """
    Crawl the specified targets to check for matching favicons with the base favicon of the provided base URL.

    Parameters:
    - targets: A list of target URLs or IP ranges to crawl.
    - base_url: The base URL from which to fetch the base favicon.
    - ports: A list of port numbers to check for each target.
    - timeout: The timeout duration for HTTP requests.
    - num_threads: The number of threads to use for concurrent crawling.

    Returns:
    - None.

    Raises:
    - None.

    Notes:
    - This function fetches the base favicon from the provided base URL and calculates its hash value.
    - It then crawls through the specified targets, checking each URL or IP address with the specified ports for matching favicons.
    - It uses multithreading to crawl targets concurrently, with each thread checking a different URL or IP address.
    - If verbose mode is enabled, it prints progress messages indicating the crawling process.
    - If any errors occur during the crawling process, they are caught and printed if verbose mode is enabled.
    """
    try:
        # Fetch base favicon
        if verbose:
            print(f"{Fore.YELLOW}Fetching base favicon for {base_url}{Style.RESET_ALL}")  # Print message indicating base favicon fetching if verbose is True
        base_favicon_hash = fetch_base_favicon(base_url, timeout)  # Fetch base favicon and calculate its hash value
        if not base_favicon_hash:
            if verbose:
                print(f"{Fore.RED}Base favicon not found or could not be fetched for {base_url}. Skipping.{Style.RESET_ALL}")  # Print message if base favicon not found or could not be fetched
            return
        if verbose:
            print(f"{Fore.YELLOW}Base favicon hash fetched for {base_url}: {base_favicon_hash}{Style.RESET_ALL}")  # Print message indicating base favicon hash value if verbose is True
        
        threads = []  # Initialize threads list
        checked_urls = set()  # Initialize checked_urls set
        encountered_503 = set()  # Initialize encountered_503 set
        
        # Wrap the loop with tqdm for progress tracking
        for target in tqdm(targets, desc="Crawling targets", unit="target"):
            # Print target message if verbose mode is enabled
            if verbose:
                print(f"{Fore.YELLOW}Crawling target: {target}{Style.RESET_ALL}")

            # Check if target is an IP range
            if '/' in target:
                network = ipaddress.ip_network(target)
                for ip in network.hosts():
                    for port in ports:
                        # Construct URL
                        if port == 443 or port == 8443:
                            url = f"https://{str(ip)}:{port}"
                        else:
                            url = f"http://{str(ip)}:{port}"
                        
                        # Check if URL has been checked
                        if url not in checked_urls:
                            # Print checking URL message if verbose mode is enabled
                            if verbose:
                                print(f"{Fore.YELLOW}Checking URL: {url}{Style.RESET_ALL}")
                            checked_urls.add(url)
                            thread = threading.Thread(target=check_favicon_match, args=(url, base_favicon_hash, timeout, encountered_503, verbose))  # Pass verbose
                            threads.append(thread)
                            thread.start()
            else:  # Target is a domain
                for port in ports:
                    # Construct URL
                    if port == 443:
                        url = f"https://{target}:{port}"
                    else:
                        url = f"http://{target}:{port}"
                    
                    # Check if URL has been checked
                    if url not in checked_urls:
                        # Print checking URL message if verbose mode is enabled
                        if verbose:
                            print(f"{Fore.YELLOW}Checking URL: {url}{Style.RESET_ALL}")
                        checked_urls.add(url)
                        thread = threading.Thread(target=check_favicon_match, args=(url, base_favicon_hash, timeout, encountered_503, verbose))  # Pass verbose
                        threads.append(thread)
                        thread.start()
        
        # Join all threads
        for thread in threads:
            thread.join()
            
        # Print 503 status code messages for URLs that encountered it if verbose mode is not enabled
        for url in encountered_503:
            if verbose:
                print(f"{Fore.YELLOW}Received 503 status code for {url}. Skipping...{Style.RESET_ALL}")  # Print message if 503 status code encountered
            
    except requests.exceptions.ConnectionError as ce:
        if verbose:
            print(f"{Fore.RED}An error occurred while connecting to {target}: {ce}{Style.RESET_ALL}")  # Print error message if connection error occurs
    except Exception as e:
        if verbose:
            print(f"{Fore.RED}An error occurred: {e}{Style.RESET_ALL}")  # Print error message if unexpected error occurs


def parse_cidr_domains(cidr_list):
    """
    Parse CIDR notation and extract IP addresses.

    Args:
        cidr_list (str): Comma-separated list of CIDR notations.

    Returns:
        list: List of IP addresses.
    """
    ip_addresses = []
    cidrs = cidr_list.split(',')
    for cidr in cidrs:
        network = ipaddress.ip_network(cidr)
        for ip in network.hosts():
            ip_addresses.append(str(ip))
    return ip_addresses

def check_favicon_match(url, base_favicon_hash, timeout, encountered_503, verbose):
    """
    Check if the favicon of the given URL matches the base favicon hash.

    Parameters:
    - url: The URL to check for favicon match.
    - base_favicon_hash: The hash value of the base favicon.
    - timeout: The timeout duration for HTTP requests.
    - encountered_503: A set to store URLs that encountered a 503 status code.
    - verbose: A boolean flag indicating whether to print progress messages.

    Returns:
    - None.

    Raises:
    - None.

    Notes:
    - This function fetches the favicon URL from the given URL, calculates its hash value, and compares it with the base favicon hash.
    - If the hashes match, the URL is appended to the `matching_urls` list.
    - If verbose mode is enabled, progress messages are printed indicating the checking process.
    - If an HTTP error occurs (e.g., 503 status code), the URL is added to the `encountered_503` set.
    - Any other exceptions are caught and printed if verbose mode is enabled.
    """
    try:
        base_favicon_url = extract_favicon_url(requests.get(url, timeout=timeout, verify=False).content, url)  # Extract favicon URL from the given URL
        if base_favicon_url:
            favicon_hash = calculate_favicon_hash(base_favicon_url, timeout)  # Calculate hash value of the favicon
            if verbose:
                print(f"{Fore.YELLOW}Hash of favicon from {url}: {favicon_hash}{Style.RESET_ALL}")  # Print favicon hash value if verbose is True
            if favicon_hash == base_favicon_hash:
                matching_urls.append(url)  # Append matching URL to the list
                if verbose:
                    print(f"{Fore.GREEN}Match found: {url}{Style.RESET_ALL}")  # Print message if match found
        else:
            if verbose:
                print(f"{Fore.RED}No favicon found for {url}{Style.RESET_ALL}")  # Print message if no favicon found
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 503:
            encountered_503.add(url)  # Add URL to set of encountered 503 status code URLs
        if verbose:
            print(f"{Fore.RED}Received {e.response.status_code} status code for {url}. Skipping...{Style.RESET_ALL}")  # Print message if 503 status code received
    except Exception as e:
        if verbose:
            print(f"{Fore.RED}An error occurred while checking favicon for {url}: {e}{Style.RESET_ALL}")  # Print error message if unexpected error occurs


def fetch_base_favicon(base_url, timeout):
    """
    Fetch the base favicon from the given base URL and calculate its hash value.

    Parameters:
    - base_url: The base URL from which to fetch the base favicon.
    - timeout: The timeout duration for HTTP requests.

    Returns:
    - The hash value of the base favicon, or None if an error occurs.

    Raises:
    - None.

    Notes:
    - This function makes an HTTP GET request to the base URL to fetch the HTML content.
    - It then extracts the URL of the favicon from the HTML content and calculates its hash value.
    - If successful, it returns the hash value of the base favicon.
    - If an HTTP error occurs (e.g., 404), an error message is printed if verbose mode is enabled.
    - Any other exceptions are caught and printed if verbose mode is enabled.
    """
    try:
        response = requests.get(base_url, timeout=timeout, verify=False)  # Fetch HTML content from the base URL
        response.raise_for_status()  # Raise an HTTPError if the response status code indicates an error
        base_favicon_url = extract_favicon_url(response.content, base_url)  # Extract favicon URL from the HTML content
        if base_favicon_url:
            base_favicon_hash = calculate_favicon_hash(base_favicon_url, timeout)  # Calculate hash value of the base favicon
            return base_favicon_hash  # Return the hash value of the base favicon
    except requests.exceptions.HTTPError as e:
        if verbose:
            print(f"{Fore.RED}An error occurred while fetching base favicon for {base_url}: {e}{Style.RESET_ALL}")  # Print error message if an HTTP error occurs
    except Exception as e:
        if verbose:
            print(f"{Fore.RED}An unexpected error occurred while fetching base favicon for {base_url}: {e}{Style.RESET_ALL}")  # Print error message if unexpected error occurs
    return None  # Return None if an error occurs during the fetching process


def print_banner():
    banner = """
     8888888b.  888       888 888b    888  .d888                  d8b
     888   Y88b 888   o   888 8888b   888 d88P"                   Y8P
     888    888 888  d8b  888 88888b  888 888
     888   d88P 888 d888b 888 888Y88b 888 888888 8888b.  888  888 888  .d8888b .d88b.  88888b.
     8888888P"  888d88888b888 888 Y88b888 888       "88b 888  888 888 d88P"   d88""88b 888 "88b
     888        88888P Y88888 888  Y88888 888   .d888888 Y88  88P 888 888     888  888 888  888
     888        8888P   Y8888 888   Y8888 888   888  888  Y8bd8P  888 Y88b.   Y88..88P 888  888
     888        888P     Y888 888    Y888 888   "Y888888   Y88P   888  "Y8888P "Y88P"  888  888

                                                                        v1.0 Designed by кασѕ
                                                                        Powered by PWNCAT S.L
    """
    print(f"{Fore.BLUE}{banner}{Style.RESET_ALL}")

if __name__ == "__main__":
    print_banner()
    parser = argparse.ArgumentParser(description="Crawl IP ranges or domains to search for matching favicons.")
    parser.add_argument("-cf", "--cidr-file", help="Specify a file containing CIDR ranges.")
    parser.add_argument("-c", "--cidr", help="Specify CIDR ranges separated by commas.")
    parser.add_argument("-df", "--domains-file", help="Specify a file containing domains.")
    parser.add_argument("-d", "--domains", help="Specify domains separated by commas.")
    parser.add_argument("-u","--url", help="Specify the base URL directly.")
    parser.add_argument("-p", "--ports", help="Specify ports to check separated by commas.", default="80,443,8080")
    parser.add_argument("--timeout", type=int, help="Specify timeout for HTTP requests in seconds.", default=10)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode for detailed logging.")
    parser.add_argument("-t", "--threads", type=int, help="Specify the number of threads to use.", default=10)
    args = parser.parse_args()

    if not vars(args) or (not args.url and not args.cidr and not args.domains and not args.cidr_file and not args.domains_file):
        parser.print_help()
    elif args.verbose:
        print(f"{Fore.YELLOW}Verbose mode enabled.{Style.RESET_ALL}")
        verbose = True

    base_url = args.url  # Define base_url based on the provided argument
    cidr_ranges = []
    if args.cidr_file:
        cidr_ranges, domains, _ = parse_cidr_domains_from_file(args.cidr_file)
    elif args.cidr:
        cidr_ranges = parse_cidr_domains(args.cidr)
    domains = []
    if args.domains_file:
        with open(args.domains_file, 'r') as file:
            domains = [line.strip() for line in file]
    elif args.domains:
        domains = args.domains.split(',')
    
    if base_url is None:
        print("Base URL is not provided. Printing help:")
        parser.print_help()
    elif not cidr_ranges and not domains:
        print("No CIDR ranges or domains provided. Printing help:")
        parser.print_help()
    else:
        ports = [int(port) for port in args.ports.split(',')]
        targets = cidr_ranges + domains
        crawl_targets(targets, base_url, ports, args.timeout, args.threads)

        if matching_urls:
            print(f"\n{Fore.GREEN}Matching URLs:{Style.RESET_ALL}")
            for url in matching_urls:
                print(url)
        else:
            print(f"{Fore.YELLOW}No matching URLs found.{Style.RESET_ALL}")

