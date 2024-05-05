# Standard library imports
import argparse
import ipaddress
import logging
import threading
from urllib.parse import urljoin, urlparse

# Third-party imports
import mmh3
import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

requests.packages.urllib3.disable_warnings()  # Disable warnings from urllib3 package

# Initialize logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Initialize an empty list to store matching URLs
matching_urls = []

# Initialize threading semaphore
semaphore = threading.Semaphore(10)

verbose = False  # or True, depending on your default
debug = False  # or True, depending on your default

# Initialize a lock for the matching_urls list
matching_urls_lock = threading.Lock()

def calculate_hash(data):
    """
    Calculate the MurmurHash3 hash value of the input data.
    """
    try:
        return mmh3.hash(data)  # Calculate the MurmurHash3 hash value
    except Exception as e:
        if debug:
            logger.error(f"An error occurred while calculating hash: {e}")
        return None  # Return None if an error occurs

def exit_program():
    """
    Exit the program.
    This function is called when the necessary arguments are not provided.
    """
    exit()

def parse_args():
    """
    Parse command line arguments.
    This function is responsible for parsing the command line arguments and returning them.
    """
    # Your code here

def parse_ports(args):
    """
    Parse the ports to check.
    This function takes the command line arguments, extracts the ports argument, splits it into a list of integers, and returns it.
    Args:
        args: The command line arguments.
    Returns:
        A list of integers representing the ports to check.
    """
    ports = [int(port) for port in args.ports.split(',')]
    return ports

def merge_targets(parsed_entries):
    """
    Merge CIDR ranges and domains into a targets list.
    This function takes the parsed entries and returns them as a list of targets.
    Args:
        parsed_entries: The parsed CIDR ranges and domains.
    Returns:
        A list of targets.
    """
    targets = parsed_entries
    return targets


def crawl_targets(targets, base_url, ports, timeout):
    """
    Crawl the specified targets to check for matching favicons with the base favicon of the provided base URL.
    """
    try:
        if verbose:
            tqdm.write(f"{Fore.YELLOW}Fetching base favicon for {base_url}{Style.RESET_ALL}")
        domain = urlparse(base_url).netloc
        headers = {"Host": domain} if domain else None
        base_favicon_hash = fetch_base_favicon(base_url, timeout, headers)
        if not base_favicon_hash:
            if verbose:
                tqdm.write(f"{Fore.RED}Base favicon not found or could not be fetched for {base_url}. Skipping.{Style.RESET_ALL}")
            return

        if verbose:
            tqdm.write(f"{Fore.YELLOW}Base favicon hash fetched for {base_url}: {base_favicon_hash}{Style.RESET_ALL}")

        checked_urls = set()

        total_hosts = 0
        for target in targets:
            if '/' in target:  # CIDR range
                network = ipaddress.ip_network(target, strict=False)
                total_hosts += len(list(network.hosts()))
            else:
                total_hosts += 1

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for target in targets:
                hosts = []
                if '/' in target:  # CIDR range
                    network = ipaddress.ip_network(target, strict=False)
                    hosts = network.hosts()
                else:
                    try:
                        hosts = [ipaddress.ip_address(target)]
                    except ValueError:
                        hosts = [target]

                for host in hosts:
                    for port in ports:
                        url = f"https://{host}:{port}" if port in (443, 8443) else f"http://{host}:{port}"
                        if url not in checked_urls:
                            if verbose:
                                tqdm.write(f"{Fore.YELLOW}Checking URL: {url}{Style.RESET_ALL}")
                            checked_urls.add(url)
                            futures.append(executor.submit(check_favicon_match, url, base_favicon_hash, timeout, headers))

            with tqdm(total=len(futures), desc="Crawling targets", unit="target") as pbar:  # Initialize progress bar with correct target count
                for future in as_completed(futures):
                    pbar.update()

    except requests.exceptions.ConnectionError as ce:
        if debug:
            logger.error(f"{Fore.RED}An error occurred while connecting to {target}: {ce}{Style.RESET_ALL}")
    except Exception as e:
        if debug:
            logger.error(f"{Fore.RED}An error occurred: {e}{Style.RESET_ALL}")

def print_matching_urls(matching_urls):
    """
    Print the matching URLs.
    This function takes a list of matching URLs and tqdm.writes them.
    Args:
        matching_urls: A list of matching URLs.
    """
    if matching_urls:
        tqdm.write(f"\n{Fore.GREEN}Matching URLs:{Style.RESET_ALL}")
        for url in matching_urls:
            tqdm.write(url)
    else:
        tqdm.write(f"{Fore.YELLOW}No matching URLs found.{Style.RESET_ALL}")

def calculate_favicon_hash(favicon_url, timeout, headers=None):
    """
    Download the favicon from the given URL, calculate its hash value using MurmurHash3 algorithm, and return the hash value.
    """
    try:
        if verbose:
            tqdm.write(f"{Fore.YELLOW}Downloading favicon from {favicon_url}{Style.RESET_ALL}")  # Print message indicating favicon download if verbose is True
        if headers:
            response = requests.get(favicon_url, timeout=timeout, allow_redirects=True, verify=False, headers=headers)  # Make HTTP GET request to download the favicon
        else:
            response = requests.get(favicon_url, timeout=timeout, allow_redirects=True, verify=False)  # Make HTTP GET request to download the favicon
        
        response.raise_for_status()  # Raise an HTTPError if the response status code indicates an error
        
        favicon_content = response.content  # Get the content of the favicon
        hash_value = calculate_hash(favicon_content)  # Calculate the hash value of the favicon content using calculate_hash function
        
        if verbose:
            tqdm.write(f"{Fore.YELLOW}Hash of favicon from {favicon_url}: {hash_value}{Style.RESET_ALL}")  # Print message indicating favicon hash value if verbose is True
        return hash_value  # Return the hash value of the favicon content
    except requests.RequestException as e:
        if debug:
            logger.error(f"{Fore.RED}An error occurred while fetching favicon from {favicon_url}: {e}{Style.RESET_ALL}")  # Print error message if an HTTP request error occurs and verbose is True
    except Exception as e:
        if debug:
            logger.error(f"{Fore.RED}An unexpected error occurred while fetching favicon from {favicon_url}: {e}{Style.RESET_ALL}")  # Print error message if an unexpected error occurs and verbose is True
    
    return "__error__"  # Return placeholder if an error occurs during the download or hash calculation

def extract_favicon_url(html_content, base_url):
    """
    Extract the URL of the favicon from the given HTML content and base URL.
    """
    soup = BeautifulSoup(html_content, 'html.parser')  # Parse the HTML content using BeautifulSoup
    favicon_link = soup.find('link', rel='icon')  # Find the favicon link tag
    if favicon_link:
        favicon_url = favicon_link.get('href')  # Get the value of the 'href' attribute
        return urljoin(base_url, favicon_url)  # Resolve the URL against the base URL and return the absolute URL
    else:
        return None  # Return None if no favicon link is found

def check_favicon_match(url, base_favicon_hash, timeout, headers, pbar=None):
    """
    Check if the favicon of the given URL matches the base favicon hash.
    """
    with semaphore:  # Use the semaphore here
        try:
            response = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True, verify=False)
            favicon_url = extract_favicon_url(response.content, url)
            if favicon_url:
                favicon_hash = calculate_favicon_hash(favicon_url, timeout)
                if verbose:
                    tqdm.write(f"{Fore.YELLOW}Hash of favicon from {url}: {favicon_hash}{Style.RESET_ALL}")
                if favicon_hash == base_favicon_hash:
                    with matching_urls_lock:  # Acquire the lock before appending to the list
                        matching_urls.append(url)
                    tqdm.write(f"{Fore.GREEN}Match found: {url}{Style.RESET_ALL}")
                else:
                    if verbose:
                        tqdm.write(f"{Fore.RED}No match found for {url}. Favicon hash: {favicon_hash}, Base favicon hash: {base_favicon_hash}{Style.RESET_ALL}")
            else:
                if verbose:
                    tqdm.write(f"{Fore.RED}No favicon found for {url}{Style.RESET_ALL}")
        except requests.exceptions.Timeout:
            if debug:
                logger.error(f"{Fore.RED}Timeout occurred while checking favicon for {url}{Style.RESET_ALL}")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 503:
                if debug:
                    logger.error(f"{Fore.RED}Received {e.response.status_code} status code for {url}. Skipping...{Style.RESET_ALL}")
            else:
                if debug:
                    logger.error(f"{Fore.RED}An error occurred while checking favicon for {url}: {e}{Style.RESET_ALL}")
        except Exception as e:
            if debug:
                logger.error(f"{Fore.RED}An error occurred while checking favicon for {url}: {e}{Style.RESET_ALL}")
        finally:
            if pbar is not None:
                pbar.update()

def fetch_base_favicon(base_url, timeout, headers):
    """
    Fetch the base favicon from the given base URL and calculate its hash value.
    """
    try:
        response = requests.get(base_url, timeout=timeout, headers=headers, allow_redirects=True, verify=False)
        base_favicon_url = extract_favicon_url(response.content, base_url)
        if base_favicon_url:
            base_favicon_hash = calculate_favicon_hash(base_favicon_url, timeout)
            if verbose:
                tqdm.write(f"{Fore.YELLOW}Base favicon hash for {base_url}: {base_favicon_hash}{Style.RESET_ALL}")
            return base_favicon_hash
        else:
            if verbose:
                tqdm.write(f"{Fore.RED}No favicon found for {base_url}{Style.RESET_ALL}")
            return None
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 503:
            if debug:
                logger.error(f"{Fore.RED}Received {e.response.status_code} status code for {base_url}. Skipping...{Style.RESET_ALL}")
            return None
        else:
            if verbose:
                logger.error(f"{Fore.RED}An error occurred while fetching base favicon for {base_url}: {e}{Style.RESET_ALL}")
            return None
    except Exception as e:
        if debug:
            logger.error(f"{Fore.RED}An error occurred while fetching base favicon for {base_url}: {e}{Style.RESET_ALL}")
        return None

def parse_cidr_domains(cidr_list):
    """
    Parse CIDR notation and extract IP addresses.
    """
    ip_addresses = []
    cidrs = cidr_list.split(',')
    for cidr in cidrs:
        network = ipaddress.ip_network(cidr)
        for ip in network.hosts():
            ip_addresses.append(str(ip))
    return ip_addresses


def parse_file(file_path):
    """
    Parse IP addresses, domains, and CIDR notations from a file.
    """
    parsed_entries = []  # Renamed the list name from cidr_domains to parsed_entries
    try:
        with open(file_path, 'r') as file:
            for line in file:
                entry = line.strip()
                if entry:  # Check if the line is not empty
                    if '/' in entry:  # Assume it's a CIDR notation
                        parsed_entries.append(entry)
                    elif '.' in entry:  # Assume it's an IP address
                        parsed_entries.append(entry)
                    else:  # Otherwise, assume it's a domain
                        parsed_entries.append(entry)
        return parsed_entries
    except FileNotFoundError:
        if debug:
            logger.error(f"{Fore.RED}File {file_path} not found.{Style.RESET_ALL}")
        return []

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
    tqdm.write(f"{Fore.BLUE}{banner}{Style.RESET_ALL}")

if __name__ == "__main__":
    print_banner()
    
    # Define parser and its arguments
    parser = argparse.ArgumentParser(description="Crawl IP ranges or domains to search for matching favicons.")
    parser.add_argument("-c", "--cidr", help="Specify CIDR ranges separated by commas.")
    parser.add_argument("-d", "--domains", help="Specify domains separated by commas.")
    parser.add_argument("-f", "--file", help="Specify IP addresses, domains, or CIDR ranges in a file.")
    parser.add_argument("-u", "--url", help="Specify the base URL directly.")
    parser.add_argument("-p", "--ports", help="Specify ports to check separated by commas.", default="80,443,8080,8443")
    parser.add_argument("--timeout", type=int, help="Specify timeout for HTTP requests in seconds.", default=10)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode for detailed logging.")
    parser.add_argument("-t", "--threads", type=int, help="Specify the number of threads to use.", default=5)
    parser.add_argument("--debug", help="Specify the file path to output debug logs.")
    args = parser.parse_args()

    # Set up logger
    if args.debug:
        debug = True
        file_handler = logging.FileHandler(args.debug)
        file_handler.setLevel(logging.ERROR)
        logger.addHandler(file_handler)
    
    # Check if no arguments are provided or if no essential argument is provided
    if not any(value for value in vars(args).values() if value is not None):
        parser.tqdm.write_help()
        exit()
    elif args.verbose:
        tqdm.write(f"{Fore.YELLOW}Verbose mode enabled.{Style.RESET_ALL}")
        verbose = True

    # Define base_url based on the provided argument
    base_url = args.url

    # Initialize parsed_entries list
    parsed_entries = []

    # Initialize the semaphore
    semaphore = threading.Semaphore(args.threads)

    # Parse entries based on the provided arguments
    if args.file:
        parsed_entries.extend(parse_file(args.file))
    if args.cidr:
        parsed_entries.extend(parse_cidr_domains(args.cidr))
    if args.domains:
        parsed_entries.extend(args.domains.split(','))

    # Check if base_url is provided and parsed_entries is not empty
    if not base_url:
        tqdm.write("Base URL is not provided. Printing help:")
        parser.tqdm.write_help()
        exit()
    elif not parsed_entries:
        tqdm.write("No CIDR ranges, domains, or file provided. Printing help:")
        parser.tqdm.write_help()
        exit()

    # Define ports to check
    ports = [int(port) for port in args.ports.split(',')]

    # Merge CIDR ranges and domains into targets list
    targets = parsed_entries
    crawl_targets(targets, base_url, ports, args.timeout)

    # Print matching URLs
    if matching_urls:
        tqdm.write(f"\n{Fore.GREEN}Matching URLs:{Style.RESET_ALL}")
        for url in matching_urls:
            tqdm.write(url)
    else:
        tqdm.write(f"{Fore.YELLOW}No matching URLs found.{Style.RESET_ALL}")
