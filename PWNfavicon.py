import mmh3
import argparse
import threading
import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style
from urllib.parse import urljoin
import ipaddress
from tqdm import tqdm

requests.packages.urllib3.disable_warnings() 
verbose = False  # Initialize verbose as a global variable
matching_urls = []

def calculate_hash(data):
    try:
        return mmh3.hash(data)
    except Exception as e:
        if verbose:
            print(f"{Fore.RED}An error occurred while calculating hash: {e}{Style.RESET_ALL}")
        return None

def calculate_favicon_hash(favicon_url, timeout):
    try:
        if verbose:
            print(f"{Fore.YELLOW}Downloading favicon from {favicon_url}{Style.RESET_ALL}")
        response = requests.get(favicon_url, timeout=timeout, allow_redirects=True, verify=False)
        response.raise_for_status()
        
        favicon_content = response.content
        hash_value = calculate_hash(favicon_content)
        
        if verbose:
            print(f"{Fore.YELLOW}Hash of favicon from {favicon_url}: {hash_value}{Style.RESET_ALL}")
        return hash_value
    except requests.RequestException as e:
        if verbose:
            print(f"{Fore.RED}An error occurred while fetching favicon from {favicon_url}: {e}{Style.RESET_ALL}")
    except Exception as e:
        if verbose:
            print(f"{Fore.RED}An unexpected error occurred while fetching favicon from {favicon_url}: {e}{Style.RESET_ALL}")
    
    return None

def extract_favicon_url(html_content, base_url):
    soup = BeautifulSoup(html_content, 'html.parser')
    favicon_link = soup.find('link', rel='icon')
    if favicon_link:
        favicon_url = favicon_link.get('href')
        return urljoin(base_url, favicon_url)
    else:
        return None

def crawl_targets(targets, base_url, ports, timeout, num_threads):
    try:

        # Fetch base favicon
        if verbose:
            print(f"{Fore.YELLOW}Fetching base favicon for {base_url}{Style.RESET_ALL}")
        base_favicon_hash = fetch_base_favicon(base_url, timeout)
        if not base_favicon_hash:
            if verbose:
                print(f"{Fore.RED}Base favicon not found or could not be fetched for {base_url}. Skipping.{Style.RESET_ALL}")
            return
        if verbose:
            print(f"{Fore.YELLOW}Base favicon hash fetched for {base_url}: {base_favicon_hash}{Style.RESET_ALL}")
        
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
                        if port == 443:
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
                print(f"{Fore.YELLOW}Received 503 status code for {url}. Skipping...{Style.RESET_ALL}")
            
    except requests.exceptions.ConnectionError as ce:
        if verbose:
            print(f"{Fore.RED}An error occurred while connecting to {target}: {ce}{Style.RESET_ALL}")
    except Exception as e:
        if verbose:
            print(f"{Fore.RED}An error occurred: {e}{Style.RESET_ALL}")


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
    try:
        base_favicon_url = extract_favicon_url(requests.get(url, timeout=timeout, verify=False).content, url)
        if base_favicon_url:
            favicon_hash = calculate_favicon_hash(base_favicon_url, timeout)
            if verbose:
                print(f"{Fore.YELLOW}Hash of favicon from {url}: {favicon_hash}{Style.RESET_ALL}")
            if favicon_hash == base_favicon_hash:
                matching_urls.append(url)  # Append matching URL to the list
                if verbose:
                    print(f"{Fore.GREEN}Match found: {url}{Style.RESET_ALL}")
        else:
            if verbose:
                print(f"{Fore.RED}No favicon found for {url}{Style.RESET_ALL}")
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 503:
            encountered_503.add(url)
        if verbose:
            print(f"{Fore.RED}Received {e.response.status_code} status code for {url}. Skipping...{Style.RESET_ALL}")
    except Exception as e:
        if verbose:
            print(f"{Fore.RED}An error occurred while checking favicon for {url}: {e}{Style.RESET_ALL}")


def fetch_base_favicon(base_url, timeout):
    try:
        response = requests.get(base_url, timeout=timeout, verify=False)
        response.raise_for_status()
        base_favicon_url = extract_favicon_url(response.content, base_url)
        if base_favicon_url:
            base_favicon_hash = calculate_favicon_hash(base_favicon_url, timeout)
            return base_favicon_hash
    except requests.exceptions.HTTPError as e:
        if verbose:
            print(f"{Fore.RED}An error occurred while fetching base favicon for {base_url}: {e}{Style.RESET_ALL}")
    except Exception as e:
        if verbose:
            print(f"{Fore.RED}An unexpected error occurred while fetching base favicon for {base_url}: {e}{Style.RESET_ALL}")
    return None

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

