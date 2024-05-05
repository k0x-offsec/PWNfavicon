
import argparse
import ipaddress
import logging
import threading
import os
from urllib.parse import urljoin, urlparse

import mmh3
import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

requests.packages.urllib3.disable_warnings()  

logger = logging.getLogger(__name__)

logger.setLevel(logging.INFO)

matching_urls = []

verbose = False  

debug = False  

matching_urls_lock = threading.Lock()

def calculate_hash(data):
    """
    Calculate the MurmurHash (version 3) of the given data.
    This function uses the mmh3 library to calculate the hash. If an error occurs during the calculation,
    it logs an error message (if debugging is enabled) and returns None.
    Args:
        data: The data to be hashed. This can be any data type that is accepted by the mmh3.hash function.
    Returns:
        The MurmurHash of the data as an integer, or None if an error occurred.
    Raises:
        This function catches all exceptions, logs an error message if debugging is enabled, and returns None.
    """
    try:
        return mmh3.hash(data)
    except Exception as e:
        if debug:
            logger.error(f"An error occurred while calculating hash: {e}")
        return None

def generate_urls(targets, ports):
    """
    Generate a set of URLs from the given targets and ports.
    This function constructs URLs for each combination of target and port. If a target is a CIDR range,
    it generates URLs for each host in the range. The scheme of the URL is determined by the port:
    if the port is 443 or 8443, the scheme is 'https', otherwise it's 'http'.
    Args:
        targets: A list of targets. Each target can be a hostname, an IP address, or a CIDR range.
        ports: A list of ports.
    Returns:
        A set of URLs.
    Raises:
        This function can raise a ValueError if a target is an invalid CIDR range.
    """
    urls = set()
    for target in targets:
        hosts = [target]
        if '/' in target:  
            network = ipaddress.ip_network(target, strict=False)
            hosts = network.hosts()
        for host in hosts:
            for port in ports:
                url = f"https://{host}:{port}" if port in (443, 8443) else f"http://{host}:{port}"
                urls.add(url)
    return urls

def crawl_targets(targets, base_url, ports, timeout, threads):
    """
    Crawl a list of target URLs and check if their favicons match a base favicon.
    This function fetches the base favicon from the base URL, generates a list of URLs from the targets and ports,
    and then uses a ThreadPoolExecutor to check if the favicon of each URL matches the base favicon hash.
    Args:
        targets: A list of targets. Each target can be a hostname, an IP address, or a CIDR range.
        base_url: The base URL to fetch the base favicon from.
        ports: A list of ports.
        timeout: The timeout for the HTTP requests.
        threads: The maximum number of workers for the ThreadPoolExecutor.
    Returns:
        None
    Raises:
        This function catches all exceptions, logs an error message if debugging is enabled, and returns None.
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
        urls = generate_urls(targets, ports)
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_favicon_match, url, base_favicon_hash, timeout, headers): url for url in urls}
            with tqdm(total=len(futures), desc="Crawling targets", unit="target") as pbar:  
                for future in as_completed(futures):
                    url = futures[future]
                    try:
                        result = future.result()  
                        if verbose:
                            tqdm.write(f"{Fore.YELLOW}Checking URL: {url}{Style.RESET_ALL}")
                        pbar.update()
                    except Exception as e:
                        if debug:
                            logger.error(f"{Fore.RED}An error occurred while checking favicon for {url}: {e}{Style.RESET_ALL}")
    except Exception as e:
        if debug:
            logger.error(f"{Fore.RED}An error occurred: {e}{Style.RESET_ALL}")

def calculate_favicon_hash(favicon_url, timeout, headers=None):
    """
    Download the favicon from the given URL and calculate its hash value.
    This function makes an HTTP GET request to download the favicon from the provided URL, calculates the hash value of the favicon content using the MurmurHash3 algorithm, and returns the hash value. If an error occurs during the download or hash calculation, it returns a placeholder string "__error__".
    Args:
        favicon_url: The URL of the favicon to download.
        timeout: The timeout for the HTTP request.
        headers: Optional; A dictionary of HTTP headers to include in the request.
    Returns:
        The hash value of the favicon content as an integer, or "__error__" if an error occurred.
    Raises:
        This function catches all exceptions, logs an error message if debugging is enabled, and returns "__error__".
    """
    try:
        if verbose:
            tqdm.write(f"{Fore.YELLOW}Downloading favicon from {favicon_url}{Style.RESET_ALL}")  
        if headers:
            response = requests.get(favicon_url, timeout=timeout, allow_redirects=True, verify=False, headers=headers)  
        else:
            response = requests.get(favicon_url, timeout=timeout, allow_redirects=True, verify=False)  
        response.raise_for_status()  
        favicon_content = response.content  
        hash_value = calculate_hash(favicon_content)  
        if verbose:
            tqdm.write(f"{Fore.YELLOW}Hash of favicon from {favicon_url}: {hash_value}{Style.RESET_ALL}")  
        return hash_value  
    except requests.RequestException as e:
        if debug:
            logger.error(f"{Fore.RED}An error occurred while fetching favicon from {favicon_url}: {e}{Style.RESET_ALL}")  
    except Exception as e:
        if debug:
            logger.error(f"{Fore.RED}An unexpected error occurred while fetching favicon from {favicon_url}: {e}{Style.RESET_ALL}")  
    return "__error__"  

def extract_favicon_url(html_content, base_url):
    """
    Extract the URL of the favicon from the given HTML content and base URL.
    This function parses the HTML content using BeautifulSoup, finds the favicon link tag, and extracts the URL of the favicon. If a favicon link tag is found, it resolves the URL against the base URL and returns the absolute URL. If no favicon link tag is found, it returns None.
    Args:
        html_content: A string containing the HTML content to extract the favicon URL from.
        base_url: The base URL to resolve the favicon URL against.
    Returns:
        The absolute URL of the favicon, or None if no favicon link tag is found.
    Raises:
        This function can raise a BeautifulSoup exception if the HTML content is not parseable.
    """
    soup = BeautifulSoup(html_content, 'html.parser')  
    favicon_link = soup.find('link', rel='icon')  
    if favicon_link:
        favicon_url = favicon_link.get('href')  
        return urljoin(base_url, favicon_url)  
    else:
        return None  

def check_favicon_match(url, base_favicon_hash, timeout, headers, pbar=None):
    """
    Check if the favicon of the given URL matches the base favicon hash.
    This function makes an HTTP GET request to the given URL, extracts the favicon URL from the response content, calculates the hash of the favicon, and checks if it matches the base favicon hash. If the favicon hash matches the base favicon hash, it appends the URL to the matching_urls list. If a progress bar is provided, it updates the progress bar after checking the favicon.
    Args:
        url: The URL to check.
        base_favicon_hash: The hash of the base favicon to compare against.
        timeout: The timeout for the HTTP requests.
        headers: A dictionary of HTTP headers to include in the requests.
        pbar: Optional; A tqdm progress bar to update after checking the favicon.
    Returns:
        None
    Raises:
        This function catches all exceptions, logs an error message if debugging is enabled, and returns None.
    """
    try:
        response = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True, verify=False)
        favicon_url = extract_favicon_url(response.content, url)
        if favicon_url:
            favicon_hash = calculate_favicon_hash(favicon_url, timeout)
            if verbose:
                tqdm.write(f"{Fore.YELLOW}Hash of favicon from {url}: {favicon_hash}{Style.RESET_ALL}")
            if favicon_hash == base_favicon_hash:
                with matching_urls_lock:  
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

def parse_input_or_file(input):
    """
    Parse the input as a file or a direct input.
    This function tries to open the input as a file and read its contents. Each line in the file is treated as a separate entry. If the line contains a CIDR range, it generates all hosts in the range. If the line is an IP address or a domain, it is added directly to the entries.
    If the input is not a file, it is parsed directly in the same way.
    Args:
        input: The input to parse. This can be a path to a file, a CIDR range, an IP address, or a domain.
    Returns:
        A list of entries. Each entry is a string representing an IP address or a domain.
    Raises:
        This function catches all exceptions, logs an error message if debugging is enabled, and returns an empty list.
    """
    entries = []
    try:
        with open(input, 'r') as file:
            for line in file:
                line = line.strip()
                if '/' in line:  
                    network = ipaddress.ip_network(line, strict=False)
                    entries.extend(str(ip) for ip in network.hosts())
                else:  
                    entries.append(line)
    except FileNotFoundError:
        if '/' in input:  
            network = ipaddress.ip_network(input, strict=False)
            entries.extend(str(ip) for ip in network.hosts())
        else:  
            entries.append(input)
    except Exception as e:
        if debug:
            logger.error(f"An error occurred while parsing input or file: {e}")
    return entries

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
    parser = argparse.ArgumentParser(description="Crawl IP ranges or domains to search for matching favicons.")
    parser.add_argument("-c", "--cidr", help="Specify CIDR ranges separated by commas.")
    parser.add_argument("-d", "--domains", help="Specify domains separated by commas.")
    parser.add_argument("-f", "--file", help="Specify IP addresses, domains, or CIDR ranges in a file.")
    parser.add_argument("-u", "--url", help="Specify the base URL directly.")
    parser.add_argument("-p", "--ports", help="Specify ports to check separated by commas.", default="80,443,8080,8443")
    parser.add_argument("--timeout", type=int, help="Specify timeout for HTTP requests in seconds.", default=10)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode for detailed logging.")
    parser.add_argument('--threads', type=int, default=os.cpu_count() or 1, help='Number of threads to use')
    parser.add_argument("--debug", help="Specify the file path to output debug logs.")
    args = parser.parse_args()

    if args.debug:
        debug = True
        file_handler = logging.FileHandler(args.debug)
        file_handler.setLevel(logging.ERROR)
        logger.addHandler(file_handler)
    if not any(value for value in vars(args).values() if value is not None):
        parser.tqdm.write_help()
        exit()
    elif args.verbose:
        tqdm.write(f"{Fore.YELLOW}Verbose mode enabled.{Style.RESET_ALL}")
        verbose = True

    base_url = args.url

    parsed_entries = []

    if args.file:
        parsed_entries.extend(parse_input_or_file(args.file))
    if args.cidr:
        parsed_entries.extend(parse_input_or_file(args.cidr))
    if args.domains:
        parsed_entries.extend(parse_input_or_file(args.domains))
    if not base_url:
        tqdm.write("Base URL is not provided. Printing help:")
        parser.tqdm.write_help()
        exit()
    elif not parsed_entries:
        tqdm.write("No CIDR ranges, domains, or file provided. Printing help:")
        parser.tqdm.write_help()
        exit()

    ports = [int(port) for port in args.ports.split(',')]
    targets = parsed_entries

    crawl_targets(targets, base_url, ports, args.timeout, args.threads)

    if matching_urls:
        tqdm.write(f"\n{Fore.GREEN}Matching URLs:{Style.RESET_ALL}")
        for url in matching_urls:
            tqdm.write(url)
    else:
        tqdm.write(f"{Fore.YELLOW}No matching URLs found.{Style.RESET_ALL}")