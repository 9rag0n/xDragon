import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import time

# Function to read payloads from a file
def read_payloads(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]

# Function to read URLs from a file
def read_urls(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]

# Define the path to the payloads file
payloads_file = "payloads.txt"

# Read the payloads from the file
xss_payloads = read_payloads(payloads_file)

# Function to check for XSS in response
def check_xss(response, payload):
    soup = BeautifulSoup(response.text, 'html.parser')

    # Check if the payload is present in the response text
    if payload in response.text:
        return True

    # Check for script tags in the response
    for script in soup.find_all('script'):
        if payload in script.decode_contents():
            return True

    # Check for attributes in all tags in the response
    for tag in soup.find_all(True):
        for attr, value in tag.attrs.items():
            if isinstance(value, list):
                if any(payload in v for v in value):
                    return True
            else:
                if payload in value:
                    return True

    # Check for inline JavaScript event handlers
    for tag in soup.find_all(True):
        for attr in tag.attrs:
            if attr.startswith('on') and payload in tag.attrs[attr]:
                return True

    return False

# Function to update URL with the payload
def update_url_with_payload(url, payload):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    query_params = payload
    new_query_string = urlencode(query_params, doseq=True)
    updated_url = urlunparse(parsed_url._replace(query=new_query_string))
    return updated_url

# Function to test for XSS and print all attempts
def test_for_xss(url):
    try:
        for payload in xss_payloads:
            # Update the URL with the payload
            updated_url = update_url_with_payload(url, payload)
            try:
                response = requests.get(updated_url)
                print(f"Attempt: {updated_url}")
                
                if check_xss(response, payload):
                    print(f"Vulnerable URL: {updated_url}")
                    print(f"Payload: {payload}")
                    print()
                    
            except requests.RequestException as e:
                print(f"Request failed for {updated_url}: {e}")
                
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt received. Exiting...")
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}")

# Function to test a list of URLs
def test_multiple_urls(urls):
    for url in urls:
        print(f"Testing URL: {url}")
        test_for_xss(url)

# Print banner
def print_banner():
    red = "\033[91m"
    reset = "\033[0m"
    banner = f"""
    {red}
                             _      _   _____   ________       ___       _________      _____     _         _
                             \.\   /./ |._'_ \  |'|.___ \     / . \     /. __'___\.\   /  '  \   |.|\.\    |.|
                              \  \  /  |.|  |.| |''   | .\   /./ \.\   /. /    ____   |. / \ .|  |.| \.\   |.|
                              /./  /   |.|  |.| |.|,-"/../  /./__ \.\  |.',   |____|  |.|   |.|  |.|  \.\  |.|
                             /./ \.\   |.|__|.| |.|\.\ .   /./ ___ \.\  \. .  . .| |  | .\ /. |  |.|   \.\ |.|
                            /./   \.\  |_____/  |.|   \.\ /./       \.\  '.__"_____;   \_____/   |.|    \.\|.|
    
                                                                                       @dragon
                                                                                       https://github.com/9rag0n/xDragon
    {reset}   
    """
    print(banner)

# Main function
def main():
    print_banner()

    parser = argparse.ArgumentParser(description="XSS Tester")
    parser.add_argument('-u', '--url', help='Single URL to test for XSS')
    parser.add_argument('-U', '--urls_file', help='File containing list of URLs to test for XSS')
    args = parser.parse_args()

    if args.url:
        test_for_xss(args.url)
    elif args.urls_file:
        urls = read_urls(args.urls_file)
        test_multiple_urls(urls)
    else:
        print("Please provide either a single URL with -u or a file containing URLs with -U")

if __name__ == "__main__":
    main()
