import json
import os
from typing import TypedDict
from abc import ABC, abstractmethod
import re
import csv
import argparse
import http.client
import urllib
import urllib.request
import ssl
from urllib.parse import urlparse, urlunparse
import re
import time

class Config(TypedDict):
    username: str
    password: str
    hostel_endpoint: str
    campus_endpoint: str

class Base(ABC):
    def __init__(self) -> None:
        self.config_file_path = "./config.json"
        self.config: Config = self.load_or_create_config()
    
    @abstractmethod
    def login(self) -> None:
        pass

    @abstractmethod
    def logout(self) -> None:
        pass

    @abstractmethod
    def generate_headers() -> dict:
        pass

    def load_or_create_config(self) -> Config:
        """Load config.json or create it if it doesn't exist."""
        if not os.path.exists(self.config_file_path):
            print(f"Config file not found. Creating {self.config_file_path}...")
            # Default config values
            default_config = {
                "username": "",
                "password": "",
                "hostel_endpoint": "https://hfw.vitap.ac.in:8090/login.xml",
                "campus_endpoint": "https://172.18.10.10:1000"
            }
            # Write default config to file
            with open(self.config_file_path, "w") as config_file:
                json.dump(default_config, config_file, indent=4)
            with open(self.config_file_path, "r") as config_file:
                return json.load(config_file)
        else:
            # Load the existing config
            with open(self.config_file_path, "r") as config_file:
                return json.load(config_file)

class Campus(Base):
    def fetch_magic(self) -> str:
        url = self.config["campus_endpoint"]
        
        # Extract hostname and path
        hostname = url.replace("https://", "").replace("http://", "")
        path = "/login?"

        # Establish a connection with SSL verification disabled
        conn = http.client.HTTPSConnection(hostname, context=ssl._create_unverified_context())
        
        # Make a GET request to the login URL
        conn.request("GET", path)

        # Get the response
        response = conn.getresponse()
        html_content = response.read().decode('utf-8')
        conn.close()

        # Regex to find the 'magic' value in the HTML
        magicRegex = re.compile(r'<input type="hidden" name="magic" value="([^"]+)">')
        match = magicRegex.search(html_content)

        if match:
            return match.group(1)
        else:
            raise ValueError("Magic token not found in the HTML response.")

    def login(self, username=None, password=None, use_csv=False) -> None:
        magic = self.fetch_magic()
        url = self.config["campus_endpoint"]

        # Extract hostname and path
        hostname = url.replace("https://", "").replace("http://", "")
        path = "/login?"

        # If username and password are provided manually, use them
        if username and password:
            creds = [(username, password)]
        elif use_csv:
            # Use CSV file when explicitly requested
            try:
                with open('wifi.csv', mode='r') as file:
                    creds = list(csv.reader(file))
            except FileNotFoundError:
                print("Error: wifi.csv not found!")
                print("Please provide credentials via parameters or update config.json")
                return
        else:
            # Default: Use config credentials
            if self.config["username"] and self.config["password"]:
                creds = [(self.config["username"], self.config["password"])]
            else:
                print("Error: No credentials found in config.json!")
                print("Please provide credentials via parameters, update config.json, or use --csv flag")
                return

        for cred in creds:
            # Prepare POST data
            post_data = urllib.parse.urlencode({
                "4Tredir": "https://172.18.10.10:1000/login?",
                "magic": magic,
                "username": cred[0],
                "password": cred[1]
            })

            headers = {
                "Content-Type": "application/x-www-form-urlencoded"
            }

            # Establish a connection with SSL verification disabled
            conn = http.client.HTTPSConnection(hostname, context=ssl._create_unverified_context())

            # Make a POST request to the login URL
            conn.request("POST", path, body=post_data, headers=headers)

            # Get the response
            response = conn.getresponse()
            response_content = response.read().decode('utf-8')
            conn.close()

            # Check the response for success or failure
            if "https://172.18.10.10:1000/keepalive?" in response_content:
                print(f"Login Successful using {cred[0]}")
                break
            elif "Sorry, user&apos;s concurrent authentication is over limit" in response_content:
                print(f"Concurrent Login while using {cred[0]}")
                continue
            else:
                print(f"Invalid login while using {cred[0]}")
                continue
        else:
            print("-End of iteration-")

    def remove(self) -> None:
        url = self.config["campus_endpoint"]
        
        # Extract hostname and path
        hostname = url.replace("https://", "").replace("http://", "")
        path = "/login?"

        # Open the CSV file and read the credentials
        with open('wifi.csv', mode='r') as file:
            creds = list(csv.reader(file))
        
        creds_copy = creds.copy()

        for cred in creds:
            magic = self.fetch_magic()
            # Prepare POST data
            post_data = urllib.parse.urlencode({
                "4Tredir": "https://172.18.10.10:1000/login?",
                "magic": magic,
                "username": cred[0],
                "password": cred[1]
            })

            headers = {
                "Content-Type": "application/x-www-form-urlencoded"
            }

            # Establish a connection with SSL verification disabled
            conn = http.client.HTTPSConnection(hostname, context=ssl._create_unverified_context())

            # Make a POST request to the login URL
            conn.request("POST", path, body=post_data, headers=headers)

            # Get the response
            response = conn.getresponse()
            response_content = response.read().decode('utf-8')
            conn.close()

            # Check the response for success or failure
            if "https://172.18.10.10:1000/keepalive?" in response_content:
                print(f"Login Successful using {cred}")
                self.logout()
                continue
                #break
            elif "Sorry, user&apos;s concurrent authentication is over limit" in response_content:
                print(f"Concurrent User Login while using {cred}. Skipping!")
                continue
            else:
                print(f"Invalid login while using {cred}. Deleting entry from the list...")
                creds_copy.remove(cred)
                with open('wifi.csv', mode='w') as tmp:
                    csvWriter = csv.writer(tmp)
                    csvWriter.writerows(creds_copy)
                continue
        else:
            print("Reached end of the csv file")


    def logout(self) -> None:
        url = self.config['campus_endpoint']
        
        # Extract hostname and path
        hostname = url.replace("https://", "").replace("http://", "")
        path = "/logout?"

        # Establish a connection
        conn = http.client.HTTPSConnection(hostname, context=ssl._create_unverified_context())

        # Make a GET request to the logout URL
        conn.request("GET", path)

        # Get the response
        response = conn.getresponse()
        html_content = response.read().decode('utf-8')
        #print(html_content)

        if "You have successfully logged out" in html_content:
            print("Logout Successful")

        conn.close()

    def check_logout_event(self):
        # Tries connecting to gstatic connect
        try:
            # Parse the URL
            url = urlparse('http://www.gstatic.com/')  # Example for a captive portal test

            # Create an HTTP connection
            conn = http.client.HTTPConnection(url.netloc, timeout=4)
            
            # Ensure there's a valid path (use "/" if the path is empty)
            path = url.path if url.path else "/"
            
            # Send a GET request
            conn.request("GET", path)
            
            # Get the response
            response = conn.getresponse()
            #print(response.status)

            data = response.read().decode('utf-8')
            #print(data)
            
            if response.status == 200:
                # Use regex to extract the URL within the window.location script
                match = re.search(r'window\.location="([^"]+)"', data)
                full_portal_url = match.group(1) if match else ""
                
                if full_portal_url:
                    # Parse the full URL to extract the base URL
                    parsed_url = urlparse(full_portal_url)
                    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}" + "/login?"  # Extract scheme and netloc
                    print(f'Session expired! Logging in to {base_url}')
                    return True
                else:
                    print("Session expired, unable to find captive portal url. Trying to login anyway...")
                    return True
            elif response.status == 404:
                #print('WAN is up, not logged out!')
                return False
            else:
                #print('WAN is down!')
                return False
            
        except Exception as e:
            print(f'Exception occurred: {str(e)}')
            return False
    
    def generate_headers(self) -> dict:
        pass


class Hostel(Base):
    def __init__(self):
        super().__init__()
        self.user_agent = 'Mozilla/5.0 (Android 13; Mobile; rv:68.0) Gecko/68.0 Firefox/104.0'
        self.product_type = 2  # Mobile client type
    
    def generate_headers(self, uni_host: str, payload_length: int, is_post: bool = False) -> dict:
        """Generate headers for HTTP requests"""
        url_parse = urlparse(uni_host)
        headers = {
            'Host': f'{url_parse.hostname}:{url_parse.port}',
            'User-Agent': self.user_agent,
            'Accept': ' */*',
            'Accept-Language': ' en-US,en;q=0.5',
            'Accept-Encoding': ' gzip, deflate, br',
            'Content-Type': ' application/x-www-form-urlencoded',
            'DNT': ' 1',
            'Connection': ' keep-alive',
            'Referer': uni_host,
            'Sec-Fetch-Dest': ' empty',
            'Sec-Fetch-Mode': ' cors',
            'Sec-Fetch-Site': ' same-origin',
            'Sec-GPC': ' 1'
        }

        if is_post:
            headers['Content-Length'] = str(payload_length)
            headers['Origin'] = uni_host

        return headers
    
    def generate_payload(self, action: str, username: str = None, password: str = None) -> str:
        """Generate payload for hostel WiFi requests"""
        epoch_time = int(time.time() * 1000)
        mode = None
        creds_field = f'username={username or self.config["username"]}'

        if action == 'login':
            mode = '191'
            creds_field += f'&password={password or self.config["password"]}'
        elif action == 'logout':
            mode = '193'
        elif action == 'ack':
            mode = '192'

        payload = f'mode={mode}&{creds_field}&a={epoch_time}&producttype={self.product_type}'
        return payload
    
    def parse_response(self, response_data: str) -> dict:
        """Parse server response and return status information"""
        result = {
            'success': False,
            'message': '',
            'action': 'unknown'
        }
        
        if re.search("Y.+}", response_data):
            result['success'] = True
            result['message'] = 'Login successful'
            result['action'] = 'login'
        elif re.search(";v.+t]", response_data):
            result['success'] = True
            result['message'] = 'Logout successful'
            result['action'] = 'logout'
        elif re.search("<l.+e><ack><!.+k]]", response_data):
            result['success'] = True
            result['message'] = 'Server acknowledgement successful'
            result['action'] = 'ack'
        elif re.search("Invalid.+admin", response_data):
            result['success'] = False
            result['message'] = 'Invalid credentials'
            result['action'] = 'login'
        elif re.search("Y.+max.+limit", response_data):
            result['success'] = False
            result['message'] = 'Maximum devices limit reached'
            result['action'] = 'login'
        else:
            result['message'] = 'Unknown response from server'
            
        return result
    
    def make_request(self, action: str, username: str = None, password: str = None) -> dict:
        """Make HTTP request to hostel WiFi portal"""
        url = self.config["hostel_endpoint"]
        
        # Extract hostname and port
        url_parse = urlparse(url)
        hostname = url_parse.hostname
        port = url_parse.port or (443 if url_parse.scheme == 'https' else 80)
        
        # Generate payload
        payload = self.generate_payload(action, username, password)
        
        # Determine the endpoint path
        if action == 'login':
            path = '/login.xml'
        elif action == 'logout':
            path = '/logout.xml'
        else:
            path = '/live'
        
        # Generate headers
        headers = self.generate_headers(url, len(payload), True)
        
        # Create connection
        conn = http.client.HTTPSConnection(
            hostname,
            port,
            context=ssl._create_unverified_context(),
            timeout=10
        )
        
        response_data = ""
        result = {'success': False, 'message': 'Connection failed', 'action': action}
        
        try:
            # Make the request
            conn.request('POST', path, body=payload, headers=headers)
            response = conn.getresponse()
            response_data = response.read().decode('UTF-8')
            
            # Parse the response
            result = self.parse_response(response_data)
            
        except Exception as e:
            result['message'] = f'Request failed: {str(e)}'
        finally:
            conn.close()
            
        return result

    def login(self, username: str = None, password: str = None, use_csv: bool = False) -> None:
        """Login to hostel WiFi"""
        # If username and password are provided manually, use them
        if username and password:
            user = username
            pwd = password
        elif use_csv:
            # Use CSV file when explicitly requested          
            try:
                with open('wifi.csv', mode='r') as file:
                    creds = list(csv.reader(file))
                    if not creds:
                        print("Error: wifi.csv is empty!")
                        return
            except FileNotFoundError:
                print("Error: wifi.csv not found!")
                print("Please provide credentials via parameters or update config.json")
                return
            
            # Try each credential until one succeeds
            for cred in creds:
                if len(cred) < 2:
                    print(f"Skipping invalid credential entry: {cred}")
                    continue
                
                user = cred[0]
                pwd = cred[1]
                
                print(f"Attempting to login with username: {user}")
                
                # Make login request
                result = self.make_request('login', user, pwd)
                
                if result['success']:
                    print(f"[SUCCESS] {result['message']} using {user}")
                    return
                else:
                    print(f"[ERROR] Login failed for {user}: {result['message']}")
                    continue
            
            # If we reach here, all credentials failed
            print("All credentials in CSV file failed")
            return
        else:
            # Default: Use config credentials
            user = self.config["username"]
            pwd = self.config["password"]
            
        if not user or not pwd:
            print("Error: Username and password are required!")
            print("Please provide credentials via parameters, update config.json, or use --csv flag")
            return
        
        print(f"Attempting to login with username: {user}")
        
        # Make login request
        result = self.make_request('login', user, pwd)
        
        if result['success']:
            print(f"[SUCCESS] {result['message']}")
        else:
            print(f"[ERROR] Login failed: {result['message']}")
    
    def logout(self) -> None:
        """Logout from hostel WiFi"""
        print("Attempting to logout...")
        
        # Make logout request
        result = self.make_request('logout')
        
        if result['success']:
            print(f"[SUCCESS] {result['message']}")
        else:
            print(f"[ERROR] Logout failed: {result['message']}")
    
    def check_connection(self) -> bool:
        """Check if internet connection is available"""
        try:
            response = urllib.request.urlopen('http://connectivitycheck.gstatic.com/generate_204', timeout=5)
            return response.getcode() == 204
        except Exception:
            return False
    
    def auto_login(self, username: str = None, password: str = None, use_csv: bool = False) -> None:
        """Auto re-login on session expiry"""
        print("Starting auto-login mode...")
        print("Press Ctrl+C to stop")
        
        try:
            while True:
                if not self.check_connection():
                    print("Connection lost, attempting to login...")
                    self.login(username, password, use_csv)
                
                time.sleep(30)  # Check every 30 seconds
                
        except KeyboardInterrupt:
            print("\nAuto-login stopped by user")
        except Exception as e:
            print(f"Auto-login error: {e}")


def parse_args() -> dict:
    ap = argparse.ArgumentParser(description="A command line utility to login and logout from VITAP's Campus and Hostel Wifi")

    # Add hostel flag as a separate argument (not mutually exclusive)
    ap.add_argument("--hostel", action="store_true", help="use hostel WiFi instead of campus")
    ap.add_argument("--csv", action="store_true", help="use credentials from wifi.csv file")

    group = ap.add_mutually_exclusive_group(required=False)
    group.add_argument("--login", action="store_true", help="attempt login")
    group.add_argument("--logout", action="store_true", help="attempt logout")
    group.add_argument("--auto", action="store_true", help="auto re-login on session expiry")
    group.add_argument("--remove", action="store_true", help="remove invalid entries from csv (campus only)")
    group.add_argument("--manual", nargs=2, metavar=("USERNAME", "PASSWORD"), help="login using provided credentials")

    return vars(ap.parse_args())

if __name__ == "__main__":

    args = parse_args()
    
    # Determine if we're using hostel or campus WiFi
    if args.get('hostel'):
        wifi_client = Hostel()
        wifi_type = "Hostel"
    else:
        wifi_client = Campus()
        wifi_type = "Campus"

    if args['login']:
        wifi_client.login(use_csv=args.get('csv', False))
    elif args['logout']:
        wifi_client.logout()
    elif args['auto']:
        if hasattr(wifi_client, 'auto_login'):
            wifi_client.auto_login(use_csv=args.get('csv', False))
        else:
            print("Running as a loop to auto re-login on session expiry...")
            while True:
                if wifi_client.check_logout_event():
                    wifi_client.login(use_csv=args.get('csv', False))
                time.sleep(60)
    elif args['remove']:
        if hasattr(wifi_client, 'remove'):
            print("Removing invalid creds from the csv file...")
            wifi_client.remove()
        else:
            print("Remove function is only available for Campus WiFi")
    elif args['manual']:
        username, password = args['manual']
        wifi_client.login(username, password, use_csv=False)  # Manual override ignores CSV
    else:
        # Interactive menu loop
        use_csv = args.get('csv', False)
        while True:
            if wifi_type == "Campus":
                print(r"""                  
  ______         _   _             _       
 |  ____|       | | (_)           | |      
 | |__ ___  _ __| |_ _  __ _  __ _| |_ ___ 
 |  __/ _ \| '__| __| |/ _` |/ _` | __/ _ \
 | | | (_) | |  | |_| | (_| | (_| | ||  __/
 |_|  \___/|_|   \__|_|\__, |\__,_|\__\___|
                        __/ |              
                       |___/              
                """)
            else:
                print(r"""                
   _____             _               
  / ____|           | |              
 | (___   ___  _ __ | |__   ___  ___ 
  \___ \ / _ \| '_ \| '_ \ / _ \/ __|
  ____) | (_) | |_) | | | | (_) \__ \
 |_____/ \___/| .__/|_| |_|\___/|___/
              | |                    
              |_|                                                                   
                """)
            print(f"\n{wifi_type} Automated Wifi Login")
            print("1. Login")
            print("2. Logout")
            print("3. Automatic Mode (keep re-logging on session expiry)")
            print("4. Remove invalid entries from the csv")
            print("5. Enter Manual Login Credentials")

            if use_csv:
                print("\033[92m6. Toggle CSV file [ENABLED]\033[0m")
            else:
                print("\033[91m6. Toggle CSV file [DISABLED]\033[0m")

            if wifi_type == "Campus":
                print("7. Switch to Hostel WiFi")
                print("8. Exit")
            else:
                print("7. Switch to Campus WiFi")
                print("8. Exit")

            choice = int(input("Enter your choice (1/2/3/4/5/6/7/8): "))

            if choice == 1:
                wifi_client.login(use_csv=use_csv)  # Default: use config.json
                break
            elif choice == 2:
                wifi_client.logout()
                break
            elif choice == 3:
                if hasattr(wifi_client, 'auto_login'):
                    wifi_client.auto_login(use_csv=use_csv)  # Default: use config.json
                else:
                    print("Running a loop to auto re-login on session expiry...")
                    while True:
                        if wifi_client.check_logout_event():
                            wifi_client.login(use_csv=use_csv)  # Default: use config.json
                        time.sleep(60)
                break
            elif choice == 4:
                if wifi_type == "Campus":
                    print("Removing invalid creds from the csv file...")
                    wifi_client.remove()
                else:
                    print("Remove function is only available for Campus WiFi")
                break
            elif choice == 5:
                username = input("Enter username: ")
                password = input("Enter password: ")
                wifi_client.login(username, password, use_csv=False)  # Manual override
                break
            elif choice == 6:
                if not use_csv:
                    print("Using CSV file for login...")
                    use_csv = True
                else:
                    print("Not using CSV file for login.")
                    use_csv = False
                continue  # Continue the loop to show the updated menu
                    
            elif choice == 7:
                if wifi_type == "Campus":
                    print("Switching to Hostel WiFi...")
                    wifi_client = Hostel()
                    wifi_type = "Hostel"
                else:
                    print("Switching to Campus WiFi...")
                    wifi_client = Campus()
                    wifi_type = "Campus"
                continue # Continue the loop to show the updated menu
            else:
                print("arigato <3 hara")
                break  # Exit the loop