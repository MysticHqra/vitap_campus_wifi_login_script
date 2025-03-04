import json
import os
from typing import TypedDict
from abc import ABC, abstractmethod
import re
import csv
import argparse
import http.client
import urllib
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

    def login(self, username=None, password=None) -> None:
        magic = self.fetch_magic()
        url = self.config["campus_endpoint"]

        # Extract hostname and path
        hostname = url.replace("https://", "").replace("http://", "")
        path = "/login?"

        # If username and password are provided manually, use them
        if username and password:
            creds = [(username, password)]
        else:
            # Otherwise, read from the CSV file
            with open('wifi.csv', mode='r') as file:
                creds = list(csv.reader(file))

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

def parse_args() -> dict:
    ap = argparse.ArgumentParser(description="A command line utility to login and logout from VITAP's Campus Wifi")

    group = ap.add_mutually_exclusive_group(required=False)
    group.add_argument("--login", action="store_true", help="attempt login")
    group.add_argument("--logout", action="store_true", help="attempt logout")
    group.add_argument("--auto", action="store_true", help="auto re-login on session expiry")
    group.add_argument("--remove", action="store_true", help="remove invalid entries from csv")
    group.add_argument("--manual", nargs=2, metavar=("USERNAME", "PASSWORD"), help="login using provided credentials")

    return vars(ap.parse_args())

if __name__ == "__main__":

    args = parse_args()
    campus = Campus()

    if args['login']:
        campus.login()
    elif args['logout']:
        campus.logout()
    elif args['auto']:
        print("Running as a loop to auto re-login on session expiry...")
        while True:
            if campus.check_logout_event():
                campus.login()
            time.sleep(60)
    elif args['remove']:
        print("Removing invalid creds from the csv file...")
        campus.remove()
    elif args['manual']:
        username, password = args['manual']
        campus.login(username, password)
    else:
        print("Campus Automated Wifi Login")
        print("1. Login")
        print("2. Logout")
        print("3. Auto login (Runs in Background)")
        print("4. Remove invalid entries from the csv")
        print("5. Manual Login")
        choice = int(input("Enter your choice (1/2/3/4/5): "))
        if choice == 1:
            campus.login()
        elif choice == 2:
            campus.logout()
        elif choice == 3:
            print("Running a loop to auto re-login on session expiry...")
            while True:
                if campus.check_logout_event():
                    campus.login()
                time.sleep(60)
        elif choice == 4:
            print("Removing invalid creds from the csv file...")
            campus.remove()
        elif choice == 5:
            username = input("Enter username: ")
            password = input("Enter password: ")
            campus.login(username, password)
        else:
            print("arigato <3 hara")