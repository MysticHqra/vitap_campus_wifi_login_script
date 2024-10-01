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
        if self.config["username"] or self.config["password"] == "":
            print(f"Please update {self.config_file_path} with your username and password.")
            exit(1)  # Exit after creating the config file
    
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
            print(f"Please update {self.config_file_path} with your username and password.")
            exit(1)  # Exit after creating the config file
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

    def login(self) -> None:
        magic = self.fetch_magic()
        url = self.config["campus_endpoint"]
        cred = [self.config["username"],self.config["password"]]
        
        # Extract hostname and path
        hostname = url.replace("https://", "").replace("http://", "")
        path = "/login?"

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
            
        elif "Sorry, user&apos;s concurrent authentication is over limit" in response_content:
            print(f"Concurrent Login while using {cred}")
            
        else:
            print(f"Invalid login while using {cred}")


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
    ap = argparse.ArgumentParser(description="A command line utility to login and logout from VITAP's hostel and campus wifi")

    group = ap.add_mutually_exclusive_group(required=False)
    group.add_argument("--login", action="store_true", help="attempt login")
    group.add_argument("--logout", action="store_true", help="attempt logout")
    
    return vars(ap.parse_args())

if __name__ == "__main__":

    args = parse_args()
    campus = Campus()

    if args['login']:
        campus.login()
    elif args['logout']:
        campus.logout()
    else:
        print("Campus Automated Wifi Login")
        print("1. Login")
        print("2. Logout")
        choice = int(input("Enter your choice (1/2): "))
        if choice == 1:
            campus.login()
            print("Running in background for auto relogin in case of sesion expiry...")
            while True:
                if campus.check_logout_event() == True:
                    campus.login()
                time.sleep(60)
        elif choice == 2:
            campus.logout()
        else:
            print("arigato <3")