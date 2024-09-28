import json
import os
from typing import TypedDict
from abc import ABC, abstractmethod
import re
import csv
import argparse
import http.client
import urllib.parse
import ssl

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
        
        # Extract hostname and path
        hostname = url.replace("https://", "").replace("http://", "")
        path = "/login?"

        # Open the CSV file and read the credentials
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
                print(f"Login Successful using {cred}")
                break
            elif "Sorry, user&apos;s concurrent authentication is over limit" in response_content:
                print(f"Concurrent Login while using {cred}")
                continue
            else:
                print(f"Invalid login while using {cred}")
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

    def generate_headers() -> dict:
        pass

def parse_args() -> dict:
    ap = argparse.ArgumentParser(description="A command line utility to login and logout from VITAP's hostel and campus wifi")

    group = ap.add_mutually_exclusive_group(required=False)
    group.add_argument("--login", action="store_true", help="attempt login")
    group.add_argument("--logout", action="store_true", help="attempt logout")
    
    return vars(ap.parse_args())

def main() -> None:
    
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
        elif choice == 2:
            campus.logout()
        else:
            print("arigato <3")

if __name__ == "__main__":
    main()