# VIT-AP Campus & Hostel Wifi Automation
## (~~Automate the Boring Stuff with Python~~)

A python script to automate the wifi login for VIT-AP's campus and hostel wifi. (Fortigate & Sophos)

## Features
1. Supports both Fortigate & Sophos Captive Login Portals.
2. Login and Logout from the wifi seamlessly without having to go through the captive portal.
3. Automate the same for a list of credentials by using a csv file. **(wifi.csv)**
4. Background Mode -> Enables auto re-login by detecting session expiry. **(Requires you to run the script in the background)**
5. Remove invalid -> Deletes invalid login credentials from the csv file.
6. Manual -> Takes username and password as inputs for logging in directly without using the csv file.

## Requirements
- python 3.x (duh)

## Installation

> **Note:** if you are going to copy paste the commands, dont copy the `$` symbol, it is just a convention. (Have to include these nowadays)

1. Clone this repository.
2. `$ cd wifi_login_script`

## Usage
```
wifi_automation.py [-h | --help]

A command line utility to login and logout from VITAP's Campus & Hostel Wifi

options:
  -h, --help  show this help message and exit
  --hostel    if firewall is sophos instead of fortigate
  --login     attempt login
  --logout    attempt logout
  --auto      auto re-login on session expiry
  --remove    remove invalid entries from csv
  --manual    login using provided credentials
  --csv       use the wifi.csv file
```

## Examples

> **Note:** If you're on linux, you might want to use `python3` instead of `python` in these examples.
```bash
$ python wifi_automation.py #Interactive Mode
```
Arguments for Fortigate Firewall:
```bash
$ python wifi_automation.py --login #Directly login to the wifi.
$ python wifi_automation.py --logout #Directly logout from the wifi.
$ python wifi_automation.py --auto #Headless mode; auto login when required and manages session expiry events.
```
Arguments for Sophos Firewall:
```bash
$ python wifi_automation.py --hostel --login #Directly login using the wifi.csv file.
$ python wifi_automation.py --hostel --logout #Directly logout from the wifi.
$ python wifi_automation.py --hostel --auto #Headless mode; auto login when required and manages session expiry events.
```
Arguments for using wifi.csv (--csv):
```bash
$ python wifi_automation.py --login --csv
$ python wifi_automation.py --hostel --login --csv
```
## Help Section
**If you use campus_wifi.py for logging in, then you need to set your username and password in the config.json file.**
> **Note:** The endpoints defined in the config.json file are the default endpoints for the hostel and campus wifi. If the endpoints are changed, you ~~should be smart enough to figure it out~~ can find the new endpoints by inspecting the network requests in the browser's developer tools.

**If you want to use csv for logging in, then you need to create a wifi.csv file containing the credentials that you want the script to use for logging in.**

## Example for wifi.csv file:
```
username1, password1
username2, password2
username3, password3
```