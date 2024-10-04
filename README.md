# VIT-AP Campus Wifi Automation
## (~~Automate the Boring Stuff with Python~~)

A python script to automate the wifi login for VIT-AP's campus's wifi. (works in MH-5 too for now)

## Features
1. Login and Logout from the wifi seamlessly without having to go through the captive portal.
2. Automate the same for a list of credentials by using a csv file. **(wifi.csv)**
3. Headless Mode -> Enables auto re-login by detecting session expiry. **(Requires you to run the script in the background)**

## Requirements
- python 3.x (duh)

## Installation

> **Note:** if you are going to copy paste the commands, dont copy the `$` symbol, it is just a convention. (Have to include these nowadays)

1. Clone this repository.
2. `$ cd wifi_login_script`

## Usage
```
campus_wifi.py [-h | --help]
campus_wifi_csv.py [-h | --help]

A command line utility to login and logout from VITAP's Campus Wifi

options:
  -h, --help  show this help message and exit
  --login     attempt login
  --logout    attempt logout
  --auto      auto re-login on session expiry
```

## Examples

> **Note:** If you're on linux, you might want to use `python3` instead of `python` in these examples.

```bash
$ python campus_wifi.py #Interactive Mode
$ python campus_wifi.py --login #Directly login to the wifi.
$ python campus_wifi.py --logout #Directly logout from the wifi.
$ python campus_wifi.py --auto #Headless mode; auto login when required and manages session expiry events.

$ python campus_wifi_csv.py #Interactive Mode
$ python campus_wifi_csv.py --login #Directly login using the wifi.csv file.
$ python campus_wifi_csv.py --logout #Directly logout from the wifi.
$ python campus_wifi_csv.py --auto #Headless mode; auto login when required and manages session expiry events.
```
## Help Section
**If you use campus_wifi.py for logging in, then you need to set your username and password in the config.json file.**
> **Note:** The endpoints defined in the config.json file are the default endpoints for the hostel and campus wifi. If the endpoints are changed, you ~~should be smart enough to figure it out~~ can find the new endpoints by inspecting the network requests in the browser's developer tools.

**If you use the campus_wifi_csv.py for logging in, then you need to create a wifi.csv file containing the credentials that you want the script to use for logging in.**

## Example for wifi.csv file:
```
username1, password1
username2, password2
username3, password3
```