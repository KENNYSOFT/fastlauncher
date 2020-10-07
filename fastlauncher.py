# Run pyinstaller -F fastlauncher.py to package it
# Made out of garbage in a short amount of time

import requests
import subprocess
import hashlib
import keyring
import json
import getpass
import ctypes
import sys
import zlib
import base64
import os
import secrets
import tkinter as tk
from tkinter import filedialog

yes = {'yes','y', 'ye', ''}
no = {'no','n'}

YES_NO_SUFFIX = '[Y/n]'

CLIENT_ID = "7853644408"
SCOPE = "us.launcher.all"
AUTO_LOGIN = False
CAPTCHA_TOKEN = "0xDEADBEEF"
PRODUCT_ID = "10100"
REMEMBER_ME = True

WEBAPI_BASE_URL = "https://www.nexon.com/account-webapi/"
API_NEXON_BASE_URL = "https://api.nexon.io/"
NXL_DOWNLOAD_BASE_URL = "https://download2.nexon.net/Game/nxl/games"

NXL_DOWNLOAD_URL = NXL_DOWNLOAD_BASE_URL + "/" + PRODUCT_ID
NXL_DOWNLOAD_PARTS_URL = NXL_DOWNLOAD_URL + "/" + PRODUCT_ID
METADATA_URL = API_NEXON_BASE_URL + "game-info/v2/games/" + PRODUCT_ID
MANIFEST_HASH_URL = METADATA_URL + "/branch/public" 
PLAYABLE_URL = API_NEXON_BASE_URL + "game-auth/v2/check-playable"
PASSPORT_URL = API_NEXON_BASE_URL + "passport/v1/passport"

LOGIN_URL = WEBAPI_BASE_URL + "login/launcher"
VERIFY_URL = WEBAPI_BASE_URL + "trusted_devices"

LAUNCHER_NAME = "fastlauncher"
VER = "0.1.0-GMSDL"
CODENAME = "SECRET"

CONFIGURATION_PATH = os.environ['APPDATA']  + '\\' + LAUNCHER_NAME + '\\configuration.json'

def query_yes_no(question, default="yes"):

    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")

class login_instance(object):

    def __init__(self):
        
        self.device_id = None
        self.id_token = None
        self.access_token = None
        self.manifest_url = None
    
    def login(self, username=None, hashed_password=None, device_id=None):
        
        logged_in = False
        self.username = username
        self.device_id = device_id

        # Log in attempt
        login_response = self.get_login_response(hashed_password)

        login_response_json = json.loads(login_response.text)

        # If code 400, something extra is needed or has gone wrong
        if not login_response.ok:

            code = login_response_json["code"]
            message = login_response_json["message"]
            print(message)
            # print(code)
            # print(login_response_json)
            # If user does not exist or password doesn't exist, reprompt 
            if code == "NOT_EXIST_USER":
                return 1
            elif code == "WRONG_PASSWORD":
                return 2
            # If Nexon recognizes a new device and needs verification
            elif code == "TRUST_DEVICE_REQUIRED":
                return 3


            # TODO: This is a reset mode
            #elif response.code == "PROTECTED_USER_N_MODE":

            # TODO: Add authenticator mode

            # Break if unhandled error
            else:
                return 5
        else:
            logged_in = True
            self.id_token = login_response_json["id_token"]
            self.access_token = login_response_json['access_token']
            return 0

    def get_login_response(self, password):
        """
        Post and get the login response which includes the id_token and access_token.
        """
        
        # Construct headers
        headers = {
            "Content-Type" : "application/json"
        }

        # Construct json
        json_dict = {
            "id" : self.username,
            "password" : password,
            "auto_login" : AUTO_LOGIN,
            "client_id" : CLIENT_ID,
            "scope" : SCOPE,
            "device_id" : self.device_id,
            "captcha_token" : CAPTCHA_TOKEN
        }

        response = requests.post(LOGIN_URL, json=json_dict, headers=headers)

        return response

    def get_verify_device_response(self, verification_code):
        """
        Put the verification code from email
        """

        # Construct headers
        headers = {
            "Content-Type" : "application/json"
        }


        # Construct json
        json_dict = {
            "email" : self.username,
            "verification_code" : verification_code,
            "device_id" : self.device_id,
            "remember_me" : REMEMBER_ME
        }

        response = requests.put(VERIFY_URL, json=json_dict, headers=headers)

        return response
    
    def get_manifest_hash_url_response(self):
        
        # Construct headers
        headers = {
            "Content-Type" : "application/json",
            "Authorization" : "Bearer {access_token}".format(access_token=self.access_token)
        }
        
        response = requests.get(MANIFEST_HASH_URL, headers=headers)
        
        return response

class launcher(object):
    
    def __init__(self):
        
        self.main()
        
    def main(self, user_configuration_path=None):
        # Set up tkinter for file diaglogues
        root = tk.Tk()
        root.withdraw()
        
        print(LAUNCHER_NAME + ' v' + VER + ' \"' + CODENAME + '\"')
                  
        self.configuration = None
              
        if os.path.exists(CONFIGURATION_PATH):
            print("Loading configuration...")
            self.configuration = self.read_configuration(CONFIGURATION_PATH)
        else:
        #Check for configuration data
            print("Checking for configuration file...")
            if not os.path.exists(CONFIGURATION_PATH):
                print("No configuration file found")
                if query_yes_no("Import a configuration file?", default="no"):
                    import_configuration_path = filedialog.askopenfilename()
                    if import_configuration_path:
                        self.configuration = self.read_configuration(CONFIGURATION_PATH)

                print("Creating configuration file...")
                self.create_configuration()
            else:
                self.configuration = self.read_configuration(CONFIGURATION_PATH)
        if not self.configuration['users']:
            print("Creating first user")
            self.create_user_profile(first_user=True)
        self.menu()

    def menu(self):
        in_menu = True
        while in_menu:
            print("Please press the number for the account to login or letter for other options, then press enter")
            user_dictionary = self.list_users()
            print("C - new account, U - update password, D - delete account, E - exit")
            user_input = input("Your selection: ").lower()
            if user_input == "c":
                self.create_user_profile()
            elif user_input == "u":
                changing_password = True
                while changing_password:
                    print("Please press the number for the account to update password or press R to return, then press enter")
                    user_dictionary = self.list_users()
                    user_input = input("Your selection: ").lower()
                    if user_input == "r":
                        changing_password = False
                    elif user_input in user_dictionary.keys():
                        self.change_password(user_dictionary[user_input])
                        changing_password = False
                    else:
                        print(user_input + " is not a valid input, please try again")
            elif user_input == "d":
                deleting_user = True
                while deleting_user:
                    print("Please press the number for the account to delete or press R to return, then press enter")
                    user_dictionary = self.list_users()
                    user_input = input("Your selection: ").lower()
                    if user_input == "r":
                        deleting_user = False
                    elif user_input in user_dictionary.keys():
                        self.delete_user(user_dictionary[user_input])
                        deleting_user = False
                    else:
                        print(user_input + " is not a valid input, please try again")
            elif user_input == "e":
                sys.exit()
            elif user_input in user_dictionary.keys():
                hashed_username = user_dictionary[user_input]
                self.login_and_launch(self.configuration['users'][hashed_username]['username'], self.configuration['users'][hashed_username]['hashed_password'], self.configuration['users'][hashed_username]['device_id'])
            else:
                print(user_input + " is not a valid input, please try again")

    def list_users(self):
        selection_dictionary = {}
        listed_count = 1
        for hashed_username in self.configuration['users'].keys():
            selection_dictionary[str(listed_count)] = hashed_username
            print(str(listed_count) + ': ' + self.configuration['users'][hashed_username]['username'])
            listed_count += 1
        return selection_dictionary
    
    def login_and_launch(self, username, hashed_password, device_id):
        instance = login_instance()
        logged_in = False
        update_config = False
        while not logged_in:
            login_attempt = instance.login(username=username, hashed_password=hashed_password, device_id=device_id)
            if login_attempt == 0:
                logged_in = True
                print(json.loads(instance.get_manifest_hash_url_response().text)["manifestUrl"])
            elif login_attempt == 1:
                username = input("Username : ")
                instance.login(username, hashed_password, device_id)
                update_config = True
            elif login_attempt == 2:
                hashed_password = hashlib.sha512(getpass.getpass(prompt="Password : ").encode('utf-8')).hexdigest()
                instance.login(username, hashed_password, device_id)
                update_config = True
            elif login_attempt == 3:
                device_verified = False
                while not device_verified:
                    # Get user input for verification code
                    verification_code = input("Verification Code : ")
                    # Get verification response:
                    verify_response = instance.get_verify_device_response(verification_code)
                    if verify_response.ok:
                        device_verified = True
                    else:
                        print(json.loads(verify_response.text)["message"])
            else:
                if not query_yes_no("Launch failed, try again?"):
                    return False
        return True

    def generate_real_device_id(self):
        # Retrieve uuid and machineguid
        uuid_raw = subprocess.Popen(["wmic.exe", "csproduct", "get", "uuid"], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.readlines()
        machineguid_raw = subprocess.Popen(["reg.exe", "query", "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.readlines()
        # Decode stdout with UTF8 and strip spaces and newlines
        uuid = uuid_raw[1].decode('utf-8').split()[0]
        machineguid = machineguid_raw[2].decode('utf-8').split()[2]
        # Join uuid and machineguid to create the raw string version of device_id
        device_id_raw = uuid + machineguid
        # Compute sha256 of the raw string version device_id (outputs string)
        device_id = hashlib.sha256(device_id_raw.encode('utf-8')).hexdigest()
        return device_id

    def generate_fake_device_id(self):
        #Generate 64 length device id
        return secrets.token_hex(32)

    def read_configuration(self, config_path):
        data = None
        with open(config_path) as config_file:
            data = json.load(config_file)
        return data

    def create_configuration(self):
        self.configuration = {'users' : {}}
        self.flush_to_configuration_file()

    def create_user_profile(self, first_user=False):
        print("Creating user...")
        username = input("Username : ")
        if not hashlib.sha512(username.encode('utf-8')).hexdigest() in self.configuration['users']:
            hashed_password = hashlib.sha512(getpass.getpass(prompt="Password : ").encode('utf-8')).hexdigest()
            device_id = None
            force_default_device_id = 'yes'
            if first_user:
                force_default_device_id = 'no'
            if query_yes_no("Fake device id?", default=force_default_device_id):
                device_id = self.generate_fake_device_id()
            else:
                device_id = self.generate_real_device_id()
            self.configuration['users'][hashlib.sha512(username.encode('utf-8')).hexdigest()] = {'username' : username, 'hashed_password' : hashed_password, 'device_id' : device_id}
            self.flush_to_configuration_file()
        else:
            print("User already exists!")
    
    def delete_user(self, hashed_username):
        del self.configuration['users'][hashed_username]
        self.flush_to_configuration_file()

    def change_password(self, hashed_username):
        print("Changing stored password for " + self.configuration['users'][hashed_username]['username'])
        hashed_password = hashlib.sha512(getpass.getpass(prompt="Password : ").encode('utf-8')).hexdigest()
        self.configuration['users'][hashed_username]['hashed_password'] = hashed_password
        self.flush_to_configuration_file()

    def flush_to_configuration_file(self, config_path=CONFIGURATION_PATH):
        if not os.path.exists(config_path):
            os.makedirs(os.path.split(config_path)[0])
        with open(config_path, 'w', encoding='utf-8') as config_file:
            json.dump(self.configuration, config_file)

if __name__ == "__main__":
    launcher()