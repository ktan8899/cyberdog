# Cyberdog:

Your trusty companion, here to assist you in the reconnaissance of a target box or IP address. This is an entry level script designed to automate the reconnaissance stage of penetration testing.
It's intended use is for fun or to learn!

# How to use:

- Cyberdog is meant to be easy and intuitive, utilizing built in Kali Linux scans to help the user

- Go to the main directory of the repository and download the cyberdog.py file
- Open a terminal and unzip the downloaded file
- Run the ifconfig command to determine the IP address of the target box you'd like to perform reconnaissance on
- Use the 'python3' command to run the downloaded cyberdog.py script

# Usage:

- Cyberdog utilizes scans that may require root privileges, meaning you would have to add 'sudo' to the beginning of your python3 command when running the script and enter your credentials
- The script creates a directory titled 'individual_scans' in which you may find the results of each scan before they are parsed for information
- The 'report.txt' file parses each of the individual scans and returns valuable data you may find useful for enumeration
- Both the 'individual_scans' and the 'report.txt' are replaced with each use of Cyberdog, make sure to move them if you need to use the script again
