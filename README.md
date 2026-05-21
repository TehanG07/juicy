# juicy
secret.py is a tool designed to analyze JavaScript files and detect sensitive information such as API keys, credentials, tokens, and other secrets that might have been accidentally exposed in the code. This tool can be useful for security researchers, bug bounty hunters, and developers to prevent the leakage of sensitive information.
# requiremnets
pip3 install pywhatkit regex



pip3 install detect-secrets trufflehog pywhat

# Activate your existing myenv virtual environment
source ~/myenv/bin/activate

# Install the required modules inside the active environment
pip install selenium webdriver-manager tqdm

sudo apt update
sudo apt install google-chrome-stable -y
