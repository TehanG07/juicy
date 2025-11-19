#!/usr/bin/env python3
"""
Secret-Killer v2.0
Author: TehanG07 (cybereye) — improved version
Multi-Engine Sensitive Info Scanner for URLs / local JS/JSON files
"""

import re
import os
import sys
import json
import time
import argparse
import requests
import logging
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any

# Optional imports
try:
    from detect_secrets.core.scan import scan_file as ds_scan_file
except Exception:
    ds_scan_file = None

# ------- Configuration -------
REQUEST_TIMEOUT = 12
MAX_WORKERS = 8
USER_AGENT = "Mozilla/5.0 (Secret-Killer/2.0)"
OUTPUT_TEXT = "secret-killer_results.txt"
OUTPUT_JSON = "secret-killer_results.json"

# ------- Logging -------
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

# ------- Patterns -------
# Basic identifiers
PATTERNS = {
    "Username": re.compile(r'["\']?(?:username|user_name|user|usr|account)["\']?\s*[:=]\s*["\']?([A-Za-z0-9._-]{3,64})["\']?', re.I),
    "Email": re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'),
    # Mobile: generic + Indian numbers (10 digits, optional +91, separators)
    "Phone": re.compile(r'(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{6,12}'),
    # DB credentials common keys
    "DB_User": re.compile(r'["\']?(?:db[_-]?user|dbuser|database[_-]?user|username)["\']?\s*[:=]\s*["\']([^"\']{1,80})["\']?', re.I),
    "DB_Pass": re.compile(r'["\']?(?:db[_-]?pass|db[_-]?password|database[_-]?password|passwd)["\']?\s*[:=]\s*["\']([^"\']{1,200})["\']?', re.I),
    # SMTP/FTP
    "SMTP_User": re.compile(r'["\']?(?:smtp[_-]?user|ftp[_-]?user|mail_user)["\']?\s*[:=]\s*["\']([^"\']+)["\']?', re.I),
    "SMTP_Pass": re.compile(r'["\']?(?:smtp[_-]?pass|ftp[_-]?pass|mail_pass)["\']?\s*[:=]\s*["\']([^"\']+)["\']?', re.I),
}

# Tokens & keys (a curated set of common formats)
TOKEN_PATTERNS = {
    "JWT": re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9._-]{10,}\.[a-zA-Z0-9._-]{10,}'),
    "AWS_AccessKey": re.compile(r'AKIA[0-9A-Z]{16}'),
    "AWS_SecretKey": re.compile(r'(?i)aws_secret_access_key["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40,})["\']?'),
    "Google_API_Key": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    "Stripe_Key": re.compile(r'sk_live_[0-9a-zA-Z]{24,}|' r'sk_test_[0-9a-zA-Z]{24,}'),
    "Slack_Token": re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,}'),
    "Firebase_API_Key": re.compile(r'["\']?apiKey["\']?\s*[:=]\s*["\']([A-Za-z0-9:\-_]{20,40})["\']', re.I),
    "Firebase_Config": re.compile(r'firebase(?:Config)?\s*[:=]\s*\{', re.I),
    "BasicAuth": re.compile(r'["\']?[A-Za-z0-9._%+-]+:[^\s"\'@]{1,80}["\']?'),  # may produce false positives
    "Bearer": re.compile(r'Bearer\s+[A-Za-z0-9\-\._~\+/]+=*'),
    "GenericToken": re.compile(r'["\']?(?:token|access[_-]?token|auth[_-]?token|secret|api[_-]?key|client[_-]?secret)["\']?\s*[:=]\s*["\']([A-Za-z0-9\-\._~\+/=]{8,200})["\']?', re.I),
    
    # Additional API Keys and Secrets
    "ABTasty_API_Key": re.compile(r'abt_[A-Za-z0-9]{32}', re.I),
    "Algolia_API_Key": re.compile(r'["\']?(?:algolia[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "Amplitude_API_Key": re.compile(r'["\']?(?:amplitude[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\']([a-f0-9]{32})["\']', re.I),
    "Asana_Access_Token": re.compile(r'["\']?(?:asana[_-]?access[_-]?token|access[_-]?token)["\']?\s*[:=]\s*["\']([0-9]/[a-f0-9]{16})["\']', re.I),
    "Azure_Application_Insights_APP_ID": re.compile(r'["\']?(?:azure[_-]?app[_-]?id|app[_-]?id)["\']?\s*[:=]\s*["\']([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["\']', re.I),
    "Azure_Application_Insights_API_Key": re.compile(r'["\']?(?:azure[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\']([a-f0-9]{32})["\']', re.I),
    "Bazaarvoice_Passkey": re.compile(r'["\']?(?:bazaarvoice[_-]?passkey|passkey)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{16})["\']', re.I),
    "Bing_Maps_API_Key": re.compile(r'["\']?(?:bing[_-]?maps[_-]?api[_-]?key|maps[_-]?api[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{32})["\']', re.I),
    "Bitly_Access_Token": re.compile(r'["\']?(?:bit\.ly[_-]?access[_-]?token|access[_-]?token)["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{32})["\']', re.I),
    "Branchio_Key": re.compile(r'["\']?(?:branch\.io[_-]?key|key[_-]?live|key[_-]?test)["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{32})["\']', re.I),
    "Branchio_Secret": re.compile(r'["\']?(?:branch\.io[_-]?secret|secret[_-]?live|secret[_-]?test)["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{32})["\']', re.I),
    "BrowserStack_Access_Key": re.compile(r'["\']?(?:browserstack[_-]?access[_-]?key|access[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{20})["\']', re.I),
    "Buildkite_Access_Token": re.compile(r'["\']?(?:buildkite[_-]?access[_-]?token|access[_-]?token)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{20})["\']', re.I),
    "ButterCMS_API_Key": re.compile(r'["\']?(?:buttercms[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "Calendly_API_Key": re.compile(r'["\']?(?:calendly[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "Contentful_Access_Token": re.compile(r'["\']?(?:contentful[_-]?access[_-]?token|access[_-]?token)["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{43})["\']', re.I),
    "CircleCI_Access_Token": re.compile(r'["\']?(?:circleci[_-]?access[_-]?token|access[_-]?token)["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{40})["\']', re.I),
    "Cloudflare_API_Key": re.compile(r'["\']?(?:cloudflare[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{37})["\']', re.I),
    "Cypress_Record_Key": re.compile(r'["\']?(?:cypress[_-]?record[_-]?key|record[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "DataDog_API_Key": re.compile(r'["\']?(?:datadog[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "Delighted_API_Key": re.compile(r'["\']?(?:delighted[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "DeviantArt_Access_Token": re.compile(r'["\']?(?:deviant[_-]?art[_-]?access[_-]?token|access[_-]?token)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "DeviantArt_Secret": re.compile(r'["\']?(?:deviant[_-]?art[_-]?secret|secret)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "Dropbox_API": re.compile(r'["\']?(?:dropbox[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{15})["\']', re.I),
    "Dropbox_Access_Token": re.compile(r'["\']?(?:dropbox[_-]?access[_-]?token|access[_-]?token)["\']?\s*[:=]\s*["\'](sl\.[A-Za-z0-9_-]{135})["\']', re.I),
    "Facebook_Access_Token": re.compile(r'EAACEdEose0cBA[0-9A-Za-z]+'),
    "Facebook_AppSecret": re.compile(r'["\']?(?:facebook[_-]?app[_-]?secret|app[_-]?secret)["\']?\s*[:=]\s*["\']([a-f0-9]{32})["\']', re.I),
    "Firebase_Cloud_Messaging_Server_Key": re.compile(r'["\']?(?:fcm[_-]?server[_-]?key|server[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{171})["\']', re.I),
    "FreshDesk_API_Key": re.compile(r'["\']?(?:freshdesk[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{16})["\']', re.I),
    "GitHub_Client_ID": re.compile(r'["\']?(?:github[_-]?client[_-]?id|client[_-]?id)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{20})["\']', re.I),
    "GitHub_Client_Secret": re.compile(r'["\']?(?:github[_-]?client[_-]?secret|client[_-]?secret)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{40})["\']', re.I),
    "GitHub_Private_SSH_Key": re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),
    "GitHub_Token": re.compile(r'ghp_[A-Za-z0-9]{36}'),
    "GitLab_Personal_Access_Token": re.compile(r'glpat-[A-Za-z0-9_-]{20}'),
    "GitLab_Runner_Registration_Token": re.compile(r'gr134[0-9a-z]{24}'),
    "Google_Cloud_Service_Account_Credentials": re.compile(r'"type":\s*"service_account"'),
    "Google_Recaptcha_Site_Key": re.compile(r'["\']?(?:recaptcha[_-]?site[_-]?key|site[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{40})["\']', re.I),
    "Google_Recaptcha_Secret_Key": re.compile(r'["\']?(?:recaptcha[_-]?secret[_-]?key|secret[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{40})["\']', re.I),
    "Grafana_Access_Token": re.compile(r'["\']?(?:grafana[_-]?access[_-]?token|access[_-]?token)["\']?\s*[:=]\s*["\'](eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,})["\']', re.I),
    "HelpScout_OAUTH": re.compile(r'["\']?(?:help[_-]?scout[_-]?oauth|oauth)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{64})["\']', re.I),
    "Heroku_API_Key": re.compile(r'["\']?(?:heroku[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']', re.I),
    "HubSpot_API_Key": re.compile(r'["\']?(?:hubspot[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{36})["\']', re.I),
    "Infura_API_Key": re.compile(r'["\']?(?:infura[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "Instagram_Access_Token": re.compile(r'["\']?(?:instagram[_-]?access[_-]?token|access[_-]?token)["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{190})["\']', re.I),
    "Instagram_Basic_Display_API": re.compile(r'["\']?(?:instagram[_-]?basic[_-]?display[_-]?api|api)["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{190})["\']', re.I),
    "Instagram_Graph_API": re.compile(r'["\']?(?:instagram[_-]?graph[_-]?api|api)["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{190})["\']', re.I),
    "Ipstack_API_Key": re.compile(r'["\']?(?:ipstack[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "Iterable_API_Key": re.compile(r'["\']?(?:iterable[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "JumpCloud_API_Key": re.compile(r'["\']?(?:jumpcloud[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "Keenio_API_Key": re.compile(r'["\']?(?:keen\.io[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "LinkedIn_OAUTH": re.compile(r'["\']?(?:linkedin[_-]?oauth|oauth)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{64})["\']', re.I),
    "Lokalise_API_Key": re.compile(r'["\']?(?:lokalise[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "Loqate_API_Key": re.compile(r'["\']?(?:loqate[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "MailChimp_API_Key": re.compile(r'["\']?(?:mailchimp[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32}-us[0-9]{1,2})["\']', re.I),
    "MailGun_Private_Key": re.compile(r'["\']?(?:mailgun[_-]?private[_-]?key|private[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "Mapbox_API_Key": re.compile(r'["\']?(?:mapbox[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\'](pk\.[A-Za-z0-9]{41})["\']', re.I),
    "Microsoft_Azure_Tenant": re.compile(r'["\']?(?:azure[_-]?tenant|tenant)["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{36})["\']', re.I),
    "Microsoft_Shared_Access_Signatures": re.compile(r'["\']?(?:sas|shared[_-]?access[_-]?signature)["\']?\s*[:=]\s*["\']([A-Za-z0-9+/]{43}={0,2})["\']', re.I),
    "Microsoft_Teams_Webhook": re.compile(r'https://outlook\.office\.com/webhook/[A-Za-z0-9-]{32}/IncomingWebhook/[A-Za-z0-9-]{32}/[A-Za-z0-9-]{32}'),
    "New_Relic_Personal_API_Key": re.compile(r'["\']?(?:new[_-]?relic[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\'](NRAK-[A-Za-z0-9]{27})["\']', re.I),
    "New_Relic_REST_API_Key": re.compile(r'["\']?(?:new[_-]?relic[_-]?rest[_-]?api[_-]?key|rest[_-]?api[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{64})["\']', re.I),
    "NPM_Token": re.compile(r'["\']?(?:npm[_-]?token|token)["\']?\s*[:=]\s*["\'](npm_[A-Za-z0-9_-]{36})["\']', re.I),
    "OpsGenie_API_Key": re.compile(r'["\']?(?:opsgenie[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "Pagerduty_API_Token": re.compile(r'["\']?(?:pagerduty[_-]?api[_-]?token|api[_-]?token)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "Paypal_Client_ID": re.compile(r'["\']?(?:paypal[_-]?client[_-]?id|client[_-]?id)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "Paypal_Secret_Key": re.compile(r'["\']?(?:paypal[_-]?secret[_-]?key|secret[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "Pendo_Integration_Key": re.compile(r'["\']?(?:pendo[_-]?integration[_-]?key|integration[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "PivotalTracker_API_Token": re.compile(r'["\']?(?:pivotaltracker[_-]?api[_-]?token|api[_-]?token)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "Razorpay_API_Key": re.compile(r'["\']?(?:razorpay[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "Razorpay_Secret_Key": re.compile(r'["\']?(?:razorpay[_-]?secret[_-]?key|secret[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "Salesforce_API_Key": re.compile(r'["\']?(?:salesforce[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "SauceLabs_Username": re.compile(r'["\']?(?:saucelabs[_-]?username|username)["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{32})["\']', re.I),
    "SauceLabs_Access_Key": re.compile(r'["\']?(?:saucelabs[_-]?access[_-]?key|access[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{32})["\']', re.I),
    "SendGrid_API_Token": re.compile(r'["\']?(?:sendgrid[_-]?api[_-]?token|api[_-]?token)["\']?\s*[:=]\s*["\'](SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})["\']', re.I),
    "Shodan_API_Key": re.compile(r'["\']?(?:shodan[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "Slack_Webhook": re.compile(r'https://hooks\.slack\.com/services/[A-Z0-9]{9}/[A-Z0-9]{9}/[A-Za-z0-9]{24}'),
    "Sonarcloud_API_Token": re.compile(r'["\']?(?:sonarcloud[_-]?api[_-]?token|api[_-]?token)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{40})["\']', re.I),
    "Spotify_Access_Token": re.compile(r'["\']?(?:spotify[_-]?access[_-]?token|access[_-]?token)["\']?\s*[:=]\s*["\'](BQ[A-Za-z0-9_-]{130})["\']', re.I),
    "Square_Access_Token": re.compile(r'["\']?(?:square[_-]?access[_-]?token|access[_-]?token)["\']?\s*[:=]\s*["\'](EAAA[AE][A-Za-z0-9_-]{60})["\']', re.I),
    "Telegram_Bot_API_Token": re.compile(r'["\']?(?:telegram[_-]?bot[_-]?api[_-]?token|bot[_-]?api[_-]?token)["\']?\s*[:=]\s*["\']([0-9]{8,10}:[A-Za-z0-9_-]{35})["\']', re.I),
    "Travis_CI_API_Token": re.compile(r'["\']?(?:travis[_-]?ci[_-]?api[_-]?token|api[_-]?token)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{22})["\']', re.I),
    "Twilio_Account_SID": re.compile(r'["\']?(?:twilio[_-]?account[_-]?sid|account[_-]?sid)["\']?\s*[:=]\s*["\'](AC[a-z0-9]{32})["\']', re.I),
    "Twilio_Auth_Token": re.compile(r'["\']?(?:twilio[_-]?auth[_-]?token|auth[_-]?token)["\']?\s*[:=]\s*["\']([a-f0-9]{32})["\']', re.I),
    "Twitter_API_Secret": re.compile(r'["\']?(?:twitter[_-]?api[_-]?secret|api[_-]?secret)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{44})["\']', re.I),
    "Twitter_Bearer_Token": re.compile(r'["\']?(?:twitter[_-]?bearer[_-]?token|bearer[_-]?token)["\']?\s*[:=]\s*["\'](AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D[A-Za-z0-9%]{22})["\']', re.I),
    "Visual_Studio_App_Center_API_Token": re.compile(r'["\']?(?:visual[_-]?studio[_-]?app[_-]?center[_-]?api[_-]?token|api[_-]?token)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{64})["\']', re.I),
    "WakaTime_API_Key": re.compile(r'["\']?(?:wakatime[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "WeGlot_Api_Key": re.compile(r'["\']?(?:weglot[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "WPEngine_API_Key": re.compile(r'["\']?(?:wpengine[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
    "YouTube_API_Key": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),  # Same as Google_API_Key
    "Zapier_Webhook_Token": re.compile(r'https://hooks\.zapier\.com/hooks/catch/[A-Za-z0-9]{32}/[A-Za-z0-9]{32}/'),
    "Zendesk_Access_Token": re.compile(r'["\']?(?:zendesk[_-]?access[_-]?token|access[_-]?token)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{64})["\']', re.I),
    "Zendesk_API_Key": re.compile(r'["\']?(?:zendesk[_-]?api[_-]?key|api[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', re.I),
}

# Detect common API endpoints (rough)
ENDPOINT_PATTERN = re.compile(r'(?:"|\')((?:https?:\/\/)?[A-Za-z0-9\-_\.]+(?:\/[A-Za-z0-9\-_\.\/{}:?-]*)+\.(?:php|asp|aspx|json|cgi|js|jsp)|\/api\/[A-Za-z0-9\/_:-]{3,})["\']', re.I)

# Script / JSON link extraction
SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\'](.*?)["\']', re.I)
LINK_HREF_RE = re.compile(r'<link[^>]+href=["\'](.*?)["\']', re.I)

# ------- Helpers -------
session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})

def fetch_url(url: str) -> str:
    """Fetch content at url, return text (or empty string)."""
    try:
        r = session.get(url, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.text
    except Exception as e:
        logging.debug(f"Failed to fetch {url}: {e}")
        return ""

def is_probable_js_or_json(url: str) -> bool:
    return url.lower().endswith(".js") or url.lower().endswith(".json") or ".js?" in url or ".json?" in url

def extract_links(base: str, html: str) -> List[str]:
    found = set()
    for m in SCRIPT_SRC_RE.findall(html):
        found.add(urljoin(base, m))
    for m in LINK_HREF_RE.findall(html):
        found.add(urljoin(base, m))
    # also naive scan for .js/.json urls anywhere
    for m in re.findall(r'(https?://[^\s"\']+\.(?:js|json)(?:\?[^\s"\']+)?)', html, re.I):
        found.add(m)
    return list(found)

def snippet_around(content: str, match_span: tuple, ctx=100):
    s, e = match_span
    start = max(0, s - ctx)
    end = min(len(content), e + ctx)
    return content[start:end].replace("\n", "\\n")

# ------- Scanning engines -------
def regex_scans(content: str) -> List[Dict[str, Any]]:
    results = []
    for name, pat in PATTERNS.items():
        for m in pat.finditer(content):
            results.append({"engine": "regex", "type": name, "secret": m.group(1) if m.groups() else m.group(0), "span": m.span()})
    for name, pat in TOKEN_PATTERNS.items():
        for m in pat.finditer(content):
            # group(1) when we captured, else full match
            val = m.group(1) if (m.groups() and m.group(1)) else m.group(0)
            results.append({"engine": "token_regex", "type": name, "secret": val, "span": m.span()})
    # endpoints
    for m in ENDPOINT_PATTERN.finditer(content):
        results.append({"engine": "endpoint_regex", "type": "API_Endpoint", "secret": m.group(1), "span": m.span()})
    return results

def detect_secrets_scan(tmp_path: str) -> List[Dict[str, Any]]:
    """Use detect-secrets if available (best-effort)."""
    if not ds_scan_file:
        return []
    try:
        secrets = ds_scan_file(tmp_path)
        out = []
        for s in secrets:
            try:
                out.append({"engine": "detect-secrets", "type": getattr(s, "type", "secret"), "secret": s.secret_value or str(s), "span": (0, 0)})
            except Exception:
                continue
        return out
    except Exception as e:
        logging.debug("detect-secrets scan failed: %s", e)
        return []

# ------- Main scanning of single source -------
def scan_content(source_name: str, content: str) -> List[Dict[str, Any]]:
    """Scan content and return list of findings with context."""
    findings = []
    # regex based findings
    findings += regex_scans(content)
    # detect-secrets findings (write to tmp file)
    if ds_scan_file:
        try:
            import tempfile
            with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", suffix=".txt") as tf:
                tf.write(content)
                tmp_path = tf.name
            findings += detect_secrets_scan(tmp_path)
            try: os.remove(tmp_path)
            except: pass
        except Exception as e:
            logging.debug("tmp/detect-secrets error: %s", e)
    # attach snippet for each finding
    for f in findings:
        try:
            f["snippet"] = snippet_around(content, f.get("span", (0,0)), ctx=80)
        except Exception:
            f["snippet"] = ""
        f["source"] = source_name
    return findings

# ------- Worker for a single URL/file -------
def process_source(src: str) -> Dict[str, Any]:
    """Given a URL or local file path, fetch and scan it plus linked JS/JSON files (if URL)."""
    logging.info("Processing: %s", src)
    result = {"source": src, "timestamp": time.time(), "findings": []}
    content = ""
    is_url = src.startswith("http://") or src.startswith("https://")
    if is_url:
        content = fetch_url(src)
        # scan main page
        result["findings"] += scan_content(src, content)
        # discover linked js/json
        links = extract_links(src, content)
        # filter and fetch likely js/json only
        to_fetch = [l for l in links if is_probable_js_or_json(l)]
        # fetch those concurrently (but limited)
        with ThreadPoolExecutor(max_workers=6) as ex:
            futures = {ex.submit(fetch_url, l): l for l in to_fetch}
            for fut in as_completed(futures):
                lnk = futures[fut]
                try:
                    txt = fut.result()
                    result["findings"] += scan_content(lnk, txt)
                except Exception as e:
                    logging.debug("Failed to fetch linked %s: %s", lnk, e)
    else:
        # local file
        try:
            with open(src, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
            result["findings"] += scan_content(src, content)
        except Exception as e:
            logging.warning("Cannot read file %s: %s", src, e)
    return result

# ------- Utility to pretty-print / save -------
def save_results(results: List[Dict[str, Any]], text_path=OUTPUT_TEXT, json_path=OUTPUT_JSON):
    # human-readable
    with open(text_path, "w", encoding="utf-8") as fh:
        for res in results:
            fh.write(f"\n[+] Source: {res['source']}\n{'='*80}\n")
            if not res["findings"]:
                fh.write("  (no findings)\n")
                continue
            for f in res["findings"]:
                fh.write(f"  - [{f.get('engine')}] {f.get('type')} : {f.get('secret')}\n")
                snippet = f.get("snippet")
                if snippet:
                    fh.write(f"      snippet: ...{snippet}...\n")
    # structured JSON
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(results, jf, indent=2, ensure_ascii=False)

# ------- CLI -------
def main():
    parser = argparse.ArgumentParser(description="Secret-Killer v2.0 — scan URLs / local JS/JSON for secrets")
    parser.add_argument("input_list", help="Plain text file with one URL or file path per line")
    parser.add_argument("-o", "--output", help="Base name for outputs (text/json). Default: secret-killer_results", default="secret-killer_results")
    parser.add_argument("-w", "--workers", help="Parallel workers (default 8)", type=int, default=MAX_WORKERS)
    parser.add_argument("-v", "--verbose", help="Verbose logging", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    base_out = args.output
    text_out = base_out + ".txt"
    json_out = base_out + ".json"

    if not os.path.isfile(args.input_list):
        logging.error("Input list file not found: %s", args.input_list)
        sys.exit(1)

    with open(args.input_list, "r", encoding="utf-8") as fh:
        sources = [l.strip() for l in fh if l.strip() and not l.strip().startswith("#")]

    if not sources:
        logging.error("No sources to scan (empty input list).")
        sys.exit(1)

    results = []
    logging.info("Starting scan of %d sources with %d workers", len(sources), args.workers)
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(process_source, s): s for s in sources}
        for fut in as_completed(futures):
            s = futures[fut]
            try:
                r = fut.result()
                results.append(r)
                logging.info("Completed: %s (findings: %d)", s, len(r["findings"]))
            except Exception as e:
                logging.warning("Failed to process %s: %s", s, e)

    save_results(results, text_out, json_out)
    logging.info("Scan complete. Results saved to %s and %s", text_out, json_out)

if __name__ == "__main__":
    main()
