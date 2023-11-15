import requests
import json
import pyperclip
import time
import ipaddress
import datetime
import tkinter as tk
from threading import Thread
from tkinter import scrolledtext

# VirusTotal API Key
API_KEY = ''

def scan_ip(ip):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {
        "x-apikey": API_KEY
    }
    response = requests.get(url, headers=headers)
    return response.json()

def update_title(root, start_time):
    elapsed_time = datetime.datetime.now() - start_time
    hours, remainder = divmod(elapsed_time.total_seconds(), 3600)
    minutes, seconds = divmod(remainder, 60)
    root.title(f"IP Scanner - Running Time: {int(hours):02}:{int(minutes):02}:{int(seconds):02}")
    root.after(1000, update_title, root, start_time)

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def update_text(text_widget, text):
    text_widget.config(state=tk.NORMAL)
    text_widget.insert(tk.END, text + '\n')
    text_widget.config(state=tk.DISABLED)
    # Auto scroll to the end
    text_widget.see(tk.END)

def main(text_widget):
    last_ip = ""
    while True:
        clipboard_ip = pyperclip.paste()
        if clipboard_ip != last_ip and is_valid_ip(clipboard_ip):
            try:
                result = scan_ip(clipboard_ip)
                # Filter the result to only show relevant information
                filtered_result = {
                    "IP": result.get("data", {}).get("id"),
                    "Last Analysis Stats": result.get("data", {}).get("attributes", {}).get("last_analysis_stats"),
                }
                current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log_message = f"Query Time: {current_time}\n" + json.dumps(filtered_result, indent=4)
                update_text(text_widget, log_message)
                last_ip = clipboard_ip
            except Exception as e:
                update_text(text_widget, f"Error: {e}")
        time.sleep(1)

if __name__ == "__main__":
    start_time = datetime.datetime.now()
    root = tk.Tk()
    root.title("IP Scanner.")
    root.geometry("500x500")
    text = scrolledtext.ScrolledText(root, bg='black', fg='light green', font=("Courier", 10))
    text.pack(fill=tk.BOTH, expand=True)
    thread = Thread(target=main, args=(text,))
    thread.start()
    update_title(root, start_time)
    root.mainloop()