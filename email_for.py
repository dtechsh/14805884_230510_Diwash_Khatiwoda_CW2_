import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import email
from email import policy
from email.parser import BytesParser
import dns.resolver
import json
import hashlib
import logging
import requests
import re
from bs4 import BeautifulSoup
from fpdf import FPDF
import os
import mysql.connector
import bcrypt

FONT = ("Helvetica", 14)
BUTTON_FONT = ("Helvetica", 16)
BUTTON_WIDTH = 20
WINDOW_SIZE = "1000x800"
BUTTON_BG = "#007BFF"
BUTTON_FG = "white"
ENTRY_WIDTH = 30

ABUSEIPDB_API_KEY = '0848748d04a0a49093a673c959b90c4cf420996d6dc65703ea314b689013e0078cc03c0aea9095c2'
VIRUSTOTAL_API_KEY = '40a22e319a62942219a2d0ca43019760837e7b074b186acacf4514c1cdedd369'

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "email_data"
}

logging.basicConfig(filename='email_forensic.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def connect_db():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except mysql.connector.Error as err:
        print(f"❌ Error: Unable to connect to MySQL: {err}")
        exit()

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(stored_password, entered_password):
    return bcrypt.checkpw(entered_password.encode(), stored_password.encode())

def init_db():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        first_name VARCHAR(50) NOT NULL,
                        last_name VARCHAR(50) NOT NULL,
                        gmail VARCHAR(100) UNIQUE NOT NULL,
                        username VARCHAR(50) UNIQUE NOT NULL,
                        password VARCHAR(255) NOT NULL
                    )''')
    conn.commit()
    conn.close()

def validate_name(name):
    return bool(re.fullmatch(r"[A-Z][a-z]{1,19}", name))

def validate_gmail(email):
    return bool(re.fullmatch(r"[a-zA-Z0-9._%+-]{4,}@gmail\.com", email))

def validate_username(username):
    return bool(re.fullmatch(r"^(?=.*[\d])(?=.*[\W_])[a-zA-Z\d\W_]{6,25}$", username))

def validate_password(password):
    return bool(re.fullmatch(r"^(?=.*[A-Z])(?=.*[\d])(?=.*[\W_])[A-Za-z\d\W_]{8,30}$", password))

def create_label_and_entry(parent, label_text, entry_var, show=None):
    label = tk.Label(parent, text=label_text, font=FONT)
    label.pack(pady=10)
    entry = tk.Entry(parent, font=FONT, width=ENTRY_WIDTH, textvariable=entry_var, show=show)
    entry.pack(pady=10)
    return label, entry

def create_button(parent, text, command):
    button = tk.Button(parent, text=text, font=BUTTON_FONT, width=BUTTON_WIDTH, command=command, bg=BUTTON_BG, fg=BUTTON_FG)
    button.pack(pady=20)
    return button

def sign_up():
    def submit_signup():
        first_name = first_name_var.get().strip()
        last_name = last_name_var.get().strip()
        gmail = gmail_var.get().strip()
        username = username_var.get().strip()
        password = password_var.get().strip()
        confirm_password = confirm_password_var.get().strip()

        if not validate_name(first_name):
            messagebox.showerror("Error", "First Name must be capitalized and contain only letters (1-20 characters).")
            return
        if not validate_name(last_name):
            messagebox.showerror("Error", "Last Name must be capitalized and contain only letters (1-20 characters).")
            return
        if not validate_gmail(gmail):
            messagebox.showerror("Error", "Invalid Gmail! It must include '@gmail.com'.")
            return
        if not validate_username(username):
            messagebox.showerror("Error", "Username must be 6-25 characters long, contain at least one number and one special character.")
            return
        if not validate_password(password):
            messagebox.showerror("Error", "Password must be 8-30 characters long, contain at least one uppercase letter, one number, and one special character.")
            return
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return

        hashed_pw = hash_password(password)
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE gmail = %s", (gmail,))
        if cursor.fetchone()[0] > 0:
            messagebox.showerror("Error", "Gmail is already registered!")
            conn.close()
            return
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", (username,))
        if cursor.fetchone()[0] > 0:
            messagebox.showerror("Error", "Username already exists!")
            conn.close()
            return

        cursor.execute("INSERT INTO users (first_name, last_name, gmail, username, password) VALUES (%s, %s, %s, %s, %s)",
                       (first_name, last_name, gmail, username, hashed_pw))
        conn.commit()
        conn.close()
        messagebox.showinfo("Success", "Sign up successful! You can now log in.")
        signup_window.destroy()

    signup_window = tk.Toplevel()
    signup_window.title("Sign Up")
    signup_window.geometry(WINDOW_SIZE)

    first_name_var = tk.StringVar()
    last_name_var = tk.StringVar()
    gmail_var = tk.StringVar()
    username_var = tk.StringVar()
    password_var = tk.StringVar()
    confirm_password_var = tk.StringVar()

    create_label_and_entry(signup_window, "First Name:", first_name_var)
    create_label_and_entry(signup_window, "Last Name:", last_name_var)
    create_label_and_entry(signup_window, "Gmail:", gmail_var)
    create_label_and_entry(signup_window, "Username:", username_var)
    create_label_and_entry(signup_window, "Password:", password_var, show="*")
    create_label_and_entry(signup_window, "Confirm Password:", confirm_password_var, show="*")

    create_button(signup_window, "Sign Up", submit_signup)

def login():
    def submit_login():
        username = username_var.get().strip()
        password = password_var.get().strip()

        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and verify_password(user[0], password):
            messagebox.showinfo("Success", "Login successful! Access granted.")
            login_window.destroy()
            open_email_forensic_tool()
        else:
            messagebox.showerror("Error", "Invalid username or password!")
        conn.close()

    login_window = tk.Toplevel()
    login_window.title("Login")
    login_window.geometry(WINDOW_SIZE)

    username_var = tk.StringVar()
    password_var = tk.StringVar()

    create_label_and_entry(login_window, "Username:", username_var)
    create_label_and_entry(login_window, "Password:", password_var, show="*")

    create_button(login_window, "Login", submit_login)

def forgot_password():
    def submit_forgot_password():
        username = username_var.get().strip()
        gmail = gmail_var.get().strip()
        new_password = new_password_var.get().strip()
        confirm_password = confirm_password_var.get().strip()

        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = %s AND gmail = %s", (username, gmail))
        user = cursor.fetchone()

        if not user:
            messagebox.showerror("Error", "Username or Gmail is incorrect!")
            conn.close()
            return

        old_hashed_password = user[0]

        if not validate_password(new_password):
            messagebox.showerror("Error", "New password must be 8-30 characters long, contain at least one uppercase letter, one number, and one special character.")
            conn.close()
            return
        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            conn.close()
            return
        if verify_password(old_hashed_password, new_password):
            messagebox.showerror("Error", "New password cannot be the same as the previous password.")
            conn.close()
            return

        hashed_pw = hash_password(new_password)
        cursor.execute("UPDATE users SET password = %s WHERE username = %s", (hashed_pw, username))
        conn.commit()
        conn.close()
        messagebox.showinfo("Success", "Password reset successful! You can now log in with your new password.")
        forgot_password_window.destroy()

    forgot_password_window = tk.Toplevel()
    forgot_password_window.title("Forgot Password")
    forgot_password_window.geometry(WINDOW_SIZE)

    username_var = tk.StringVar()
    gmail_var = tk.StringVar()
    new_password_var = tk.StringVar()
    confirm_password_var = tk.StringVar()

    create_label_and_entry(forgot_password_window, "Username:", username_var)
    create_label_and_entry(forgot_password_window, "Gmail:", gmail_var)
    create_label_and_entry(forgot_password_window, "New Password:", new_password_var, show="*")
    create_label_and_entry(forgot_password_window, "Confirm New Password:", confirm_password_var, show="*")

    create_button(forgot_password_window, "Submit", submit_forgot_password)

def authentication():
    init_db()

    def open_sign_up():
        sign_up()

    def open_login():
        login()

    def open_forgot_password():
        forgot_password()

    main_window = tk.Tk()
    main_window.title("User Authentication")
    main_window.geometry(WINDOW_SIZE)

    style = ttk.Style()
    style.configure("TLabel", font=FONT, background="#f0f0f0")
    style.configure("TButton", font=BUTTON_FONT, background=BUTTON_BG, foreground=BUTTON_FG)

    tk.Label(main_window, text="Welcome! Please select an option.", font=("Helvetica", 18)).pack(pady=30)

    create_button(main_window, "Sign Up", open_sign_up)
    create_button(main_window, "Login", open_login)
    create_button(main_window, "Forgot Password", open_forgot_password)

    main_window.mainloop()

def analyze_email_headers(email_path):
    with open(email_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    headers = {
        'sender': msg['From'],
        'recipient': msg['To'],
        'subject': msg['Subject'],
        'timestamps': msg['Date'],
        'ip_addresses': [],
        'message_id': msg['Message-ID'],
        'user_agent': msg['User-Agent'] if 'User-Agent' in msg else 'N/A',
        'x_mailer': msg['X-Mailer'] if 'X-Mailer' in msg else 'N/A',
        'return_path': msg['Return-Path'] if 'Return-Path' in msg else 'N/A',
        'received': msg.get_all('Received'),
        'dkim_signature': msg['DKIM-Signature'] if 'DKIM-Signature' in msg else 'N/A',
        'spf': msg['Received-SPF'] if 'Received-SPF' in msg else 'N/A',
        'dmarc': msg['Authentication-Results'] if 'Authentication-Results' in msg else 'N/A'
    }

    for received in headers['received']:
        ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', received)
        if ip_match:
            headers['ip_addresses'].append(ip_match.group(0))

    return headers

def check_spf(domain):
    try:
        spf_record = dns.resolver.resolve(domain, 'TXT')
        for record in spf_record:
            if 'v=spf1' in record.to_text():
                return True
    except Exception as e:
        logging.error(f"Error checking SPF for domain {domain}: {e}")
    return False

def check_dkim(domain):
    try:
        dkim_record = dns.resolver.resolve(f'_domainkey.{domain}', 'TXT')
        for record in dkim_record:
            if 'v=DKIM1' in record.to_text():
                return True
    except Exception as e:
        logging.error(f"Error checking DKIM for domain {domain}: {e}")
    return False

def check_dmarc(domain):
    try:
        dmarc_record = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for record in dmarc_record:
            if 'v=DMARC1' in record.to_text():
                return True
    except Exception as e:
        logging.error(f"Error checking DMARC for domain {domain}: {e}")
    return False

def detect_phishing_spoofing(email_path):
    headers = analyze_email_headers(email_path)
    domain = headers['sender'].split('@')[-1]

    spf = check_spf(domain)
    dkim = check_dkim(domain)
    dmarc = check_dmarc(domain)

    return {
        'SPF': spf,
        'DKIM': dkim,
        'DMARC': dmarc
    }

def analyze_attachments(email_path, known_malware_hashes):
    with open(email_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    attachments = []
    for part in msg.iter_attachments():
        file_name = part.get_filename()
        file_data = part.get_payload(decode=True)
        file_hash = calculate_sha256(file_data)
        is_malware = check_malware(file_hash, known_malware_hashes)
        file_type = file_name.split('.')[-1].upper() if '.' in file_name else 'Unknown'
        attachments.append({
            'file_name': file_name,
            'file_hash': file_hash,
            'is_malware': is_malware,
            'file_type': file_type
        })

    return attachments

def calculate_sha256(file_data):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_data)
    return sha256_hash.hexdigest()

def check_malware(file_hash, known_malware_hashes):
    return file_hash in known_malware_hashes

def analyze_email_body(email_path):
    with open(email_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    body = ""
    links = []
    if msg.is_multipart():
        for part in msg.iter_parts():
            if part.get_content_type() == "text/plain":
                body += part.get_payload(decode=True).decode(part.get_content_charset(), errors='replace')
            elif part.get_content_type() == "text/html":
                html_content = part.get_payload(decode=True).decode(part.get_content_charset(), errors='replace')
                soup = BeautifulSoup(html_content, 'html.parser')
                body += soup.get_text()
                for link in soup.find_all('a', href=True):
                    links.append(link['href'])
    else:
        if msg.get_content_type() == "text/plain":
            body = msg.get_payload(decode=True).decode(msg.get_content_charset(), errors='replace')
        elif msg.get_content_type() == "text/html":
            html_content = msg.get_payload(decode=True).decode(msg.get_content_charset(), errors='replace')
            soup = BeautifulSoup(html_content, 'html.parser')
            body += soup.get_text()
            for link in soup.find_all('a', href=True):
                links.append(link['href'])

    suspicious_keywords = ['password', 'login', 'urgent', 'click here', 'download']
    suspicious_content = any(keyword in body.lower() for keyword in suspicious_keywords)

    return {
        'body': body,
        'suspicious_content': suspicious_content,
        'links': links
    }

def check_threat_intelligence(ip_addresses, domains, links):
    threat_intel = {
        'ip_addresses': {},
        'domains': {},
        'links': {}
    }

    for ip in ip_addresses:
        response = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            params={'ipAddress': ip},
            headers={'Key': ABUSEIPDB_API_KEY}
        )
        if response.status_code == 200:
            data = response.json()
            threat_intel['ip_addresses'][ip] = data['data']

    for domain in domains:
        response = requests.get(
            f'https://www.virustotal.com/api/v3/domains/{domain}',
            headers={'x-apikey': VIRUSTOTAL_API_KEY}
        )
        if response.status_code == 200:
            data = response.json()
            threat_intel['domains'][domain] = data['data']

    for link in links:
        domain = re.search(r'https?://([^/]+)', link)
        if domain:
            domain = domain.group(1)
            response = requests.get(
                f'https://www.virustotal.com/api/v3/domains/{domain}',
                headers={'x-apikey': VIRUSTOTAL_API_KEY}
            )
            if response.status_code == 200:
                data = response.json()
                threat_intel['links'][link] = data['data']

    return threat_intel

def open_file():
    global file_paths
    file_paths = filedialog.askopenfilenames(filetypes=[('EML Files', '*.eml')])
    if file_paths:
        file_path_label.config(text=f"Selected Files: {', '.join(file_paths)}")

def analyze_files():
    if not file_paths:
        messagebox.showwarning("No Files Selected", "Please select EML files first.")
        return

    all_results = []
    for file_path in file_paths:
        headers = analyze_email_headers(file_path)
        phishing_spoofing = detect_phishing_spoofing(file_path)
        known_malware_hashes = ['known_hash_1', 'known_hash_2']
        attachments = analyze_attachments(file_path, known_malware_hashes)
        body_analysis = analyze_email_body(file_path)
        threat_intel = check_threat_intelligence(headers['ip_addresses'], [headers['sender'].split('@')[-1]], body_analysis['links'])

        results = {
            'file_path': file_path,
            'email_headers': headers,
            'phishing_spoofing': phishing_spoofing,
            'attachments': attachments,
            'body_analysis': body_analysis,
            'threat_intel': threat_intel
        }
        all_results.append(results)

        if any(phishing_spoofing.values()) or any(attachment['is_malware'] for attachment in attachments) or body_analysis['suspicious_content']:
            messagebox.showwarning("Potential Threat Detected", f"The email {file_path} contains potential threats. Please review the analysis results carefully.")

    headers_text.delete(1.0, tk.END)
    phishing_text.delete(1.0, tk.END)
    attachments_text.delete(1.0, tk.END)
    body_text.delete(1.0, tk.END)
    threat_intel_text.delete(1.0, tk.END)

    for results in all_results:
        headers_text.insert(tk.END, f"Email Headers for {results['file_path']}:\n")
        for key, value in results['email_headers'].items():
            if isinstance(value, list):
                headers_text.insert(tk.END, f'{key}:\n')
                for item in value:
                    headers_text.insert(tk.END, f'  {item}\n')
            else:
                headers_text.insert(tk.END, f'{key}: {value}\n')

        phishing_text.insert(tk.END, f"Phishing & Spoofing Detection for {results['file_path']}:\n")
        for key, value in results['phishing_spoofing'].items():
            phishing_text.insert(tk.END, f'{key}: {value}\n')

        attachments_text.insert(tk.END, f"Attachment Analysis for {results['file_path']}:\n")
        for attachment in results['attachments']:
            attachments_text.insert(tk.END, f'File Name: {attachment["file_name"]}, SHA-256 Hash: {attachment["file_hash"]}, Is Malware: {attachment["is_malware"]}, Type: {attachment["file_type"]}\n')

        body_text.insert(tk.END, f"Email Body Analysis for {results['file_path']}:\n")
        body_text.insert(tk.END, f'Suspicious Content: {results["body_analysis"]["suspicious_content"]}\n')
        body_text.insert(tk.END, 'Links:\n')
        for link in results['body_analysis']['links']:
            body_text.insert(tk.END, f'{link}\n')

        threat_intel_text.insert(tk.END, f"Threat Intelligence for {results['file_path']}:\n")
        threat_intel_text.insert(tk.END, f'IP Addresses: {results["threat_intel"]["ip_addresses"]}\n')
        threat_intel_text.insert(tk.END, f'Domains: {results["threat_intel"]["domains"]}\n')
        threat_intel_text.insert(tk.END, f'Links: {results["threat_intel"]["links"]}\n')

def export_results():
    if not file_paths:
        messagebox.showwarning("No Files Selected", "Please select EML files first.")
        return

    all_results = []
    for file_path in file_paths:
        headers = analyze_email_headers(file_path)
        phishing_spoofing = detect_phishing_spoofing(file_path)
        known_malware_hashes = ['known_hash_1', 'known_hash_2']
        attachments = analyze_attachments(file_path, known_malware_hashes)
        body_analysis = analyze_email_body(file_path)
        threat_intel = check_threat_intelligence(headers['ip_addresses'], [headers['sender'].split('@')[-1]], body_analysis['links'])

        results = {
            'file_path': file_path,
            'email_headers': headers,
            'phishing_spoofing': phishing_spoofing,
            'attachments': attachments,
            'body_analysis': body_analysis,
            'threat_intel': threat_intel
        }
        all_results.append(results)

    export_file_path = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON Files', '*.json'), ('PDF Files', '*.pdf')])
    if export_file_path:
        if export_file_path.endswith('.json'):
            with open(export_file_path, 'w') as f:
                json.dump(all_results, f, indent=4)
        elif export_file_path.endswith('.pdf'):
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)

            for results in all_results:
                pdf.cell(200, 10, txt=f"Email Forensic Analysis Report for {results['file_path']}", ln=True, align='C')

                pdf.cell(200, 10, txt="Email Headers:", ln=True)
                for key, value in results['email_headers'].items():
                    if isinstance(value, list):
                        pdf.cell(200, 10, txt=f'{key}:', ln=True)
                        for item in value:
                            pdf.cell(200, 10, txt=f'  {item}', ln=True)
                    else:
                        pdf.cell(200, 10, txt=f'{key}: {value}', ln=True)

                pdf.cell(200, 10, txt="Phishing & Spoofing Detection:", ln=True)
                for key, value in results['phishing_spoofing'].items():
                    pdf.cell(200, 10, txt=f'{key}: {value}', ln=True)

                pdf.cell(200, 10, txt="Attachment Analysis:", ln=True)
                for attachment in results['attachments']:
                    pdf.cell(200, 10, txt=f'File Name: {attachment["file_name"]}, SHA-256 Hash: {attachment["file_hash"]}, Is Malware: {attachment["is_malware"]}, Type: {attachment["file_type"]}', ln=True)

                pdf.cell(200, 10, txt="Email Body Analysis:", ln=True)
                pdf.cell(200, 10, txt=f'Suspicious Content: {results["body_analysis"]["suspicious_content"]}', ln=True)
                pdf.cell(200, 10, txt="Links:", ln=True)
                for link in results['body_analysis']['links']:
                    pdf.cell(200, 10, txt=f'{link}', ln=True)

                pdf.cell(200, 10, txt="Threat Intelligence:", ln=True)
                pdf.cell(200, 10, txt=f'IP Addresses: {results["threat_intel"]["ip_addresses"]}', ln=True)
                pdf.cell(200, 10, txt=f'Domains: {results["threat_intel"]["domains"]}', ln=True)
                pdf.cell(200, 10, txt=f'Links: {results["threat_intel"]["links"]}', ln=True)

            pdf.output(export_file_path)

def open_email_forensic_tool():
    root = tk.Tk()
    root.title('Email Forensic Tool')
    root.geometry(WINDOW_SIZE)
    root.configure(bg="#e0e0e0")

    global file_path_label, headers_text, phishing_text, attachments_text, body_text, threat_intel_text

    open_button = tk.Button(root, text='Open EML Files', command=open_file, bg=BUTTON_BG, fg=BUTTON_FG, font=BUTTON_FONT)
    open_button.pack(pady=10)

    file_path_label = tk.Label(root, text="Selected Files: None", font=FONT, bg="#e0e0e0")
    file_path_label.pack(pady=10)

    analyze_button = tk.Button(root, text='Analyze Files', command=analyze_files, bg=BUTTON_BG, fg=BUTTON_FG, font=BUTTON_FONT)
    analyze_button.pack(pady=10)

    canvas = tk.Canvas(root, bg="#ffffff")
    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    scrollbar = tk.Scrollbar(root, command=canvas.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

    frame = tk.Frame(canvas, bg="#ffffff")
    canvas.create_window((0, 0), window=frame, anchor="nw")

    headers_label = tk.Label(frame, text='Email Headers:', font=FONT, bg="#ffffff")
    headers_label.pack(anchor='w')
    headers_text = tk.Text(frame, height=10, width=120, bg="#ffffff", font=FONT)
    headers_text.pack(anchor='w')

    phishing_label = tk.Label(frame, text='Phishing & Spoofing Detection:', font=FONT, bg="#ffffff")
    phishing_label.pack(anchor='w')
    phishing_text = tk.Text(frame, height=10, width=120, bg="#ffffff", font=FONT)
    phishing_text.pack(anchor='w')

    attachments_label = tk.Label(frame, text='Attachment Analysis:', font=FONT, bg="#ffffff")
    attachments_label.pack(anchor='w')
    attachments_text = tk.Text(frame, height=10, width=120, bg="#ffffff", font=FONT)
    attachments_text.pack(anchor='w')

    body_label = tk.Label(frame, text='Email Body Analysis:', font=FONT, bg="#ffffff")
    body_label.pack(anchor='w')
    body_text = tk.Text(frame, height=10, width=120, bg="#ffffff", font=FONT)
    body_text.pack(anchor='w')

    threat_intel_label = tk.Label(frame, text='Threat Intelligence:', font=FONT, bg="#ffffff")
    threat_intel_label.pack(anchor='w')
    threat_intel_text = tk.Text(frame, height=10, width=120, bg="#ffffff", font=FONT)
    threat_intel_text.pack(anchor='w')

    export_button = tk.Button(root, text='Export Results', command=export_results, bg=BUTTON_BG, fg=BUTTON_FG, font=BUTTON_FONT)
    export_button.pack(pady=10)

    root.mainloop()

if __name__ == '__main__':
    authentication()
