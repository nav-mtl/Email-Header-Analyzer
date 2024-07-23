import re
import requests
from flask import Flask, request, render_template
from datetime import datetime

app = Flask(__name__)

# Function to parse email headers
def parse_email_headers(headers):
    header_lines = headers.split('\n')
    parsed_headers = {}
    for line in header_lines:
        if ': ' in line:
            key, value = line.split(': ', 1)
            if key not in parsed_headers:
                parsed_headers[key] = value
            else:
                parsed_headers[key] += f"\n{value}"
    return parsed_headers

# Function to perform IP lookup and geolocation
def ip_lookup(ip):
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/")
        data = response.json()
        return data
    except Exception as e:
        return {"error": str(e)}

# Function to extract hop information
def extract_hops(headers):
    hops = []
    received_headers = headers.get('Received', '').split('\n')
    for index, header in enumerate(received_headers, start=1):
        hop_info = {
            'hop': index,
            'submitting_host': None,
            'receiving_host': None,
            'time': None,
            'delay': None,
            'type': None,
            'ip': None,
            'location': None
        }
        
        # Extract submitting and receiving hosts, time, and delay
        match = re.search(r'from\s+([^\s]+)', header, re.IGNORECASE)
        if match:
            hop_info['submitting_host'] = match.group(1)
        match = re.search(r'by\s+([^\s]+)', header, re.IGNORECASE)
        if match:
            hop_info['receiving_host'] = match.group(1)
        match = re.search(r';\s+(.+)', header)
        if match:
            hop_info['time'] = match.group(1)
        
        # Detect IP address and type
        match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', header)
        if match:
            hop_info['ip'] = match.group(1)
            hop_info['location'] = ip_lookup(hop_info['ip'])
        
        # Calculate delay
        if index > 1 and hops[-1]['time'] and hop_info['time']:
            prev_time = datetime.strptime(hops[-1]['time'], '%a, %d %b %Y %H:%M:%S %z')
            current_time = datetime.strptime(hop_info['time'], '%a, %d %b %Y %H:%M:%S %z')
            hop_info['delay'] = str(current_time - prev_time)
        
        # Determine type (ESMTP, etc.)
        match = re.search(r'with\s+(\S+)', header, re.IGNORECASE)
        if match:
            hop_info['type'] = match.group(1)
        
        hops.append(hop_info)
    return hops

# Function to check for malicious or phishing content
def check_malicious_content(headers):
    malicious_keywords = ['spam', 'phishing', 'virus', 'malware']
    for key, value in headers.items():
        if any(keyword in value.lower() for keyword in malicious_keywords):
            return True
    return False

@app.route('/', methods=['GET', 'POST'])
def email_analyzer():
    if request.method == 'POST':
        email_headers = None
        if 'email_file' in request.files and request.files['email_file'].filename != '':
            email_file = request.files['email_file']
            email_headers = email_file.read().decode('utf-8')
        elif 'email_text' in request.form and request.form['email_text'].strip() != '':
            email_headers = request.form['email_text']

        if email_headers:
            parsed_headers = parse_email_headers(email_headers)
            ip_info = []
            hops = extract_hops(parsed_headers)
            for key, value in parsed_headers.items():
                if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', value):
                    ip = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', value).group()
                    ip_info.append({"header": key, "ip": ip, "location": ip_lookup(ip)})

            is_malicious = check_malicious_content(parsed_headers)

            return render_template('email_analyzer.html', headers=parsed_headers, ip_info=ip_info, hops=hops, is_malicious=is_malicious)

    return render_template('email_analyzer.html')

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
