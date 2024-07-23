# Email Header Analyzer

This is a web application to analyze email headers for security issues, IP geolocation, and hop information. It can also detect potential malicious or phishing content in the email headers.

## Features

- **Analyze Email Headers**: Extracts and displays detailed information from email headers.
- **IP Geolocation**: Looks up the geolocation of IP addresses found in the headers.
- **Hop Information**: Extracts hop information from the `Received` headers, including submitting host, receiving host, time, delay, type, IP address, and geolocation.
- **Malicious Content Detection**: Checks the headers for potential malicious or phishing content and provides a warning if detected.

## Usage

### Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/nav-mtl/Email-Header-Analyzer.git
    cd Email-Header-Analyzer
    ```

2. **Create a virtual environment and activate it**:
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. **Install the required packages**:
    ```bash
    pip install -r requirements.txt
    ```

4. **Run the application**:
    ```bash
    python email_analyzer.py
    ```

5. **Open your browser and navigate to**:
    ```
    http://127.0.0.1:5000/
    ```

### Using the Application

1. **Paste Email Headers**: You can paste the email headers directly into the text area provided.
2. **Upload Email Header File**: Alternatively, you can upload a file containing the email headers.
3. **Analyze Headers**: Click the "Analyze Headers" button to process the headers.

### Output

- **Parsed Headers**: Displays the parsed email headers in a table.
- **Hop Information**: Displays detailed hop information including submitting host, receiving host, time, delay, type, IP address, and geolocation.
- **IP Information**: Displays IP addresses found in the headers along with their geolocation.
- **Security Check**: Indicates if the email appears to be malicious or a phishing attempt.

### Malicious Content Detection

The application checks for the following keywords in the headers to determine if the email might be malicious or a phishing attempt:

- `spam`
- `phishing`
- `virus`
- `malware`

### Example

Below is an example of how the application displays hop information and indicates if an email is malicious:

#### Hop Information Table

| Hop | Submitting Host | Receiving Host | Time                | Delay       | Type                   | IP              | Geolocation                             |
|-----|-----------------|----------------|---------------------|-------------|------------------------|-----------------|-----------------------------------------|
| 1   | User            | None           | None                | None        | None                   | 85.250.54.29    | Ramat Gan, Tel Aviv, Israel             |
| 2   | mail.shako.com.tw | bf.shako.com.tw | Fri, 18 Jan 2013 07:34:12 +0800 | 34 seconds | ESMTP                 | 59.125.100.112 | Taipei, Taipei City, Taiwan             |
| ... | ...             | ...            | ...                 | ...         | ...                    | ...             | ...                                     |

#### IP Information Table

| Header    | IP            | Geolocation                             |
|-----------|---------------|-----------------------------------------|
| Received  | 85.250.54.29  | Ramat Gan, Tel Aviv, Israel             |
| Received  | 59.125.100.112| Taipei, Taipei City, Taiwan             |
| ...       | ...           | ...                                     |

#### Security Warning

Warning: This email appears to be malicious or a phishing attempt.

## Author

**Navjot Singh**  
[LinkedIn](https://www.linkedin.com/in/njot/)

## License

This project is licensed under the MIT License.
