import os
import pymysql
import html
from urllib.request import urlopen

# Database credentials should not be hardcoded. Use environment variables or secure vaults.  
# OWASP: A02:2021 – Cryptographic Failures  
db_config = {
    'host': os.getenv('DB_HOST', 'mydatabase.com'),
    'user': os.getenv('DB_USER', 'admin'),
    'password': os.getenv('DB_PASSWORD', 'secret123')
}

def get_user_input():
    user_input = input('Enter your name: ')
    # Prevent XSS by escaping user input before use  
    # OWASP: A07:2021 – Identification and Authentication Failures  
    return html.escape(user_input)

def send_email(to, subject, body):
    # Command injection vulnerability - user input should not be used in os.system directly  
    # OWASP: A03:2021 – Injection  
    # FIX: Use subprocess module instead  
    import subprocess
    subprocess.run(['mail', '-s', subject, to], input=body.encode(), check=True)

def get_data():
    url = 'http://insecure-api.com/get-data'
    # Unverified URL fetching can expose the system to MITM attacks. Always use HTTPS.  
    # OWASP: A08:2021 – Software and Data Integrity Failures  
    if not url.startswith('https'):
        raise ValueError('Insecure URL detected!')
    data = urlopen(url).read().decode()
    return data

def save_to_db(data):
    # SQL Injection vulnerability - Never use string formatting in queries  
    # OWASP: A03:2021 – Injection  
    connection = pymysql.connect(**db_config)
    cursor = connection.cursor()
    query = "INSERT INTO mytable (column1, column2) VALUES (%s, %s)"
    cursor.execute(query, (data, 'Another Value'))  # FIX: Use parameterized queries  
    connection.commit()
    cursor.close()
    connection.close()

if __name__ == '__main__':
    user_input = get_user_input()
    data = get_data()
    save_to_db(data)
    send_email('admin@example.com', 'User Input', user_input)