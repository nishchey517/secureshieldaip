import requests

def check_virustotal(file_path, api_key):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': api_key}
    files = {'file': (file_path, open(file_path, 'rb'))}
    
    response = requests.post(url, files=files, params=params)
    if response.status_code == 200:
        report_url = response.json().get('permalink')
        return f"VirusTotal Report URL: {report_url}"
    else:
        return "Error submitting file to VirusTotal."
