import json
import requests

def check_virustotal(file_path, api_key):
    # Endpoint for scanning a file
    scan_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    
    # Endpoint for getting the analysis report
    report_url = 'https://www.virustotal.com/vtapi/v2/file/report'

    # Parameters for scanning the file
    scan_params = {'apikey': api_key}
    scan_files = {'file': (file_path, open(file_path, 'rb'))}

    # Submit the file for scanning
    response_scan = requests.post(scan_url, files=scan_files, params=scan_params)
    if response_scan.status_code == 200:
        # If scanning is successful, get the resource identifier
        resource_id = response_scan.json().get('resource')

        # Parameters for getting the analysis report
        report_params = {'apikey': api_key, 'resource': resource_id}

        # Check the analysis report
        response_report = requests.get(report_url, params=report_params)
        if response_report.status_code == 200:
            # If report retrieval is successful, return the full report as a string
            report = response_report.json()
            # Convert the dictionary to a string representation
            report_str = json.dumps(report, indent=4)
            return report_str
        else:
            return "Error retrieving analysis report from VirusTotal."
    else:
        return "Error submitting file to VirusTotal for scanning."
