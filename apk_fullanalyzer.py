import subprocess
import json
from androguard.misc import AnalyzeAPK
import requests
#from rootbeer import RootBeer

def run_mobsf_scan(apk_path):
    """
    Run MobSF scan on the specified APK file using the MobSF API.
    """
    api_key = "c02e83a8f386a3aee4d8a788034322436252562d6752f84727004e8c736fb05a"
    url = "http://127.0.0.1:8000/api/v1/scan"  # Update with your MobSF API URL
    headers = {"Authorization": api_key}  # Update with your API key header

    try:
        with open(apk_path, "rb") as apk_file:
            files = {"file": apk_file}
            response = requests.post(url, headers=headers, files=files)
            response_data = response.json()
            return response_data
    except Exception as e:
        print("MobSF scan failed:", e)
        return None

def run_qark_scan(apk_path):
    """
    Run QARK scan on the specified APK file.
    """
    try:
        output = subprocess.check_output(['qark', '--apk', apk_path, '--output', 'json'])
        return json.loads(output.decode('utf-8'))
    except subprocess.CalledProcessError as e:
        print("QARK scan failed:", e)
        return None

def analyze_apk(apk_path):
    """
    Analyze the specified APK file using AndroGuard.
    """
    try:
        a, d, dx = AnalyzeAPK(apk_path)
        return {
            "activities": a.get_activities(),
            "permissions": d.get_permissions(),
            "classes": len(dx.get_classes())
        }
    except Exception as e:
        print("AndroGuard analysis failed:", e)
        return None
'''
def check_for_root():
    """
    Check for root access using Rootbeer.
    """
    try:
        rb = RootBeer()
        return rb.isRooted()
    except Exception as e:
        print("Root check failed:", e)
        return None
'''
def run_all_analysis(apk_path):
    """
    Run all analysis tools on the specified APK file and save results to a report file.
    """
    report = ""
    '''
    # Run MOBSF scan
    mobsf_result = run_mobsf_scan(apk_path)
    if mobsf_result:
        report += "MOBSF:\n" + json.dumps(mobsf_result, indent=4) + "\n\n"
    
    # Run QARK scan
    qark_result = run_qark_scan(apk_path)
    if qark_result:
        report += "QARK:\n" + json.dumps(qark_result, indent=4) + "\n\n"
    
    # Check for root access
    
    root_status = check_for_root()
    if root_status is not None:
        report += f"Root Status: {'Rooted' if root_status else 'Not Rooted'}\n\n"    
    '''
    # Run AndroGuard analysis
    androguard_result = analyze_apk(apk_path)
    if androguard_result:
        report += "AndroGuard:\n" + json.dumps(androguard_result, indent=4) + "\n\n"
    
    return report
    
def write_report(report, output_file):
    """
    Write the analysis report to a text file.
    """
    with open(output_file, 'w') as f:
        f.write(report)

# Example usage
if __name__ == "__main__":
    apk_path = '/path/to/your/app.apk'
    output_file = 'report.txt'
    analysis_report = run_all_analysis(apk_path)
    if analysis_report:
        write_report(analysis_report, output_file)
        print(f"Analysis report saved to {output_file}")
    else:
        print("Analysis failed.")
