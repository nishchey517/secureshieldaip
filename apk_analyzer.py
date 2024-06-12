import subprocess
import os
from androguard.misc import AnalyzeAPK
from OpenSSL import crypto
import zipfile

def verify_signature(file_path):
    with zipfile.ZipFile(file_path, 'r') as zip:
        for file in zip.namelist():
            if file.startswith('META-INF/') and (file.endswith('.RSA') or file.endswith('.DSA')):
                with zip.open(file) as cert_file:
                    cert_data = cert_file.read()
                    cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_data)
                    return cert.get_subject()
                    
def analyze_apk(file_path):
    # Define the directory containing AndroBugs_Framework
    androbugs_dir = 'AndroBugs_Framework'

    # Define the output file path
    output_file = "vulnerability_report.txt"

    # Construct the command to run AndroBugs analysis
    command = f"python3 {os.path.join(androbugs_dir, 'androbugs.py')} -f {file_path} -o {output_file}"
    print("-------------------------Command Printed-----------"+command)
    try:
        # Run the AndroBugs analysis command
        process = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        print("Process = ", process)
        print("------------------Process Printed-----------")
        # Check if the process completed successfully
        if process.returncode == 0:
            print(f"Vulnerability report saved to: {output_file}")

            # Assuming 'static_analysis' is a defined function, call it here
            static_analysis_report = static_analysis(file_path)

            # Combine the AndroBugs report with the static analysis report
            combined_report = f"{output_file}"+"\n"+f"{static_analysis_report}"
            return combined_report

    # Handle subprocess errors
    except subprocess.CalledProcessError as e:
        print("Error running AndroBugs:")
        print(e.stderr)
        return None

    # Handle other exceptions
    except Exception as e:
        print("An error occurred:")
        print(e)
        return None

def static_analysis(file_path):
    a, d, dx = AnalyzeAPK(file_path)
    analysis_report = "Static Analysis Report:"+"\n"
    analysis_report += f"Package: {a.get_package()}"+"\n"
    analysis_report += f"Main Activity: {a.get_main_activity()}"+"\n"
    analysis_report += "Permissions:"+"\n"
    for perm in a.get_permissions():
        analysis_report += f"- {perm}"+"\n"
    return analysis_report
