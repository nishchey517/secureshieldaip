import os
import subprocess
import sys

def install_packages():
    try:
        import pip
    except ImportError:
        print("pip is not installed. Please install pip and try again.")
        sys.exit(1)

    requirements = [
        'pyOpenSSL',
        'androguard',
        'pdfkit',
        'requests',
        'scikit-learn',
        'joblib',
        'pyotp',
        'qrcode',
        'pillow',
        'numpy',
        'rootbeer'  
    ]

    for package in requirements:
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
        except subprocess.CalledProcessError:
            print(f"Failed to install {package}. Please install it manually.")
            

def install_androbugs():
    androbugs_repo = 'https://github.com/AndroBugs/AndroBugs_Framework.git'
    androbugs_dir = 'AndroBugs_Framework'

    if not os.path.isdir(androbugs_dir):
        try:
            subprocess.check_call(['git', 'clone', androbugs_repo])
            print("AndroBugs cloned successfully.")
        except subprocess.CalledProcessError:
            print("Failed to clone AndroBugs repository. Please try again.")
            

    if sys.platform.startswith('linux') or sys.platform == 'darwin':
        subprocess.check_call(['chmod', '+x', os.path.join(androbugs_dir, 'androbugs.sh')])

def install_mobsf():
    mobsf_url = 'https://github.com/MobSF/Mobile-Security-Framework-MobSF.git'
    mobsf_dir = 'Mobile-Security-Framework-MobSF'

    if not os.path.isdir(mobsf_dir):
        try:
            subprocess.check_call(['git', 'clone', mobsf_url])
            print("MobSF cloned successfully.")
        except subprocess.CalledProcessError:
            print("Failed to clone MobSF repository. Please try again.")
            

    # Install MobSF dependencies and perform additional setup steps if necessary

def install_quark():
    quark_url = 'https://github.com/quark-links/quark-cli.git'
    quark_dir = 'quark'

    if not os.path.isdir(quark_dir):
        try:
            subprocess.check_call(['git', 'clone', quark_url])
            print("Quark cloned successfully.")
        except subprocess.CalledProcessError:
            print("Failed to clone Quark repository. Please try again.")
            

def check_for_updates():
    print("Checking for updates...")
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--upgrade', 'Androguard', 'pdfkit', 'requests', 'scikit-learn', 'joblib', 'pyotp', 'qrcode'])
        print("All packages are up-to-date.")
    except subprocess.CalledProcessError:
        print("Error checking for updates.")

if __name__ == "__main__":
    install_packages()
    install_androbugs()
    install_mobsf()
    install_quark()
    check_for_updates()
