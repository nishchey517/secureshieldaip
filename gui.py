import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog, filedialog
from PIL import Image, ImageTk
from apk_selector import select_apk_file
from apk_analyzer import analyze_apk
from apk_fullanalyzer import run_all_analysis
from permission_analyzer import analyze_permissions
from network_traffic_analyzer import analyze_network_traffic
from report_printer import print_vulnerabilities
from pdf_saver import save_as_pdf
from virustotal_checker import check_virustotal
from ai_malware_detector import load_model, extract_features, predict_malware
from mfa import generate_otp, verify_otp, generate_qr_code
from validate_certificate import validate_certificate

class APKVulnerabilityCheckerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("APK Vulnerability Checker")
        self.root.configure(bg="black")

        self.file_path = None
        self.api_key = "e691e118ebb3f22d46c47009a914fde6d8631d3af8caa8a8a031c915d66665f0"  # Replace with your actual VirusTotal API key
        self.report_content = ""
        self.model = load_model()
        self.generated_otp = generate_otp()
        self.username = "user"

        if self.model is None:
                messagebox.showerror("Error", "AI model not loaded. Please check the model file.")

        # Create and place widgets
        self.create_widgets()

    def create_widgets(self):
        '''
        # Load and display logo
        logo_img = Image.open("logo.jpg")
        logo_render = ImageTk.PhotoImage(logo_img)
        self.logo_label = tk.Label(self.root, image=logo_render, bg="black")
        self.logo_label.image = logo_render
        self.logo_label.grid(row=0, column=0, columnspan=8, padx=10, pady=10)
'''
        # Select APK button
        self.select_button = tk.Button(self.root, text="Select APK", command=self.select_file, bg="#4CAF50", fg="white")
        self.select_button.grid(row=1, column=0, padx=10, pady=10, sticky="ew")

        # Analyze APK button
        self.analyze_button = tk.Button(self.root, text="Analyze", command=self.analyze_file, bg="#FF5722", fg="white")
        self.analyze_button.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        # Analyze Permissions button
        self.permission_button = tk.Button(self.root, text="Analyze Permissions", command=self.analyze_permissions, bg="#2196F3", fg="white")
        self.permission_button.grid(row=1, column=2, padx=10, pady=10, sticky="ew")

        # Analyze Network Traffic button
        self.network_button = tk.Button(self.root, text="Analyze Network Traffic", command=self.analyze_network_traffic, bg="#FFC107", fg="white")
        self.network_button.grid(row=1, column=3, padx=10, pady=10, sticky="ew")

        # Verify MFA button
        self.mfa_button = tk.Button(self.root, text="Verify MFA", command=self.verify_mfa, bg="#009688", fg="white")
        self.mfa_button.grid(row=1, column=4, padx=10, pady=10, sticky="ew")

        # Check VirusTotal button
        self.virustotal_button = tk.Button(self.root, text="Check VirusTotal", command=self.check_virustotal, bg="#607D8B", fg="white")
        self.virustotal_button.grid(row=1, column=5, padx=10, pady=10, sticky="ew")

        # AI Malware Detection button
        self.ai_button = tk.Button(self.root, text="AI Malware Detection", command=self.ai_malware_detection, bg="#9C27B0", fg="white")
        self.ai_button.grid(row=1, column=6, padx=10, pady=10, sticky="ew")

        # Save PDF button
        self.save_pdf_button = tk.Button(self.root, text="Save Full Analysis as PDF", command=self.save_full_analysis_pdf, bg="#FF9800", fg="white")
        self.save_pdf_button.grid(row=1, column=8, padx=10, pady=10, sticky="ew")

        # Check Certificate button
        self.check_certificate_button = tk.Button(self.root, text="Validate Certificates", command=self.validate_certificate, bg="#FF9800", fg="white")
        self.check_certificate_button.grid(row=1, column=7, padx=10, pady=10, sticky="ew")

        # Text area for displaying output
        self.text_area = scrolledtext.ScrolledText(self.root, width=100, height=30, bg="white")
        self.text_area.grid(row=2, column=0, columnspan=8, padx=12, pady=12, sticky="nsew")

        # Footer
        self.footer_label = tk.Label(self.root, text="Developed by Code Guardians", bg="black", fg="white", font=("Arial", 14))
        self.footer_label.grid(row=4, column=0, columnspan=8, padx=10, pady=10, sticky="ew")

        # Configure grid layout to resize with window
        for i in range(8):
            self.root.grid_columnconfigure(i, weight=1)
        self.root.grid_rowconfigure(2, weight=1)


    def show_qr_code(self, img_path):
        self.qr_code_render = Image.open(img_path)
        self.qr_code_render = ImageTk.PhotoImage(self.qr_code_render)
        self.qr_code_label = tk.Label(self.root, image=self.qr_code_render)
        self.qr_code_label.grid(row=3, column=0, columnspan=8, padx=10, pady=10, sticky="ew")

    def select_file(self):
        self.file_path = select_apk_file()
        if self.file_path:
            self.text_area.insert(tk.END, f"Selected APK file: {self.file_path}\n")

    def analyze_file(self):
        if not self.file_path:
            messagebox.showwarning("Warning", "No APK file selected")
            return

        report = analyze_apk(self.file_path)
        if report:
            try:
                self.text_area.insert(tk.END, report)
                self.report_content += report
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred while analyzing the file: {e}")

    def analyze_permissions(self):
        if not self.file_path:
            messagebox.showwarning("Warning", "No APK file selected")
            return

        permissions_report = analyze_permissions(self.file_path)
        self.text_area.insert(tk.END, permissions_report)
        self.report_content += permissions_report
    
    def validate_certificate(self):
        if not self.file_path:
            messagebox.showwarning("Warning", "No APK file selected")
            return
        
        is_valid_certificate = validate_certificate(self.file_path)
        if is_valid_certificate:
            print("Certificate is valid.")
        else:
            print("Certificate is invalid or cannot be validated.")


    def analyze_network_traffic(self):
        if not self.file_path:
            messagebox.showwarning("Warning", "No APK file selected")
            return

        network_report = analyze_network_traffic(self.file_path)
        self.text_area.insert(tk.END, network_report)
        self.report_content += network_report

    def check_virustotal(self):
        if not self.file_path:
            messagebox.showwarning("Warning", "No APK file selected")
            return

        virustotal_report = check_virustotal(self.file_path, self.api_key)
        self.text_area.insert(tk.END, virustotal_report)
        self.report_content += virustotal_report

    def ai_malware_detection(self):
        if not self.file_path:
            messagebox.showwarning("Warning", "No APK file selected")
            return

        if not self.model:
            messagebox.showwarning("Warning", "AI model not loaded")
            return

        features = extract_features(self.file_path)
        prediction = predict_malware(self.model, features)
        self.text_area.insert(tk.END, f"AI Malware Detection Result: {'Malware' if prediction else 'Safe'}\n")
        self.report_content += f"AI Malware Detection Result: {'Malware' if prediction else 'Safe'}\n"

    def verify_mfa(self):
        self.generated_otp = generate_otp()
        qr_code_path = generate_qr_code(self.generated_otp)
        self.show_qr_code(qr_code_path)
        entered_otp = simpledialog.askstring("MFA Verification", "Enter the OTP:")
        if verify_otp(self.generated_otp, entered_otp):
            messagebox.showinfo("Success", "MFA Verified Successfully")
        else:
            messagebox.showwarning("Failure", "MFA Verification Failed")
        # Hide the QR code after verification
        self.hide_qr_code()

    def hide_qr_code(self):
        if self.qr_code_label:
            self.qr_code_label.destroy()

    def save_full_analysis_pdf(self):
        if not self.report_content:
            messagebox.showwarning("Warning", "No analysis performed yet")
            return

        output_file = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
        if output_file:
            pdf_file = save_as_pdf(self.report_content, output_file)
            messagebox.showinfo("Info", f"Full analysis report saved to: {pdf_file}")


def main():
    root = tk.Tk()
    app = APKVulnerabilityCheckerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
