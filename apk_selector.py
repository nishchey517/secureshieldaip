import tkinter as tk
from tkinter import filedialog

def select_apk_file():
    root = tk.Tk()
    root.withdraw()  # Hide the root window

    file_path = filedialog.askopenfilename(
        title="Select an APK file",
        filetypes=[("APK files", "*.apk")]
    )

    if file_path:
        print(f"Selected APK file: {file_path}")
        return file_path
    else:
        print("No file selected")
        return None
