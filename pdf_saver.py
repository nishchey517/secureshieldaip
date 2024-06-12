
import pdfkit
import os

def save_as_pdf(report_content, output_file):
    # Set the path to wkhtmltopdf executable
    if os.name == 'nt':  # Windows
        path_to_wkhtmltopdf = r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe'
    elif os.name == 'posix':  # macOS/Linux
        path_to_wkhtmltopdf = '/usr/local/bin/wkhtmltopdf'  # Homebrew installation path for macOS
        # Alternatively, you can use the following path for typical Linux installations
        # path_to_wkhtmltopdf = '/usr/bin/wkhtmltopdf'
    else:
        raise EnvironmentError('Unsupported operating system')

    config = pdfkit.configuration(wkhtmltopdf=path_to_wkhtmltopdf)
    
    pdfkit.from_string(report_content, output_file, configuration=config)
    return output_file
