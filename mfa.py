import qrcode
from PIL import Image
import random

def generate_otp():
    return random.randint(100000, 999999)

def generate_qr_code(otp):
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=5, border=3)
    qr.add_data(str(otp))
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    img_path = 'mfa_qr_code.png'
    img.save(img_path)
    return img_path

def verify_otp(generated_otp, entered_otp):
    return generated_otp == int(entered_otp)


