# image_parser.py
#
# Extracts text directly from image formats (PNG, JPG, etc.) to catch 
# scammers who embed their notices in pictures to evade text scanners.

import pytesseract
from PIL import Image
import os

def extract_text_from_image(image_path):
    if not os.path.exists(image_path):
        return None

    try:
        img = Image.open(image_path)
        text = pytesseract.image_to_string(img)
        return text.strip()
    except Exception as e:
        return f"[Image Processing Error: {e}]"
