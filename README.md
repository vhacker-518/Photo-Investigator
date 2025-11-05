# Photo Investigator


Photo Investigator is a secure, privacy-first tool for analyzing images: EXIF extraction, OCR, screenshot detection, reverse image search and leak-checking helpers.


## Key features
- EXIF metadata extraction (date, camera make/model, GPS fallback)
- Screenshot detection and PC-spec hint extraction via OCR
- Fast OCR (pytesseract) with preprocessing optimizations
- Reverse image search helpers (Google Lens, Bing, TinEye, Yandex) — manual or upload with explicit consent
- Safe leak-check (filename/web-text scan) — no automatic uploads by default
- Export report as TXT or PDF
- Dual-language GUI: English & Arabic


## Requirements
- Python 3.14
- System Tesseract OCR engine (separate install)
- Python packages: pillow, exifread, piexif, requests, colorama, pytesseract, fpdf


Install dependencies:
