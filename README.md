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

pip install pillow exifread piexif requests colorama pytesseract fpdf

## Quick start
1. Install Tesseract (Windows: UB‑Mannheim build recommended).
2. Edit `TESSERACT_CMD` in the config if needed.
3. Run GUI: `python image_search_safe_full.py`


## Security & Privacy
- The app never uploads images without your explicit consent.
- Safe leak checks are filename/text-based unless you press `Upload & Search` and confirm.


## License
MIT — see LICENSE file.


Packaging instructions (EXE via PyInstaller)

Quick steps

Install PyInstaller: pip install pyinstaller

From project root run:

pyinstaller --onefile --windowed --add-data "path/to/Tesseract-OCR;Tesseract-OCR" image_search_safe_full.py

The single EXE appears in dist/ — test on a clean Windows VM.

Notes:

Bundling Tesseract binary into EXE is possible but large; recommended approach: ship EXE + instructions to install Tesseract separately or include Tesseract folder next to EXE and set TESSERACT_CMD dynamically.


LICENSE (MIT)

MIT License


Copyright (c) 2025 ml-ftt


Permission is hereby granted, free of charge, to any person obtaining a copy
