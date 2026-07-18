# QRShield

QRShield is a premium Flask cybersecurity web application that scans QR codes, extracts hidden content, analyzes URLs for phishing indicators, and generates clear risk reports before users open suspicious links.

## Features

- QR image upload with drag-and-drop preview powered by OpenCV QRCodeDetector
- HTTPS, IP address, URL shortener, suspicious keyword, long URL, encoded URL, redirect, and typosquatting checks
- Risk score from 0 to 100 with Safe, Suspicious, and Dangerous statuses
- Professional responsive dark cyber UI with custom SVG logo and loading screen
- Browser-local scan history, search, delete, copy URL, dashboard statistics, and dark/light toggle
- Downloadable PDF security report

## Run Locally

```bash
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

## QR Decoding

QRShield uses OpenCV's built-in `QRCodeDetector` for QR decoding, so Windows installs only need the Python packages listed in `requirements.txt`.
