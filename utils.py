import os
import re
import uuid
from datetime import datetime
from urllib.parse import urlparse

from werkzeug.utils import secure_filename


ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "bmp", "webp"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def save_upload(file_storage, upload_folder):
    os.makedirs(upload_folder, exist_ok=True)
    filename = secure_filename(file_storage.filename)
    ext = filename.rsplit(".", 1)[1].lower() if "." in filename else "png"
    saved_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:10]}.{ext}"
    path = os.path.join(upload_folder, saved_name)
    file_storage.save(path)
    return saved_name, path


def normalize_url(content):
    text = (content or "").strip()
    if not text:
        return ""
    parsed = urlparse(text)
    if parsed.scheme and parsed.netloc:
        return text
    if re.match(r"^[\w.-]+\.[a-zA-Z]{2,}(/.*)?$", text):
        return f"https://{text}"
    return text


def status_from_score(score):
    if score <= 25:
        return "Safe"
    if score <= 60:
        return "Suspicious"
    return "Dangerous"


def status_color(status):
    return {"Safe": "success", "Suspicious": "warning", "Dangerous": "danger"}.get(status, "secondary")
