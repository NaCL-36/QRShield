import os
from datetime import datetime

from flask import Flask, jsonify, redirect, render_template, request, send_file, url_for
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from analyzer import analyze_content
from scanner import QRScanError, decode_qr_image
from utils import allowed_file, save_upload, status_color


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
REPORT_FOLDER = os.path.join(BASE_DIR, "reports")

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["REPORT_FOLDER"] = REPORT_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024
app.secret_key = os.environ.get("QRSHIELD_SECRET_KEY", "qrshield-dev-secret")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)


@app.context_processor
def inject_branding():
    return {"app_name": "QRShield", "slogan": "Scan Smart. Stay Safe."}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan")
def scan():
    return render_template("scan.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    if "qr_image" not in request.files:
        return render_template("scan.html", error="Please upload a QR code image."), 400

    file = request.files["qr_image"]
    if not file.filename:
        return render_template("scan.html", error="Please choose an image file."), 400
    if not allowed_file(file.filename):
        return render_template("scan.html", error="Unsupported file type. Use PNG, JPG, GIF, BMP, or WEBP."), 400

    saved_name, image_path = save_upload(file, app.config["UPLOAD_FOLDER"])
    try:
        decoded = decode_qr_image(image_path)
        result = analyze_content(decoded)
    except QRScanError as exc:
        return render_template("scan.html", error=str(exc)), 422

    result["image_filename"] = saved_name
    result["image_url"] = url_for("static", filename=f"uploads/{saved_name}")
    result["created_at"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    result["status_color"] = status_color(result["status"])
    return render_template("result.html", result=result)


@app.route("/api/analyze-text", methods=["POST"])
def api_analyze_text():
    payload = request.get_json(silent=True) or {}
    content = payload.get("content", "")
    result = analyze_content(content)
    result["created_at"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    return jsonify(result)


@app.route("/download-report", methods=["POST"])
def download_report():
    data = request.get_json(silent=True) or request.form.to_dict()
    result = analyze_content(data.get("content", ""))
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    report_path = os.path.join(app.config["REPORT_FOLDER"], f"qrshield-report-{timestamp}.pdf")
    _create_pdf_report(report_path, result)
    return send_file(report_path, as_attachment=True, download_name=os.path.basename(report_path))


def _create_pdf_report(path, result):
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(path, pagesize=letter, title="QRShield Security Report")
    story = [
        Paragraph("QRShield Security Report", styles["Title"]),
        Paragraph("Scan Smart. Stay Safe.", styles["Heading2"]),
        Spacer(1, 14),
        Paragraph(f"Overall Result: <b>{result['status']}</b>", styles["Heading2"]),
        Paragraph(f"Risk Score: <b>{result['score']}/100</b>", styles["Normal"]),
        Paragraph(f"Decoded Content: {result['original_content']}", styles["Normal"]),
        Paragraph(f"Recommendation: {result['recommendation']}", styles["Normal"]),
        Spacer(1, 16),
    ]

    rows = [["Check", "Result", "Details"]]
    for check in result["checks"]:
        rows.append([check["name"], check["result"], check["detail"]])
    for issue in result["issues"]:
        rows.append([issue["title"], issue["status"], issue["detail"]])

    table = Table(rows, colWidths=[140, 90, 300])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0B1120")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#9CA3AF")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ]))
    story.append(table)
    doc.build(story)


if __name__ == "__main__":
    app.run(debug=True)
