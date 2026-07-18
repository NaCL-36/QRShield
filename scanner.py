import cv2
import numpy as np


class QRScanError(Exception):
    pass


def decode_qr_image(image_path):
    """Decode the first QR payload found in an uploaded image using OpenCV."""
    try:
        image_bytes = np.fromfile(image_path, dtype=np.uint8)
        image = cv2.imdecode(image_bytes, cv2.IMREAD_COLOR)
    except Exception as exc:
        raise QRScanError(f"Unable to read the uploaded image: {exc}") from exc

    if image is None:
        raise QRScanError("Unable to read the uploaded image. Please upload a valid image file.")

    detector = cv2.QRCodeDetector()
    decoded_text, points, _ = detector.detectAndDecode(image)

    if not decoded_text and points is None:
        raise QRScanError("No QR code was detected in the uploaded image.")
    if not decoded_text:
        raise QRScanError("A QR code was detected, but its content could not be decoded. Try a clearer image.")

    return decoded_text
