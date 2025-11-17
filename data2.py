from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet
import qrcode

def generate_pdf_certificate(certificate_data, output_path):
    """Generate a professional PDF certificate with QR code."""
    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    story.append(Paragraph("DATA WIPE CERTIFICATE", styles['Title']))
    story.append(Spacer(1, 12))
    
    # Certificate details
    story.append(Paragraph(f"Device: {certificate_data['device']['device_id']}", styles['Normal']))
    story.append(Paragraph(f"Method: {certificate_data['ai_analysis']['selected_method']}", styles['Normal']))
    story.append(Paragraph(f"Timestamp: {certificate_data['system_info']['certificate_timestamp']}", styles['Normal']))
    
    # QR Code with verification URL
    qr = qrcode.make(json.dumps(certificate_data, sort_keys=True))
    qr_path = "/tmp/cert_qr.png"
    qr.save(qr_path)
    
    story.append(Spacer(1, 12))
    story.append(Image(qr_path, width=100, height=100))
    story.append(Paragraph("Scan to verify certificate", styles['Small']))
    
    doc.build(story)
