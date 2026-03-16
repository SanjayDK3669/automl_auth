"""
email_service.py  —  Gmail SMTP email sender with premium HTML templates
"""
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

EMAIL_ADDRESS  = os.getenv("EMAIL_ADDRESS", "")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")
APP_NAME       = "RaWML.ai"
APP_URL        = os.getenv("APP_URL", "http://localhost:5173")



# ═══════════════════════════════════════════════════════════════
#  Core sender
# ═══════════════════════════════════════════════════════════════

def _send(to: str, subject: str, html: str, text: str = "") -> bool:
    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        print("⚠️ Email credentials not set — skipping email.")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{APP_NAME} <{EMAIL_ADDRESS}>"
        msg["To"] = to

        if text:
            msg.attach(MIMEText(text, "plain"))

        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, to, msg.as_string())

        print(f"✅ Email sent → {to}")
        return True

    except Exception as e:
        print(f"❌ Email failed → {e}")
        return False
# ═══════════════════════════════════════════════════════════════
#  Shared premium layout wrapper  (black & white theme)
# ═══════════════════════════════════════════════════════════════

def _wrap(body_html: str) -> str:
    year = datetime.now().year
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>{APP_NAME}</title>
</head>
<body style="margin:0;padding:0;background:#ebebeb;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#ebebeb;padding:48px 16px;">
  <tr><td align="center">

    <!-- Card -->
    <table width="580" cellpadding="0" cellspacing="0" border="0"
           style="max-width:580px;width:100%;background:#ffffff;border-radius:20px;
                  overflow:hidden;box-shadow:0 8px 48px rgba(0,0,0,.12);">

      <!-- Accent stripe -->
      <tr><td style="background:linear-gradient(90deg,#0a0a0a 0%,#2a2a2a 100%);height:5px;line-height:5px;font-size:0;">&nbsp;</td></tr>

      <!-- Header -->
      <tr>
        <td style="background:#0a0a0a;padding:28px 40px;">
          <table width="100%" cellpadding="0" cellspacing="0" border="0">
            <tr>
              <td style="vertical-align:middle;">
                <table cellpadding="0" cellspacing="0" border="0">
                  <tr>
                    <td style="background:#1e1e1e;border:1px solid #333;border-radius:9px;
                                width:36px;height:36px;text-align:center;vertical-align:middle;">
                      <span style="color:#fff;font-size:16px;line-height:36px;">&#9651;</span>
                    </td>
                    <td style="padding-left:10px;vertical-align:middle;">
                      <span style="color:#ffffff;font-size:19px;font-weight:300;letter-spacing:-.4px;">
                        RaWML<span style="color:#666;">.ai</span>
                      </span>
                    </td>
                  </tr>
                </table>
              </td>
              <td align="right" style="vertical-align:middle;">
                <span style="color:#444;font-size:10px;letter-spacing:2.5px;
                             text-transform:uppercase;font-weight:600;">
                  Automated Intelligence
                </span>
              </td>
            </tr>
          </table>
        </td>
      </tr>

      <!-- Body injected here -->
      <tr><td>{body_html}</td></tr>

      <!-- Footer -->
      <tr>
        <td style="background:#f7f7f7;border-top:1px solid #e8e8e8;padding:22px 40px;">
          <table width="100%" cellpadding="0" cellspacing="0" border="0">
            <tr>
              <td style="font-size:11px;color:#999;line-height:1.7;">
                &copy; {year} RaWML.ai. All rights reserved.<br/>
                You received this because you have an account on RaWML.ai.<br/>
                <span style="color:#bbb;">If you didn't request this, ignore this email — no action needed.</span>
              </td>
              <td align="right" style="vertical-align:top;">
                <span style="font-size:10px;color:#d0d0d0;letter-spacing:2px;font-weight:700;">RaWML.ai</span>
              </td>
            </tr>
          </table>
        </td>
      </tr>

    </table>
    <!-- /Card -->

  </td></tr>
</table>
</body>
</html>"""


# ═══════════════════════════════════════════════════════════════
#  Template 1 — Welcome Email
# ═══════════════════════════════════════════════════════════════

def send_welcome_email(to: str, username: str) -> bool:
    body = f"""
    <!-- Hero -->
    <table width="100%" cellpadding="0" cellspacing="0" border="0">
      <tr>
        <td style="padding:52px 40px 36px;text-align:center;
                   background:linear-gradient(180deg,#fafafa 0%,#ffffff 100%);">
          <h1 style="margin:0 0 12px;font-size:30px;font-weight:300;color:#0a0a0a;
                     letter-spacing:-1px;line-height:1.15;">
            Welcome aboard,<br/>
            <strong style="font-weight:800;">{username}</strong>
          </h1>
          <p style="margin:0 auto;font-size:15px;color:#666;line-height:1.65;
                    max-width:360px;">
            Your RaWML.ai account is live. Start building machine learning
            models in minutes — no code required.
          </p>
        </td>
      </tr>
    </table>

    <!-- Divider -->
    <table width="100%" cellpadding="0" cellspacing="0" border="0">
      <tr><td style="padding:0 40px;">
        <div style="border-top:1px solid #ebebeb;"></div>
      </td></tr>
    </table>

    <!-- Features grid -->
    <table width="100%" cellpadding="0" cellspacing="0" border="0">
      <tr><td style="padding:32px 40px 36px;">
        <p style="margin:0 0 20px;font-size:10px;font-weight:800;
                  letter-spacing:2.5px;text-transform:uppercase;color:#bbb;">
          What you can do now
        </p>

        <!-- Row 1 -->
        <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:10px;">
          <tr>
            <td style="width:50%;padding-right:6px;vertical-align:top;">
              <table width="100%" cellpadding="0" cellspacing="0" border="0"
                     style="background:#f8f8f8;border:1px solid #e8e8e8;border-radius:14px;">
                <tr><td style="padding:20px;">
                  <div style="font-size:22px;margin-bottom:10px;">📊</div>
                  <div style="font-size:13px;font-weight:800;color:#0a0a0a;
                               margin-bottom:5px;letter-spacing:-.2px;">AutoML Studio</div>
                  <div style="font-size:12px;color:#888;line-height:1.55;">
                    Upload a CSV, train 12+ models automatically, and download the best one.
                  </div>
                </td></tr>
              </table>
            </td>
            <td style="width:50%;padding-left:6px;vertical-align:top;">
              <table width="100%" cellpadding="0" cellspacing="0" border="0"
                     style="background:#f8f8f8;border:1px solid #e8e8e8;border-radius:14px;">
                <tr><td style="padding:20px;">
                  <div style="font-size:22px;margin-bottom:10px;">🔎</div>
                  <div style="font-size:13px;font-weight:800;color:#0a0a0a;
                               margin-bottom:5px;letter-spacing:-.2px;">RAG Chat</div>
                  <div style="font-size:12px;color:#888;line-height:1.55;">
                    Upload PDFs and chat with an AI that retrieves answers from your documents.
                  </div>
                </td></tr>
              </table>
            </td>
          </tr>
        </table>

        <!-- Row 2 -->
        <table width="100%" cellpadding="0" cellspacing="0" border="0">
          <tr>
            <td style="width:50%;padding-right:6px;vertical-align:top;">
              <table width="100%" cellpadding="0" cellspacing="0" border="0"
                     style="background:#f8f8f8;border:1px solid #e8e8e8;border-radius:14px;">
                <tr><td style="padding:20px;">
                  <div style="font-size:22px;margin-bottom:10px;">📈</div>
                  <div style="font-size:13px;font-weight:800;color:#0a0a0a;
                               margin-bottom:5px;letter-spacing:-.2px;">Drift Detection</div>
                  <div style="font-size:12px;color:#888;line-height:1.55;">
                    Catch data drift before deploying — powered by Evidently AI.
                  </div>
                </td></tr>
              </table>
            </td>
            <td style="width:50%;padding-left:6px;vertical-align:top;">
              <table width="100%" cellpadding="0" cellspacing="0" border="0"
                     style="background:#0a0a0a;border-radius:14px;">
                <tr><td style="padding:20px;">
                  <div style="font-size:22px;margin-bottom:10px;">⚡</div>
                  <div style="font-size:13px;font-weight:800;color:#ffffff;
                               margin-bottom:5px;letter-spacing:-.2px;">Groq AI Chat</div>
                  <div style="font-size:12px;color:#888;line-height:1.55;">
                    Near-instant AI answers about your models, powered by Groq LLM.
                  </div>
                </td></tr>
              </table>
            </td>
          </tr>
        </table>

      </td></tr>
    </table>

    <!-- CTA -->
    <table width="100%" cellpadding="0" cellspacing="0" border="0">
      <tr><td style="padding:0 40px 52px;text-align:center;">
        <a href="{APP_URL}"
           style="display:inline-block;background:#0a0a0a;color:#ffffff;
                  text-decoration:none;padding:15px 40px;border-radius:11px;
                  font-size:14px;font-weight:700;letter-spacing:.3px;">
          Open RaWML.ai &rarr;
        </a>
        <p style="margin:18px 0 0;font-size:11px;color:#bbb;">
          Account: <strong style="color:#888;">{to}</strong>
        </p>
      </td></tr>
    </table>
    """
    html = _wrap(body)
    text = (
        f"Welcome to RaWML.ai, {username}!\n\n"
        f"Your account is live. Visit: {APP_URL}\n\n"
        "— The RaWML.ai team"
    )
    return _send(to, f"Welcome to RaWML.ai, {username}!", html, text)


# ═══════════════════════════════════════════════════════════════
#  Template 2 — Password Reset OTP Email
# ═══════════════════════════════════════════════════════════════

def send_otp_email(to: str, username: str, otp: str) -> bool:
    # Build individual digit cells
    digit_boxes = ""
    for ch in otp:
        digit_boxes += (
            f'<td style="width:52px;height:66px;background:#0a0a0a;border-radius:12px;'
            f'text-align:center;vertical-align:middle;">'
            f'<span style="font-size:30px;font-weight:900;color:#fff;'
            f'font-family:Courier New,Courier,monospace;">{ch}</span>'
            f'</td>'
            f'<td style="width:8px;"></td>'
        )

    body = f"""
    <!-- Hero -->
    <table width="100%" cellpadding="0" cellspacing="0" border="0">
      <tr>
        <td style="padding:48px 40px 28px;text-align:center;">
          <h1 style="margin:0 0 10px;font-size:27px;font-weight:300;color:#0a0a0a;
                     letter-spacing:-.6px;line-height:1.2;">
            Password <strong style="font-weight:800;">Reset</strong> Code
          </h1>
          <p style="margin:0 auto;font-size:14px;color:#666;line-height:1.6;
                    max-width:320px;">
            Hi <strong>{username}</strong>, here is your verification code.
            It is valid for <strong style="color:#0a0a0a;">60 seconds</strong> only.
          </p>
        </td>
      </tr>
    </table>

    <!-- OTP block -->
    <table width="100%" cellpadding="0" cellspacing="0" border="0">
      <tr><td style="padding:0 40px 32px;text-align:center;">
        <table cellpadding="0" cellspacing="0" border="0"
               style="display:inline-table;background:#f5f5f5;
                      border:2px solid #0a0a0a;border-radius:18px;">
          <tr><td style="padding:28px 32px;text-align:center;">

            <p style="margin:0 0 18px;font-size:10px;font-weight:800;
                      letter-spacing:3px;text-transform:uppercase;color:#aaa;">
              Verification Code
            </p>

            <!-- Digit row -->
            <table cellpadding="0" cellspacing="0" border="0" style="margin:0 auto;">
              <tr>
                <td style="width:4px;"></td>
                {digit_boxes}
              </tr>
            </table>

            <p style="margin:18px 0 0;font-size:12px;color:#aaa;letter-spacing:.5px;">
              &#9201; Expires in <strong style="color:#0a0a0a;">60 seconds</strong>
            </p>
          </td></tr>
        </table>
      </td></tr>
    </table>

    <!-- Warning box -->
    <table width="100%" cellpadding="0" cellspacing="0" border="0">
      <tr><td style="padding:0 40px 28px;">
        <table width="100%" cellpadding="0" cellspacing="0" border="0"
               style="background:#fffbeb;border:1.5px solid #fcd34d;border-radius:12px;">
          <tr><td style="padding:16px 20px;">
            <table cellpadding="0" cellspacing="0" border="0">
              <tr>
                <td style="width:22px;vertical-align:top;padding-top:2px;font-size:15px;">&#9888;&#65039;</td>
                <td style="padding-left:10px;font-size:12px;color:#92400e;line-height:1.7;">
                  <strong>Never share this code.</strong>
                  RaWML.ai staff will never ask for your verification code.<br/>
                  If you didn&rsquo;t request a password reset, ignore this email.
                </td>
              </tr>
            </table>
          </td></tr>
        </table>
      </td></tr>
    </table>

    <!-- Steps -->
    <table width="100%" cellpadding="0" cellspacing="0" border="0">
      <tr><td style="padding:0 40px 48px;">
        <p style="margin:0 0 16px;font-size:10px;font-weight:800;
                  letter-spacing:2.5px;text-transform:uppercase;color:#bbb;">
          Next steps
        </p>
        {"".join([
          f'<table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:10px;">'
          f'<tr>'
          f'<td style="width:30px;height:30px;background:#0a0a0a;border-radius:50%;'
          f'text-align:center;vertical-align:middle;font-size:11px;'
          f'font-weight:800;color:#fff;flex-shrink:0;">{n}</td>'
          f'<td style="padding-left:14px;font-size:13px;color:#444;vertical-align:middle;line-height:1.5;">{step}</td>'
          f'</tr></table>'
          for n, step in [
            ("1", "Enter the 6-digit code on the verification screen"),
            ("2", "You have <strong style='color:#0a0a0a;'>60 seconds</strong> — act fast"),
            ("3", "Set a strong new password (minimum 8 characters)"),
          ]
        ])}
      </td></tr>
    </table>
    """
    html = _wrap(body)
    text = (
        f"RaWML.ai — Password Reset\n\n"
        f"Hi {username},\n\n"
        f"Your verification code is: {otp}\n\n"
        f"This code expires in 60 seconds.\n\n"
        f"If you didn't request a reset, ignore this email."
    )
    return _send(to, "Your RaWML.ai verification code", html, text)