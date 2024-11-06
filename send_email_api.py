import os
import json
import re
import html
import bleach
import logging
from enum import Enum
from email_services.workmail_service import WorkMailService
from email_services.gmail_service import GmailService
from email_services.outlook_service import OutlookService
from email_services.yahoo_service import YahooService
from email_services.zoho_service import ZohoService

# Logging Configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

# Constants Section
MAX_SUBJECT_LENGTH = 255
MAX_BODY_LENGTH = 5000
EMAIL_REGEX = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
SUBJECT_REGEX = r'^[\w\s\-\_\!\?\.]*$'
BODY_REGEX = r'^[\w\s\.\,\!\?\:\;\-\'\"\(\)\[\]]*$'
ALLOWED_HTML_TAGS = ['b', 'i', 'p', 'u', 'em', 'strong', 'a', 'br', 'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'code', 'pre', 'img']

# Error Messages Section
ERROR_MESSAGES = {
    "subject_length_exceeded": "Subject must be less than 255 characters",
    "subject_invalid_chars": "Subject contains invalid characters",
    "body_length_exceeded": "Body content must be less than 5000 characters",
    "body_contains_invalid_character": "Body contains invalid characters",
    "invalid_service_type": "Invalid service type provided",
    "invalid_email": "Invalid email format",
}

class EmailServiceType(Enum):
    WORKMAIL = "workmail"
    GMAIL = "gmail"
    OUTLOOK = "outlook"
    YAHOO = "yahoo"
    ZOHO = "zoho"

def validate_subject(subject):
    logger.debug("Validating subject...")
    # Escape HTML tags to prevent any HTML injection or XSS
    subject = html.escape(subject)

    # Enforce a length limit (e.g., 255 characters)
    if len(subject) > MAX_SUBJECT_LENGTH:
        logger.error(f"Subject exceeds max length: {len(subject)} > {MAX_SUBJECT_LENGTH}")
        raise ValueError(ERROR_MESSAGES["subject_length_exceeded"])

    # Allow only alphanumeric and specific special characters
    if not re.match(SUBJECT_REGEX, subject):
        logger.error(f"Subject contains invalid characters: {subject}")
        raise ValueError(ERROR_MESSAGES["subject_invalid_chars"])

    logger.info(f"Subject validated successfully: {subject}")
    return subject

def validate_body(body):
    logger.debug("Validating body...")
    # Escape HTML tags to prevent any HTML injection or XSS
    body = html.escape(body)

    # Enforce a length limit (e.g., 5000 characters)
    if len(body) > MAX_BODY_LENGTH:
        logger.error(f"Body exceeds max length: {len(body)} > {MAX_BODY_LENGTH}")
        raise ValueError(ERROR_MESSAGES["body_length_exceeded"])

    # Allow only a restricted set of characters (alphanumeric, common punctuation, and whitespace)
    # Adjust the regex as needed to match acceptable punctuation for your use case
    if not re.match(BODY_REGEX, body):
        logger.error(f"Body contains invalid characters: {body}")
        raise ValueError(ERROR_MESSAGES["body_contains_invalid_character"])

    # Sanitize HTML content using bleach to allow only safe tags
    body = bleach.clean(body, tags=ALLOWED_HTML_TAGS, strip=True)
    logger.info(f"Body sanitized successfully: {body[:100]}...")  # Log first 100 chars for preview
    return body

def validate_and_sanitize(event):
    logger.info("Starting validation and sanitization...")
    # Validate and sanitize service_type
    service_type_str = event.get("service_type", EmailServiceType.WORKMAIL.value).strip().lower()
    try:
        service_type = EmailServiceType(service_type_str)
    except ValueError:
        logger.error(f"Invalid service type: {service_type_str}")
        raise ValueError(ERROR_MESSAGES["invalid_service_type"])

    to_email = os.getenv("TO_EMAIL")

    # Validate and sanitize from_email (customer email address)
    from_email = event.get("from_email", "").strip()
    if not re.match(EMAIL_REGEX, from_email):
        logger.error(f"Invalid email format: {from_email}")
        raise ValueError(ERROR_MESSAGES["invalid_email"])

    # Validate and sanitize subject
    subject = validate_subject(event.get("subject", "").strip())

    # Validate and sanitize body
    body = validate_body(event.get("body", "").strip())

    logger.info("Validation and sanitization complete.")
    return service_type, to_email, from_email, subject, body

def get_email_service(service_type):
    logger.debug(f"Fetching email service for: {service_type}")
    """Initialize the appropriate email service based on service_type."""
    if service_type == EmailServiceType.WORKMAIL:
        return WorkMailService(
            region_name=os.getenv("WORKMAIL_REGION"),
            access_key=os.getenv("WORKMAIL_ACCESS_KEY"),
            secret_key=os.getenv("WORKMAIL_SECRET_KEY"),
            workmail_domain=os.getenv("WORKMAIL_DOMAIN")
        )
    elif service_type == EmailServiceType.GMAIL:
        return GmailService(
            client_id=os.getenv("GMAIL_CLIENT_ID"),
            client_secret=os.getenv("GMAIL_CLIENT_SECRET"),
            refresh_token=os.getenv("GMAIL_REFRESH_TOKEN")
        )
    elif service_type == EmailServiceType.OUTLOOK:
        return OutlookService(
            client_id=os.getenv("OUTLOOK_CLIENT_ID"),
            client_secret=os.getenv("OUTLOOK_CLIENT_SECRET"),
            refresh_token=os.getenv("OUTLOOK_REFRESH_TOKEN")
        )
    elif service_type == EmailServiceType.YAHOO:
        return YahooService(
            app_password=os.getenv("YAHOO_APP_PASSWORD"),
            username=os.getenv("YAHOO_USERNAME")
        )
    elif service_type == EmailServiceType.ZOHO:
        return ZohoService(
            client_id=os.getenv("ZOHO_CLIENT_ID"),
            client_secret=os.getenv("ZOHO_CLIENT_SECRET"),
            refresh_token=os.getenv("ZOHO_REFRESH_TOKEN")
        )
    else:
        logger.error(f"Unsupported email service type: {service_type}")
        raise ValueError("Unsupported email service type")

def lambda_handler(event, context):
    try:
        logger.info("Lambda function execution started.")
        # Parse and validate input
        service_type, to_email, subject, body = validate_and_sanitize(event)

    
