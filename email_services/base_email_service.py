from abc import ABC, abstractmethod
import logging

# Set up logging for email services
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BaseEmailService(ABC):
    def __init__(self):
        # Initialize any common attributes here if needed
        self.to_email = None
        self.subject = None
        self.body = None

    @abstractmethod
    def send_email(self, to_email, subject, body):
        """
        Method to send an email. Must be implemented by subclasses.
        """
        pass

    def sanitize_input(self, data):
        """
        Basic sanitization to avoid injection attacks (like HTML/JS injection).
        """
        import html
        return html.escape(data)
