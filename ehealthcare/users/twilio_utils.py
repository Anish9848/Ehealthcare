import os
import time
from twilio.rest import Client
from django.conf import settings
import logging
from datetime import datetime
import pytz

logger = logging.getLogger(__name__)

# Global variable to track the last SMS sent time for each phone number
# This acts as a basic rate limiting mechanism
last_sms_sent_times = {}

def send_otp_sms(phone_number, otp):
    """
    Send OTP via Twilio SMS with rate limiting and proper formatting.
    Ensures multiple OTPs aren't sent to the same number within 30 seconds.
    """
    # Rate limiting check - prevents sending multiple OTPs too quickly to same number
    current_time = time.time()
    if phone_number in last_sms_sent_times:
        time_since_last = current_time - last_sms_sent_times[phone_number]
        if time_since_last < 30:  # 30 seconds minimum between OTPs to same number
            logger.warning(f"Rate limit: OTP to {phone_number} requested too soon ({time_since_last:.1f}s)")
            return False, "Please wait before requesting another code"
    
    # Update the last SMS sent time for this number
    last_sms_sent_times[phone_number] = current_time
    
    # Debug mode for development environments
    if settings.TWILIO_DEBUG_MODE:
        print(f"\n=== DEBUG MODE: OTP for {phone_number} is {otp} ===\n")
        return True, "DEBUG_MODE"
    
    # Generate current time in Nepal timezone
    local_tz = pytz.timezone("Asia/Kathmandu")
    current_time = datetime.now(local_tz)
    formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
    
    # Create message with proper formatting
    message_body = (
        f"Your E-Healthcare verification code is: {otp}\n\n"
        f"This code will expire in 5 minutes.\n"
        f"Time: {formatted_time}\n\n"
        f"If you didn't request this code, please ignore this message."
    )
    
    try:
        client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        message = client.messages.create(
            body=message_body,
            from_=settings.TWILIO_PHONE_NUMBER,
            to=phone_number
        )
        
        logger.info(f"OTP sent successfully to {phone_number}, SID: {message.sid}")
        return True, message.sid
    except Exception as e:
        logger.error(f"Failed to send OTP to {phone_number}: {str(e)}")
        return False, str(e)