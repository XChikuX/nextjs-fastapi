from typing import Tuple
from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr
import dns.resolver
from disposable_email_domains import blocklist

import smtplib
import socket


async def email_deduplication_and_spam_trap_removal(email: EmailStr, domain: str) -> Tuple[bool, str]:
    if domain in blocklist:
        return False, "Email domain is in the blocklist of invalid or disposable emails."
    return True, ""

async def domain_validation(email: EmailStr, domain: str) -> Tuple[bool, str]:
    
    try:
        dns.resolver.resolve(domain, 'A')
        return True, ""
    except dns.resolver.NXDOMAIN:
        return False, "DNS entry not found for the domain."

async def risk_validation(email: EmailStr, domain: str) -> Tuple[bool, str]:
    
    # Replace with your high-risk email database check
    return True, ""

async def mta_validation(email: EmailStr, domain: str) -> Tuple[bool, str]:
    
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        for mx in mx_records:  # type: ignore
            if mx.preference == 0:
                return False, "Catch-all address detected."
        return True, ""
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return False, "MX record not found for the domain."


async def check_email_deliverability(email: EmailStr, domain: str):
    
    # Perform DNS lookup for MX records
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
    except dns.resolver.NXDOMAIN:
        return False, "MX record not found for the domain."
    
    # Sort MX records by preference
    mx_records = sorted(mx_records, key=lambda record: record.preference)  # type: ignore
    
    # Perform SMTP handshake
    for mx_record in mx_records:
        print(mx_record)
        mx_server = str(mx_record.exchange)
        
        try:
            # Connect to the mail server
            server = smtplib.SMTP(host=mx_server, timeout=3)
            
            # Start TLS for security
            server.starttls()
            
            # SMTP 'helo' command
            server.helo()
            
            # SMTP 'mail from' command
            server.mail('')
            
            # SMTP 'rcpt to' command
            code, message = server.rcpt(email)
            
            # Close the connection
            server.quit()
            
            # Check if the server is willing to accept mail
            if code == 250:
                return True, "Email is deliverable."
            else:
                return False, "Email is not deliverable."
        except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected, socket.timeout):
            continue
    
    return False, "Could not connect to any mail server."

##### START HERE########
class Email(BaseModel):
    name: EmailStr

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.get("/favicon.ico")
async def favicon() -> FileResponse:
    return FileResponse("favicon.ico")


@app.post("/verify_email")
async def verify_email(email: Email) -> dict:
    steps = [
        email_deduplication_and_spam_trap_removal,
        domain_validation,
        risk_validation,
        mta_validation,
        #check_email_deliverability
    ]
    domain = email.name.split('@')[1]
    for step in steps:
        is_valid, message = await step(email.name, domain)
        if not is_valid:
            return {"is_valid": False, "message": message}
    
    return {"is_valid": True, "message": "Email is valid."}
