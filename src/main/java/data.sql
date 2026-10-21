INSERT IGNORE INTO scam_rules (rule_code, category, keyword_or_pattern, weight, description_en, source_url, is_active, reviewed_at) VALUES
('OTP_SHARE', 'credentials', 'share otp', 30, 'The message asks the recipient to share an OTP.', 'https://rbi.org.in/Scripts/NotificationUser.aspx?Id=11917', 1, CURRENT_DATE),
('DIGITAL_ARREST', 'impersonation', 'digital arrest', 40, 'Mentions a fake digital arrest or CBI threat.', 'https://cybercrime.gov.in', 1, CURRENT_DATE),
('URGENT_KYC', 'phishing', 'kyc is expired', 30, 'Uses urgency regarding a frozen account or KYC.', 'https://sancharsaathi.gov.in', 1, CURRENT_DATE),
('ANYDESK_APP', 'remote_access', 'anydesk', 40, 'Asks you to install a remote-access application.', 'https://rbi.org.in', 1, CURRENT_DATE);