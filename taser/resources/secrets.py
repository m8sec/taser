"""Shared secret-detection regex patterns used by Taser tooling."""

SECRET_PATTERNS = {
    # Cloud providers
    'google_api_key': r'AIza[0-9A-Za-z\-_]{35}',
    'google_oauth_token': r'ya29\.[0-9A-Za-z\-_]+',
    'firebase_server_key': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    'aws_access_key_id': r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b',
    'aws_secret_access_key': r'(?i)aws(?:.{0,20})?(?:secret|access)(?:.{0,20})?[\'"`\s:=]{1,10}[A-Za-z0-9/+=]{40}\b',

    # Git hosting / package registries
    'github_pat': r'\bgh(?:p|o|u|s|r)_[A-Za-z0-9_]{36,255}\b',
    'github_fine_grained_pat': r'\bgithub_pat_[A-Za-z0-9_]{80,255}\b',
    'gitlab_pat': r'\bglpat-[A-Za-z0-9\-_]{20,255}\b',
    'npm_token': r'\bnpm_[A-Za-z0-9]{36}\b',
    'pypi_token': r'\bpypi-[A-Za-z0-9_\-]{50,255}\b',

    # AI / developer tooling
    'openai_api_key': r'\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,255}\b',
    'huggingface_token': r'\bhf_[A-Za-z0-9]{30,255}\b',
    'postman_api_key': r'\bPMAK-[0-9a-f]{24}-[0-9a-f]{34}\b',

    # Messaging / collaboration
    'slack_token': r'\bxox(?:a|b|p|r|s)-[A-Za-z0-9-]{10,255}\b',
    'slack_app_token': r'\bxapp-[A-Za-z0-9-]{20,255}\b',
    'discord_bot_token': r'\b(?:mfa\.[A-Za-z0-9_\-]{20,}|[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27})\b',
    'telegram_bot_token': r'\b\d{8,10}:[A-Za-z0-9_\-]{35}\b',
    'sendgrid_api_key': r'\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b',

    # SaaS / payments / communications
    'stripe_secret_key': r'\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{24,}\b',
    'square_token': r'\bsq0(?:atp|csp|at)-[0-9A-Za-z\-_]{22,255}\b',
    'mailgun_api_key': r'\bkey-[0-9A-Za-z]{32}\b',
    'twilio_api_key': r'\bSK[0-9A-Fa-f]{32}\b',
    'twilio_account_sid': r'\bAC[0-9A-Fa-f]{32}\b',
    'twilio_app_sid': r'\bAP[0-9A-Fa-f]{32}\b',
    'braintree_access_token': r'\baccess_token\$(?:production|sandbox)\$[0-9a-z]{16}\$[0-9A-Fa-f]{32}\b',

    # Auth material
    'jwt_token': r'\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9._\-]{10,}\.[A-Za-z0-9._\-]{10,}\b',
    'basic_auth_header': r'(?i)authorization[\'"`\s:=]{1,10}basic\s+[A-Za-z0-9+/=]{8,}',
    'bearer_token': r'(?i)authorization[\'"`\s:=]{1,10}bearer\s+[A-Za-z0-9._\-+/=]{16,}',

    # Private keys
    'rsa_private_key': r'-----BEGIN RSA PRIVATE KEY-----',
    'dsa_private_key': r'-----BEGIN DSA PRIVATE KEY-----',
    'ec_private_key': r'-----BEGIN EC PRIVATE KEY-----',
    'openssh_private_key': r'-----BEGIN OPENSSH PRIVATE KEY-----',
    'pgp_private_key_block': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'generic_private_key_block': r'-----BEGIN PRIVATE KEY-----',
}
