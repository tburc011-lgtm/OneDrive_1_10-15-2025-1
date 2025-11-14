"""
Enhanced Secure Authentication & Authorization System
Features: Password Hashing, MFA, RBAC, Password Reset, Email Verification, OAuth
"""

import dash
from dash import dcc, html, dash_table, no_update, ctx
from dash.dependencies import Input, Output, State
import dash_bootstrap_components as dbc
import sqlite3
import bcrypt
import secrets
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta
import hashlib
import json
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
from urllib.parse import urlencode

# ============================================================================
# 1. CONFIGURATION
# ============================================================================

class Config:
    """Application configuration - in production, use environment variables"""
    
    # Email Settings (Gmail example - use app-specific password)
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 587
    EMAIL_ADDRESS = "your-email@gmail.com"  # Change this
    EMAIL_PASSWORD = "your-app-password"     # Change this
    EMAIL_FROM_NAME = "Secure Auth System"
    
    # OAuth Settings (GitHub example)
    GITHUB_CLIENT_ID = "your-github-client-id"      # Get from GitHub OAuth Apps
    GITHUB_CLIENT_SECRET = "your-github-secret"      # Get from GitHub OAuth Apps
    GITHUB_REDIRECT_URI = "http://localhost:8050/oauth/github/callback"
    
    # Google OAuth
    GOOGLE_CLIENT_ID = "your-google-client-id"
    GOOGLE_CLIENT_SECRET = "your-google-secret"
    GOOGLE_REDIRECT_URI = "http://localhost:8050/oauth/google/callback"
    
    # Application Settings
    APP_URL = "http://localhost:8050"
    SESSION_TIMEOUT_HOURS = 24
    RESET_TOKEN_EXPIRY_HOURS = 1
    VERIFICATION_TOKEN_EXPIRY_HOURS = 24

# ============================================================================
# 2. DATABASE INITIALIZATION
# ============================================================================

def init_security_db():
    """Initialize database with enhanced schema"""
    with sqlite3.connect('secure_auth.db') as conn:
        cursor = conn.cursor()
        
        # Users table with email verification
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT,
                role TEXT NOT NULL CHECK(role IN ('student', 'faculty', 'admin')),
                mfa_secret TEXT,
                mfa_enabled BOOLEAN DEFAULT 0,
                email_verified BOOLEAN DEFAULT 0,
                account_locked BOOLEAN DEFAULT 0,
                failed_login_attempts INTEGER DEFAULT 0,
                last_failed_login TIMESTAMP,
                password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                oauth_provider TEXT,
                oauth_id TEXT
            )
        """)
        
        # Email verification tokens
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS email_verification_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        
        # Password reset tokens
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        
        # Sessions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                is_active BOOLEAN DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        
        # Audit log
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT,
                event_type TEXT NOT NULL,
                event_description TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        
        # Role permissions
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS role_permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                role TEXT NOT NULL,
                resource TEXT NOT NULL,
                can_read BOOLEAN DEFAULT 0,
                can_write BOOLEAN DEFAULT 0,
                can_delete BOOLEAN DEFAULT 0,
                UNIQUE(role, resource)
            )
        """)
        
        # Initialize default admin
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
        if cursor.fetchone()[0] == 0:
            admin_password = 'SecureAdmin123!'
            password_hash = hash_password(admin_password)
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role, email_verified)
                VALUES (?, ?, ?, ?, ?)
            """, ('admin', 'admin@example.com', password_hash, 'admin', 1))
            log_audit_event(cursor, None, 'admin', 'ACCOUNT_CREATED', 
                          'Default admin account created', '127.0.0.1')
        
        # Initialize permissions
        default_permissions = [
            ('student', 'dashboard', 1, 0, 0),
            ('student', 'profile', 1, 1, 0),
            ('student', 'courses', 1, 0, 0),
            ('faculty', 'dashboard', 1, 0, 0),
            ('faculty', 'profile', 1, 1, 0),
            ('faculty', 'courses', 1, 1, 0),
            ('faculty', 'grades', 1, 1, 0),
            ('faculty', 'students', 1, 0, 0),
            ('admin', 'dashboard', 1, 1, 1),
            ('admin', 'profile', 1, 1, 1),
            ('admin', 'courses', 1, 1, 1),
            ('admin', 'grades', 1, 1, 1),
            ('admin', 'students', 1, 1, 1),
            ('admin', 'faculty', 1, 1, 1),
            ('admin', 'users', 1, 1, 1),
            ('admin', 'security', 1, 1, 1),
        ]
        
        for perm in default_permissions:
            cursor.execute("""
                INSERT OR IGNORE INTO role_permissions 
                (role, resource, can_read, can_write, can_delete)
                VALUES (?, ?, ?, ?, ?)
            """, perm)
        
        conn.commit()

# ============================================================================
# 3. PASSWORD SECURITY
# ============================================================================

def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against hash"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except:
        return False

def validate_password_strength(password: str) -> tuple[bool, str]:
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Must contain uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Must contain lowercase letter"
    if not re.search(r'\d', password):
        return False, "Must contain number"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Must contain special character"
    
    common = ['password', '12345678', 'qwerty', 'admin123']
    if password.lower() in common:
        return False, "Password too common"
    
    return True, ""

# ============================================================================
# 4. EMAIL FUNCTIONS
# ============================================================================

def send_email(to_email: str, subject: str, html_body: str) -> bool:
    """Send email using SMTP"""
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"{Config.EMAIL_FROM_NAME} <{Config.EMAIL_ADDRESS}>"
        msg['To'] = to_email
        
        html_part = MIMEText(html_body, 'html')
        msg.attach(html_part)
        
        with smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT) as server:
            server.starttls()
            server.login(Config.EMAIL_ADDRESS, Config.EMAIL_PASSWORD)
            server.send_message(msg)
        
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

def send_verification_email(user_email: str, username: str, token: str) -> bool:
    """Send email verification link"""
    verify_url = f"{Config.APP_URL}/verify-email?token={token}"
    
    html = f"""
    <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2>Welcome to Secure Auth System!</h2>
            <p>Hi {username},</p>
            <p>Please verify your email address by clicking the link below:</p>
            <p style="margin: 30px 0;">
                <a href="{verify_url}" 
                   style="background: #007bff; color: white; padding: 12px 24px; 
                          text-decoration: none; border-radius: 4px;">
                    Verify Email Address
                </a>
            </p>
            <p>Or copy this link: {verify_url}</p>
            <p>This link expires in 24 hours.</p>
            <hr>
            <small style="color: #666;">
                If you didn't create this account, please ignore this email.
            </small>
        </body>
    </html>
    """
    
    return send_email(user_email, "Verify Your Email", html)

def send_password_reset_email(user_email: str, username: str, token: str) -> bool:
    """Send password reset link"""
    reset_url = f"{Config.APP_URL}/reset-password?token={token}"
    
    html = f"""
    <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2>Password Reset Request</h2>
            <p>Hi {username},</p>
            <p>We received a request to reset your password. Click below to proceed:</p>
            <p style="margin: 30px 0;">
                <a href="{reset_url}" 
                   style="background: #dc3545; color: white; padding: 12px 24px; 
                          text-decoration: none; border-radius: 4px;">
                    Reset Password
                </a>
            </p>
            <p>Or copy this link: {reset_url}</p>
            <p>This link expires in 1 hour.</p>
            <hr>
            <small style="color: #666;">
                If you didn't request this, please ignore and your password will remain unchanged.
            </small>
        </body>
    </html>
    """
    
    return send_email(user_email, "Password Reset Request", html)

# ============================================================================
# 5. EMAIL VERIFICATION
# ============================================================================

def create_verification_token(user_id: int) -> str:
    """Create email verification token"""
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(hours=Config.VERIFICATION_TOKEN_EXPIRY_HOURS)
    
    with sqlite3.connect('secure_auth.db') as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO email_verification_tokens (user_id, token, expires_at)
            VALUES (?, ?, ?)
        """, (user_id, token, expires_at))
        conn.commit()
    
    return token

def verify_email_token(token: str) -> tuple[bool, str]:
    """Verify email token and activate account"""
    with sqlite3.connect('secure_auth.db') as conn:
        cursor = conn.cursor()
        
        result = cursor.execute("""
            SELECT user_id, expires_at, used FROM email_verification_tokens
            WHERE token = ?
        """, (token,)).fetchone()
        
        if not result:
            return False, "Invalid verification link"
        
        user_id, expires_at, used = result
        
        if used:
            return False, "This link has already been used"
        
        if datetime.fromisoformat(expires_at) < datetime.now():
            return False, "Verification link expired"
        
        # Mark email as verified
        cursor.execute("""
            UPDATE users SET email_verified = 1 WHERE id = ?
        """, (user_id,))
        
        cursor.execute("""
            UPDATE email_verification_tokens SET used = 1 WHERE token = ?
        """, (token,))
        
        log_audit_event(cursor, user_id, None, 'EMAIL_VERIFIED',
                       'User verified email address', '127.0.0.1')
        
        conn.commit()
        return True, "Email verified successfully!"

# ============================================================================
# 6. PASSWORD RESET
# ============================================================================

def create_password_reset_token(email: str) -> tuple[bool, str]:
    """Create password reset token"""
    with sqlite3.connect('secure_auth.db') as conn:
        cursor = conn.cursor()
        
        user = cursor.execute("""
            SELECT id, username FROM users WHERE email = ?
        """, (email,)).fetchone()
        
        if not user:
            return False, "No account found with this email"
        
        user_id, username = user
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(hours=Config.RESET_TOKEN_EXPIRY_HOURS)
        
        cursor.execute("""
            INSERT INTO password_reset_tokens (user_id, token, expires_at)
            VALUES (?, ?, ?)
        """, (user_id, token, expires_at))
        
        log_audit_event(cursor, user_id, username, 'PASSWORD_RESET_REQUESTED',
                       'User requested password reset', '127.0.0.1')
        
        conn.commit()
        
        # Send email
        send_password_reset_email(email, username, token)
        return True, "Password reset link sent to your email"

def reset_password_with_token(token: str, new_password: str) -> tuple[bool, str]:
    """Reset password using token"""
    # Validate password
    is_valid, error = validate_password_strength(new_password)
    if not is_valid:
        return False, error
    
    with sqlite3.connect('secure_auth.db') as conn:
        cursor = conn.cursor()
        
        result = cursor.execute("""
            SELECT user_id, expires_at, used FROM password_reset_tokens
            WHERE token = ?
        """, (token,)).fetchone()
        
        if not result:
            return False, "Invalid reset link"
        
        user_id, expires_at, used = result
        
        if used:
            return False, "This link has already been used"
        
        if datetime.fromisoformat(expires_at) < datetime.now():
            return False, "Reset link expired"
        
        # Update password
        password_hash = hash_password(new_password)
        cursor.execute("""
            UPDATE users 
            SET password_hash = ?, 
                password_changed_at = CURRENT_TIMESTAMP,
                failed_login_attempts = 0,
                account_locked = 0
            WHERE id = ?
        """, (password_hash, user_id))
        
        cursor.execute("""
            UPDATE password_reset_tokens SET used = 1 WHERE token = ?
        """, (token,))
        
        log_audit_event(cursor, user_id, None, 'PASSWORD_RESET',
                       'User reset password', '127.0.0.1')
        
        conn.commit()
        return True, "Password reset successfully!"

# ============================================================================
# 7. OAUTH FUNCTIONS
# ============================================================================

def get_github_oauth_url() -> str:
    """Generate GitHub OAuth authorization URL"""
    params = {
        'client_id': Config.GITHUB_CLIENT_ID,
        'redirect_uri': Config.GITHUB_REDIRECT_URI,
        'scope': 'user:email',
        'state': secrets.token_urlsafe(16)
    }
    return f"https://github.com/login/oauth/authorize?{urlencode(params)}"

def exchange_github_code(code: str) -> dict:
    """Exchange GitHub auth code for access token"""
    try:
        # Exchange code for token
        token_response = requests.post(
            'https://github.com/login/oauth/access_token',
            data={
                'client_id': Config.GITHUB_CLIENT_ID,
                'client_secret': Config.GITHUB_CLIENT_SECRET,
                'code': code,
                'redirect_uri': Config.GITHUB_REDIRECT_URI
            },
            headers={'Accept': 'application/json'}
        )
        
        token_data = token_response.json()
        access_token = token_data.get('access_token')
        
        if not access_token:
            return None
        
        # Get user info
        user_response = requests.get(
            'https://api.github.com/user',
            headers={
                'Authorization': f'token {access_token}',
                'Accept': 'application/json'
            }
        )
        
        user_data = user_response.json()
        
        # Get email
        email_response = requests.get(
            'https://api.github.com/user/emails',
            headers={
                'Authorization': f'token {access_token}',
                'Accept': 'application/json'
            }
        )
        
        emails = email_response.json()
        primary_email = next((e['email'] for e in emails if e['primary']), None)
        
        return {
            'oauth_id': str(user_data.get('id')),
            'username': user_data.get('login'),
            'email': primary_email,
            'provider': 'github'
        }
    except Exception as e:
        print(f"GitHub OAuth error: {e}")
        return None

def get_google_oauth_url() -> str:
    """Generate Google OAuth authorization URL"""
    params = {
        'client_id': Config.GOOGLE_CLIENT_ID,
        'redirect_uri': Config.GOOGLE_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'openid email profile',
        'state': secrets.token_urlsafe(16)
    }
    return f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"

def exchange_google_code(code: str) -> dict:
    """Exchange Google auth code for user info"""
    try:
        # Exchange code for token
        token_response = requests.post(
            'https://oauth2.googleapis.com/token',
            data={
                'client_id': Config.GOOGLE_CLIENT_ID,
                'client_secret': Config.GOOGLE_CLIENT_SECRET,
                'code': code,
                'redirect_uri': Config.GOOGLE_REDIRECT_URI,
                'grant_type': 'authorization_code'
            }
        )
        
        token_data = token_response.json()
        access_token = token_data.get('access_token')
        
        if not access_token:
            return None
        
        # Get user info
        user_response = requests.get(
            'https://www.googleapis.com/oauth2/v2/userinfo',
            headers={'Authorization': f'Bearer {access_token}'}
        )
        
        user_data = user_response.json()
        
        return {
            'oauth_id': user_data.get('id'),
            'username': user_data.get('email').split('@')[0],
            'email': user_data.get('email'),
            'provider': 'google'
        }
    except Exception as e:
        print(f"Google OAuth error: {e}")
        return None

def get_or_create_oauth_user(oauth_data: dict) -> dict:
    """Get existing OAuth user or create new one"""
    with sqlite3.connect('secure_auth.db') as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Check if OAuth user exists
        user = cursor.execute("""
            SELECT * FROM users 
            WHERE oauth_provider = ? AND oauth_id = ?
        """, (oauth_data['provider'], oauth_data['oauth_id'])).fetchone()
        
        if user:
            cursor.execute("""
                UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?
            """, (user['id'],))
            log_audit_event(cursor, user['id'], user['username'], 
                          'OAUTH_LOGIN', f"Login via {oauth_data['provider']}", '127.0.0.1')
            conn.commit()
            return dict(user)
        
        # Create new user
        username = oauth_data['username']
        # Ensure unique username
        base_username = username
        counter = 1
        while cursor.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
            username = f"{base_username}{counter}"
            counter += 1
        
        cursor.execute("""
            INSERT INTO users 
            (username, email, role, email_verified, oauth_provider, oauth_id)
            VALUES (?, ?, 'student', 1, ?, ?)
        """, (username, oauth_data['email'], oauth_data['provider'], oauth_data['oauth_id']))
        
        user_id = cursor.lastrowid
        
        log_audit_event(cursor, user_id, username, 'OAUTH_ACCOUNT_CREATED',
                       f"Account created via {oauth_data['provider']}", '127.0.0.1')
        conn.commit()
        
        return dict(cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone())

# ============================================================================
# 8. MFA FUNCTIONS
# ============================================================================

def generate_mfa_secret() -> str:
    """Generate MFA secret"""
    return pyotp.random_base32()

def generate_qr_code(username: str, mfa_secret: str) -> str:
    """Generate QR code for MFA"""
    totp_uri = pyotp.totp.TOTP(mfa_secret).provisioning_uri(
        name=username,
        issuer_name='Secure Auth System'
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    img_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    return f"data:image/png;base64,{img_base64}"

def verify_mfa_token(mfa_secret: str, token: str) -> bool:
    """Verify MFA token"""
    totp = pyotp.TOTP(mfa_secret)
    return totp.verify(token, valid_window=1)

# ============================================================================
# 9. SESSION & AUTH FUNCTIONS
# ============================================================================

def create_session(user_id: int, ip_address: str = None, user_agent: str = None) -> str:
    """Create session"""
    session_token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(hours=Config.SESSION_TIMEOUT_HOURS)
    
    with sqlite3.connect('secure_auth.db') as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO sessions 
            (user_id, session_token, ip_address, user_agent, expires_at)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, session_token, ip_address, user_agent, expires_at))
        conn.commit()
    
    return session_token

def validate_session(session_token: str) -> dict:
    """Validate session"""
    if not session_token:
        return None
    
    with sqlite3.connect('secure_auth.db') as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        result = cursor.execute("""
            SELECT s.*, u.username, u.email, u.role, u.mfa_enabled, u.email_verified
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_token = ? 
            AND s.is_active = 1 
            AND s.expires_at > CURRENT_TIMESTAMP
        """, (session_token,)).fetchone()
        
        return dict(result) if result else None

def invalidate_session(session_token: str):
    """Invalidate session"""
    with sqlite3.connect('secure_auth.db') as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE sessions SET is_active = 0 WHERE session_token = ?
        """, (session_token,))
        conn.commit()

def log_audit_event(cursor, user_id: int, username: str, event_type: str, 
                    description: str, ip_address: str = None):
    """Log audit event"""
    cursor.execute("""
        INSERT INTO audit_log 
        (user_id, username, event_type, event_description, ip_address)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, username, event_type, description, ip_address))

def register_user(username: str, email: str, password: str, role: str) -> tuple[bool, str, int]:
    """Register new user"""
    is_valid, error = validate_password_strength(password)
    if not is_valid:
        return False, error, None
    
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return False, "Invalid email format", None
    
    password_hash = hash_password(password)
    
    try:
        with sqlite3.connect('secure_auth.db') as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role, email_verified)
                VALUES (?, ?, ?, ?, 0)
            """, (username, email, password_hash, role))
            
            user_id = cursor.lastrowid
            
            # Create verification token
            token = create_verification_token(user_id)
            
            # Send verification email
            send_verification_email(email, username, token)
            
            log_audit_event(cursor, user_id, username, 'ACCOUNT_CREATED',
                          f'New {role} account created - verification email sent', '127.0.0.1')
            conn.commit()
            
        return True, "Account created! Check your email to verify.", user_id
    except sqlite3.IntegrityError as e:
        if 'username' in str(e):
            return False, "Username already exists", None
        elif 'email' in str(e):
            return False, "Email already registered", None
        return False, "Registration failed", None

def authenticate_user(username: str, password: str, mfa_token: str = None) -> tuple[bool, str, dict]:
    """Authenticate user"""
    with sqlite3.connect('secure_auth.db') as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        user = cursor.execute("""
            SELECT * FROM users WHERE username = ?
        """, (username,)).fetchone()
        
        if not user:
            log_audit_event(cursor, None, username, 'LOGIN_FAILED',
                          'Username not found', '127.0.0.1')
            return False, "Invalid username or password", None
        
        # Check if OAuth user (no password)
        if user['oauth_provider']:
            return False, f"This account uses {user['oauth_provider']} login", None
        
        if user['account_locked']:
            log_audit_event(cursor, user['id'], username, 'LOGIN_BLOCKED',
                          'Account locked', '127.0.0.1')
            return False, "Account locked. Contact administrator.", None
        
        # Check email verification
        if not user['email_verified']:
            return False, "Please verify your email before logging in", None
        
        if not verify_password(password, user['password_hash']):
            failed_attempts = user['failed_login_attempts'] + 1
            cursor.execute("""
                UPDATE users 
                SET failed_login_attempts = ?,
                    last_failed_login = CURRENT_TIMESTAMP,
                    account_locked = CASE WHEN ? >= 5 THEN 1 ELSE 0 END
                WHERE id = ?
            """, (failed_attempts, failed_attempts, user['id']))
            
            log_audit_event(cursor, user['id'], username, 'LOGIN_FAILED',
                          f'Invalid password (attempt {failed_attempts})', '127.0.0.1')
            conn.commit()
            
            if failed_attempts >= 5:
                return False, "Account locked after 5 failed attempts", None
            return False, "Invalid username or password", None
        
        if user['mfa_enabled']:
            if not mfa_token:
                return False, "MFA_REQUIRED", dict(user)
            
            if not verify_mfa_token(user['mfa_secret'], mfa_token):
                log_audit_event(cursor, user['id'], username, 'MFA_FAILED',
                              'Invalid MFA token', '127.0.0.1')
                return False, "Invalid MFA token", None
        
        cursor.execute("""
            UPDATE users 
            SET failed_login_attempts = 0,
                last_login = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (user['id'],))
        
        log_audit_event(cursor, user['id'], username, 'LOGIN_SUCCESS',
                      'User logged in successfully', '127.0.0.