# =============================================
# SECURE LUNG NODULE CLASSIFIER WITH USER AUTHENTICATION
# ENHANCED VERSION WITH COMPREHENSIVE USER MANAGEMENT
# COMPLETELY FIXED VERSION WITH WORKING ADMIN CONTROLS
# =============================================

import gradio as gr
import numpy as np
import os
import time
import tensorflow as tf
from tensorflow.keras import layers, models
from PIL import Image
import random
from datetime import datetime, timedelta
import cv2
import warnings
import hashlib
import traceback
from scipy import ndimage
import sqlite3
import bcrypt
import secrets
import json
from typing import Optional, Dict, Any, Tuple, List
from pathlib import Path
import socket
import logging
from logging.handlers import RotatingFileHandler
from contextlib import contextmanager
import pandas as pd
import io
import base64
from tensorflow.keras.preprocessing.image import ImageDataGenerator

warnings.filterwarnings('ignore')

print("=" * 80)
print("🔒 SECURE LUNG NODULE CLASSIFIER - ENHANCED WITH USER MANAGEMENT")
print("=" * 80)

# =============================================
# 0. ENHANCED LOGGING SYSTEM
# =============================================

def setup_logging():
    """Setup comprehensive logging system"""
    logger = logging.getLogger('LungNoduleClassifier')
    logger.setLevel(logging.INFO)
    
    Path('logs').mkdir(exist_ok=True)
    
    file_handler = RotatingFileHandler(
        'logs/lung_classifier.log',
        maxBytes=10*1024*1024,
        backupCount=5
    )
    file_handler.setLevel(logging.INFO)
    
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logging()

# =============================================
# 1. ENHANCED DATABASE & USER MANAGEMENT SYSTEM
# =============================================

class EnhancedUserDatabase:
    """Enhanced SQLite database for user management with connection pooling"""
    
    def __init__(self, db_path='enhanced_users.db'):
        self.db_path = db_path
        self.lockout_users = {}
        self.failed_attempts = {}
        self._ensure_database()

    @contextmanager
    def _get_connection(self):
        """Get database connection with context manager"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            yield conn
        except Exception as e:
            logger.error(f"Database connection error: {e}")
            raise
        finally:
            if conn:
                conn.close()

    def _ensure_database(self):
        """Create database tables if they don't exist"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Create users table with enhanced fields
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY,
                        password_hash TEXT NOT NULL,
                        role TEXT DEFAULT 'user',
                        is_approved INTEGER DEFAULT 0,
                        status TEXT DEFAULT 'pending',
                        full_name TEXT,
                        email TEXT,
                        security_question TEXT,
                        security_answer TEXT,
                        last_login TIMESTAMP,
                        login_count INTEGER DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create sessions table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS sessions (
                        session_id TEXT PRIMARY KEY,
                        username TEXT NOT NULL,
                        ip_address TEXT,
                        user_agent TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP NOT NULL,
                        last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
                    )
                ''')
                
                # Create audit log table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS audit_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT,
                        action TEXT NOT NULL,
                        details TEXT,
                        ip_address TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create indexes for performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_log(username)')
                
                # Check if admin exists
                cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
                if cursor.fetchone()[0] == 0:
                    admin_hash = self._hash_password("Admin@Secure123!")
                    cursor.execute('''
                        INSERT INTO users (username, password_hash, role, is_approved, status, full_name, email, security_question, security_answer)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', ('admin', admin_hash, 'admin', 1, 'active', 'System Administrator', 'admin@example.com', 
                          'What is your favorite color?', self._hash_security_answer('blue')))
                    logger.info("Created admin user")
                
                # Check if demo user exists
                cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'demo'")
                if cursor.fetchone()[0] == 0:
                    demo_hash = self._hash_password("Demo@123")
                    cursor.execute('''
                        INSERT INTO users (username, password_hash, role, is_approved, status, full_name, email, security_question, security_answer)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', ('demo', demo_hash, 'user', 1, 'active', 'Demo User', 'demo@example.com', 
                          'What is your pet\'s name?', self._hash_security_answer('max')))
                    logger.info("Created demo user")
                
                conn.commit()
                logger.info("Database initialized successfully")
                
        except Exception as e:
            logger.error(f"Database setup error: {e}")
            raise

    def _hash_password(self, password: str) -> str:
        """Hash password using bcrypt with enhanced security"""
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def _hash_security_answer(self, answer: str) -> str:
        """Hash security answer"""
        return hashlib.sha256(answer.lower().strip().encode()).hexdigest()

    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except Exception as e:
            logger.warning(f"Password verification error: {e}")
            return False

    def _verify_security_answer(self, answer: str, stored_hash: str) -> bool:
        """Verify security answer"""
        return self._hash_security_answer(answer) == stored_hash

    def _is_locked_out(self, username: str) -> bool:
        """Check if user is locked out due to failed attempts"""
        if username in self.lockout_users:
            if datetime.now() < self.lockout_users[username]:
                return True
            else:
                del self.lockout_users[username]
                self.failed_attempts[username] = 0
        return False

    def _record_audit_log(self, username: str, action: str, details: str = "", ip_address: str = None):
        """Record audit log entry"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO audit_log (username, action, details, ip_address)
                    VALUES (?, ?, ?, ?)
                ''', (username, action, details, ip_address))
                conn.commit()
        except Exception as e:
            logger.error(f"Audit log error: {e}")

    # =============== USER MANAGEMENT METHODS ===============

    def create_user(self, username: str, password: str, full_name: str = "", email: str = "", 
                   role: str = "user", security_question: str = "", security_answer: str = "") -> Tuple[bool, str]:
        """Create a new user (admin only)"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Check if user exists
                cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
                if cursor.fetchone()[0] > 0:
                    return False, "Username already exists"
                
                # Validate password strength
                if len(password) < 8:
                    return False, "Password must be at least 8 characters"
                
                # Hash password and security answer
                password_hash = self._hash_password(password)
                security_answer_hash = self._hash_security_answer(security_answer) if security_answer else ""
                
                # Insert new user
                cursor.execute('''
                    INSERT INTO users (username, password_hash, role, is_approved, status, 
                                      full_name, email, security_question, security_answer)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (username, password_hash, role, 0, 'pending', full_name, email, 
                     security_question, security_answer_hash))
                
                conn.commit()
                
                self._record_audit_log(username, "USER_CREATED", f"Created by admin")
                logger.info(f"User {username} created successfully")
                
                return True, "User created successfully. Waiting for admin approval."
                
        except Exception as e:
            logger.error(f"Create user error: {e}")
            return False, f"Error creating user: {str(e)}"

    def update_user(self, username: str, **kwargs) -> Tuple[bool, str]:
        """Update user information (admin only)"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Check if user exists
                cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
                if cursor.fetchone()[0] == 0:
                    return False, "User not found"
                
                # Build update query
                updates = []
                params = []
                
                allowed_fields = ['full_name', 'email', 'role', 'status', 'is_approved']
                for field, value in kwargs.items():
                    if field in allowed_fields:
                        updates.append(f"{field} = ?")
                        params.append(value)
                
                if not updates:
                    return False, "No valid fields to update"
                
                params.append(username)
                query = f"UPDATE users SET {', '.join(updates)}, updated_at = CURRENT_TIMESTAMP WHERE username = ?"
                
                cursor.execute(query, params)
                conn.commit()
                
                self._record_audit_log(username, "USER_UPDATED", f"Updated fields: {', '.join(updates)}")
                logger.info(f"User {username} updated successfully")
                
                return True, "User updated successfully"
                
        except Exception as e:
            logger.error(f"Update user error: {e}")
            return False, f"Error updating user: {str(e)}"

    def reset_password(self, username: str, new_password: str, admin_username: str = None) -> Tuple[bool, str]:
        """Reset user password (admin or self with security question)"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Check if user exists
                cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
                if cursor.fetchone()[0] == 0:
                    return False, "User not found"
                
                # Hash new password
                password_hash = self._hash_password(new_password)
                
                # Update password
                cursor.execute("UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?", 
                             (password_hash, username))
                conn.commit()
                
                if admin_username:
                    self._record_audit_log(admin_username, "PASSWORD_RESET", f"Reset password for user: {username}")
                else:
                    self._record_audit_log(username, "PASSWORD_RESET_SELF", "Password reset via security question")
                
                logger.info(f"Password reset for user {username}")
                
                return True, "Password reset successfully"
                
        except Exception as e:
            logger.error(f"Reset password error: {e}")
            return False, f"Error resetting password: {str(e)}"

    def verify_security_answer(self, username: str, answer: str) -> Tuple[bool, str]:
        """Verify security answer for password recovery"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("SELECT security_answer FROM users WHERE username = ?", (username,))
                result = cursor.fetchone()
                
                if not result:
                    return False, "User not found"
                
                stored_hash = result['security_answer']
                if not stored_hash:
                    return False, "No security question set"
                
                if self._verify_security_answer(answer, stored_hash):
                    return True, "Security answer verified"
                else:
                    return False, "Incorrect security answer"
                
        except Exception as e:
            logger.error(f"Security answer verification error: {e}")
            return False, f"Error verifying security answer: {str(e)}"

    def get_security_question(self, username: str) -> Tuple[bool, str]:
        """Get user's security question"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("SELECT security_question FROM users WHERE username = ?", (username,))
                result = cursor.fetchone()
                
                if not result:
                    return False, "User not found"
                
                question = result['security_question']
                if not question:
                    return False, "No security question set"
                
                return True, question
                
        except Exception as e:
            logger.error(f"Get security question error: {e}")
            return False, f"Error getting security question: {str(e)}"

    def get_all_users(self) -> List[Dict]:
        """Get all users (admin only)"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT username, role, is_approved, status, full_name, email, 
                           last_login, login_count, created_at
                    FROM users 
                    ORDER BY created_at DESC
                """)
                
                users = []
                for row in cursor.fetchall():
                    users.append({
                        'username': row['username'],
                        'role': row['role'],
                        'is_approved': bool(row['is_approved']),
                        'status': row['status'],
                        'full_name': row['full_name'],
                        'email': row['email'],
                        'last_login': row['last_login'],
                        'login_count': row['login_count'],
                        'created_at': row['created_at']
                    })
                
                return users
                
        except Exception as e:
            logger.error(f"Get all users error: {e}")
            return []

    def get_pending_users(self) -> List[Dict]:
        """Get users pending approval"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT username, full_name, email, created_at
                    FROM users 
                    WHERE status = 'pending' AND is_approved = 0
                    ORDER BY created_at DESC
                """)
                
                users = []
                for row in cursor.fetchall():
                    users.append({
                        'username': row['username'],
                        'full_name': row['full_name'],
                        'email': row['email'],
                        'created_at': row['created_at']
                    })
                
                return users
                
        except Exception as e:
            logger.error(f"Get pending users error: {e}")
            return []

    def approve_user(self, username: str, admin_username: str) -> Tuple[bool, str]:
        """Approve a pending user"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("UPDATE users SET is_approved = 1, status = 'active', updated_at = CURRENT_TIMESTAMP WHERE username = ?", 
                             (username,))
                
                if cursor.rowcount == 0:
                    return False, "User not found or already approved"
                
                conn.commit()
                
                self._record_audit_log(admin_username, "USER_APPROVED", f"Approved user: {username}")
                logger.info(f"User {username} approved by {admin_username}")
                
                return True, f"User {username} approved successfully"
                
        except Exception as e:
            logger.error(f"Approve user error: {e}")
            return False, f"Error approving user: {str(e)}"

    def disable_user(self, username: str, admin_username: str) -> Tuple[bool, str]:
        """Disable a user account"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Don't allow disabling admin account
                if username == 'admin':
                    return False, "Cannot disable admin account"
                
                cursor.execute("UPDATE users SET status = 'disabled', updated_at = CURRENT_TIMESTAMP WHERE username = ?", 
                             (username,))
                
                if cursor.rowcount == 0:
                    return False, "User not found"
                
                conn.commit()
                
                self._record_audit_log(admin_username, "USER_DISABLED", f"Disabled user: {username}")
                logger.info(f"User {username} disabled by {admin_username}")
                
                return True, f"User {username} disabled successfully"
                
        except Exception as e:
            logger.error(f"Disable user error: {e}")
            return False, f"Error disabling user: {str(e)}"

    def activate_user(self, username: str, admin_username: str) -> Tuple[bool, str]:
        """Activate a disabled user account"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("UPDATE users SET status = 'active', updated_at = CURRENT_TIMESTAMP WHERE username = ?", 
                             (username,))
                
                if cursor.rowcount == 0:
                    return False, "User not found"
                
                conn.commit()
                
                self._record_audit_log(admin_username, "USER_ACTIVATED", f"Activated user: {username}")
                logger.info(f"User {username} activated by {admin_username}")
                
                return True, f"User {username} activated successfully"
                
        except Exception as e:
            logger.error(f"Activate user error: {e}")
            return False, f"Error activating user: {str(e)}"

    def delete_user(self, username: str, admin_username: str) -> Tuple[bool, str]:
        """Delete a user account"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Don't allow deleting admin account
                if username == 'admin':
                    return False, "Cannot delete admin account"
                
                cursor.execute("DELETE FROM users WHERE username = ?", (username,))
                
                if cursor.rowcount == 0:
                    return False, "User not found"
                
                conn.commit()
                
                self._record_audit_log(admin_username, "USER_DELETED", f"Deleted user: {username}")
                logger.info(f"User {username} deleted by {admin_username}")
                
                return True, f"User {username} deleted successfully"
                
        except Exception as e:
            logger.error(f"Delete user error: {e}")
            return False, f"Error deleting user: {str(e)}"

    def authenticate_user(self, username: str, password: str, ip_address: str = None) -> Tuple[bool, str, Optional[Dict]]:
        """Authenticate user with enhanced security"""
        try:
            if self._is_locked_out(username):
                self._record_audit_log(username, "LOCKOUT_CHECK", "Account is locked", ip_address)
                return False, "Account is temporarily locked. Please try again later.", None
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT username, password_hash, role, is_approved, status, full_name, email
                    FROM users WHERE username = ?
                """, (username,))
                
                result = cursor.fetchone()
                if not result:
                    time.sleep(random.uniform(0.5, 1.5))
                    return False, "Invalid credentials", None
                
                if result['status'] != 'active':
                    self._record_audit_log(username, "LOGIN_FAILED", f"Account status: {result['status']}", ip_address)
                    return False, f"Account is {result['status']}", None
                
                if not result['is_approved']:
                    self._record_audit_log(username, "LOGIN_FAILED", "Account pending approval", ip_address)
                    return False, "Account pending admin approval", None
                
                if not self._verify_password(password, result['password_hash']):
                    self.failed_attempts[username] = self.failed_attempts.get(username, 0) + 1
                    
                    if self.failed_attempts[username] >= 5:
                        lockout_time = datetime.now() + timedelta(minutes=15)
                        self.lockout_users[username] = lockout_time
                        self._record_audit_log(username, "ACCOUNT_LOCKED", 
                                              f"5 failed attempts. Locked until {lockout_time}", ip_address)
                        return False, "Too many failed attempts. Account locked for 15 minutes.", None
                    
                    self._record_audit_log(username, "LOGIN_FAILED", "Invalid password", ip_address)
                    time.sleep(random.uniform(0.5, 1.5))
                    return False, "Invalid credentials", None
                
                self.failed_attempts[username] = 0
                if username in self.lockout_users:
                    del self.lockout_users[username]
                
                cursor.execute("""
                    UPDATE users 
                    SET last_login = CURRENT_TIMESTAMP, 
                        login_count = login_count + 1,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE username = ?
                """, (username,))
                
                session_id = secrets.token_urlsafe(48)
                expires_at = (datetime.now() + timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
                
                cursor.execute("""
                    INSERT INTO sessions (session_id, username, ip_address, expires_at)
                    VALUES (?, ?, ?, ?)
                """, (session_id, username, ip_address, expires_at))
                
                conn.commit()
                
                user_info = {
                    'username': result['username'],
                    'role': result['role'],
                    'is_approved': bool(result['is_approved']),
                    'status': result['status'],
                    'full_name': result['full_name'],
                    'email': result['email']
                }
                
                self._record_audit_log(username, "LOGIN_SUCCESS", f"Session: {session_id[:10]}...", ip_address)
                
                return True, "Login successful", {
                    'session_id': session_id, 
                    'user': user_info,
                    'expires_at': expires_at
                }
                
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False, f"Authentication error: {str(e)}", None

    def validate_session(self, session_id: str) -> Optional[Dict]:
        """Validate session with activity tracking"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP")
                
                cursor.execute("""
                    SELECT s.username, u.role, u.is_approved, u.status, u.full_name, u.email
                    FROM sessions s
                    JOIN users u ON s.username = u.username
                    WHERE s.session_id = ? AND u.status = 'active'
                """, (session_id,))
                
                result = cursor.fetchone()
                if result:
                    cursor.execute("""
                        UPDATE sessions 
                        SET last_activity = CURRENT_TIMESTAMP
                        WHERE session_id = ?
                    """, (session_id,))
                    conn.commit()
                    
                    return {
                        'username': result['username'],
                        'role': result['role'],
                        'is_approved': bool(result['is_approved']),
                        'status': result['status'],
                        'full_name': result['full_name'],
                        'email': result['email']
                    }
                return None
                
        except Exception as e:
            logger.error(f"Session validation error: {e}")
            return None

    def logout(self, session_id: str) -> bool:
        """Logout user with audit logging"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("SELECT username FROM sessions WHERE session_id = ?", (session_id,))
                result = cursor.fetchone()
                
                if result:
                    username = result['username']
                    cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
                    conn.commit()
                    self._record_audit_log(username, "LOGOUT", f"Session: {session_id[:10]}...")
                    return True
                return False
                
        except Exception as e:
            logger.error(f"Logout error: {e}")
            return False

    def get_user_stats(self):
        """Get user statistics"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) as total FROM users")
                total = cursor.fetchone()['total']
                
                cursor.execute("SELECT COUNT(*) as active FROM users WHERE status = 'active'")
                active = cursor.fetchone()['active']
                
                cursor.execute("SELECT COUNT(*) as pending FROM users WHERE status = 'pending'")
                pending = cursor.fetchone()['pending']
                
                cursor.execute("SELECT COUNT(*) as disabled FROM users WHERE status = 'disabled'")
                disabled = cursor.fetchone()['disabled']
                
                cursor.execute("SELECT COUNT(*) as online FROM sessions WHERE expires_at > CURRENT_TIMESTAMP")
                online = cursor.fetchone()['online']
                
                return {
                    'total_users': total,
                    'active_users': active,
                    'pending_users': pending,
                    'disabled_users': disabled,
                    'online_users': online
                }
        except Exception as e:
            logger.error(f"Get user stats error: {e}")
            return {}

# Initialize enhanced database
print("\n🔧 Initializing enhanced database...")
try:
    user_db = EnhancedUserDatabase()
    print("   ✓ Enhanced database ready")
    logger.info("Enhanced database initialized")
except Exception as e:
    print(f"   ❌ Database initialization failed: {e}")
    raise

# =============================================
# 2. ENHANCED SESSION MANAGEMENT
# =============================================

class EnhancedSessionManager:
    """Enhanced session management with security features"""
    
    def __init__(self):
        self.current_session = None
        self.current_user = None
        self.session_expiry = None
        self.last_activity = datetime.now()
    
    def login(self, username: str, password: str, ip_address: str = None) -> Tuple[bool, str]:
        """Login user with enhanced security"""
        if not username or not password:
            return False, "Username and password are required"
        
        if len(username) < 3 or len(username) > 50:
            return False, "Username must be between 3 and 50 characters"
        
        if len(password) < 6:
            return False, "Password must be at least 6 characters"
        
        success, message, session_data = user_db.authenticate_user(username, password, ip_address)
        
        if success and session_data:
            self.current_session = session_data['session_id']
            self.current_user = session_data['user']
            self.session_expiry = datetime.strptime(session_data['expires_at'], '%Y-%m-%d %H:%M:%S')
            self.last_activity = datetime.now()
            
            logger.info(f"User {username} logged in successfully")
            return True, message
        
        logger.warning(f"Failed login attempt for user {username}")
        return False, message
    
    def logout(self):
        """Logout user with cleanup"""
        if self.current_session:
            user_db.logout(self.current_session)
            logger.info(f"User {self.current_user.get('username')} logged out")
        
        self.current_session = None
        self.current_user = None
        self.session_expiry = None
        self.last_activity = None
    
    def is_authenticated(self) -> bool:
        """Check if user is authenticated with session validation"""
        if not self.current_session or not self.session_expiry:
            return False
        
        if datetime.now() > self.session_expiry:
            self.logout()
            return False
        
        user = user_db.validate_session(self.current_session)
        if user:
            self.current_user = user
            self.last_activity = datetime.now()
            return True
        
        self.logout()
        return False
    
    def is_admin(self) -> bool:
        """Check if user is admin"""
        return self.is_authenticated() and self.current_user.get('role') == 'admin'
    
    def is_approved(self) -> bool:
        """Check if user is approved"""
        return self.is_authenticated() and self.current_user.get('is_approved')
    
    def get_user_info(self) -> Dict:
        """Get user info"""
        return self.current_user or {}
    
    def get_session_remaining_time(self) -> int:
        """Get remaining session time in minutes"""
        if not self.session_expiry:
            return 0
        remaining = self.session_expiry - datetime.now()
        return max(0, int(remaining.total_seconds() / 60))
    
    def refresh_session(self) -> bool:
        """Refresh session if nearing expiry"""
        if not self.is_authenticated():
            return False
        
        remaining = self.get_session_remaining_time()
        if remaining < 60:
            self.session_expiry = datetime.now() + timedelta(hours=24)
            logger.info(f"Session refreshed for user {self.current_user.get('username')}")
            return True
        return False

# Initialize enhanced session manager
session_manager = EnhancedSessionManager()

# =============================================
# 3. AUTHENTICATION DECORATORS
# =============================================

def login_required(func):
    """Decorator to require login with session refresh"""
    def wrapper(*args, **kwargs):
        if not session_manager.is_authenticated():
            return "⛔ ACCESS DENIED\n\nPlease login to access this feature."
        
        if not session_manager.is_approved():
            return "⏳ ACCOUNT PENDING\n\nYour account is pending admin approval."
        
        session_manager.refresh_session()
        
        return func(*args, **kwargs)
    return wrapper

def admin_required(func):
    """Decorator to require admin privileges"""
    def wrapper(*args, **kwargs):
        if not session_manager.is_authenticated():
            return "⛔ ACCESS DENIED\n\nPlease login to access this feature."
        
        if not session_manager.is_admin():
            return "⛔ ADMIN PRIVILEGES REQUIRED\n\nThis feature is only available to administrators."
        
        session_manager.refresh_session()
        
        return func(*args, **kwargs)
    return wrapper

# =============================================
# 4. ENHANCED DATA GENERATION WITH AUGMENTATION
# =============================================

def create_augmented_dataset(X, y, augmentation_factor=2):
    """Create augmented dataset for better generalization"""
    print(f"\n🔄 Creating augmented dataset (factor: {augmentation_factor})...")
    
    datagen = ImageDataGenerator(
        rotation_range=15,
        width_shift_range=0.1,
        height_shift_range=0.1,
        zoom_range=0.1,
        horizontal_flip=True,
        brightness_range=[0.9, 1.1],
        fill_mode='nearest'
    )
    
    augmented_images = []
    augmented_labels = []
    
    for i in range(len(X)):
        img = X[i]
        label = y[i]
        
        img_reshaped = img.reshape((1,) + img.shape)
        
        aug_iter = datagen.flow(img_reshaped, batch_size=1)
        
        for _ in range(augmentation_factor):
            augmented_img = next(aug_iter)[0]
            augmented_images.append(augmented_img)
            augmented_labels.append(label)
    
    augmented_images_array = np.array(augmented_images)
    augmented_labels_array = np.array(augmented_labels)
    
    X_augmented = np.concatenate([X, augmented_images_array], axis=0)
    y_augmented = np.concatenate([y, augmented_labels_array], axis=0)
    
    indices = np.random.permutation(len(X_augmented))
    X_augmented = X_augmented[indices]
    y_augmented = y_augmented[indices]
    
    print(f"   ✓ Original: {len(X)} images")
    print(f"   ✓ Augmented: {len(X_augmented)} images")
    print(f"   ✓ Total increase: {len(X_augmented)/len(X):.1f}x")
    
    return X_augmented, y_augmented

def create_enhanced_data(num_images: int = 300) -> Tuple[np.ndarray, np.ndarray]:
    """Create enhanced synthetic data with realistic patterns"""
    print(f"\n📊 Creating enhanced dataset ({num_images} images)...")

    data_dir = Path('lung_data')
    data_dir.mkdir(exist_ok=True)

    X_list = []
    y_list = []

    for i in range(num_images):
        label = 1 if i < num_images * 0.5 else 0

        img = np.ones((128, 128, 3), dtype=np.float32) * 0.5

        if label == 1:
            center_x = random.randint(30, 98)
            center_y = random.randint(30, 98)
            
            if random.choice([True, False]):
                size_x = random.randint(15, 35)
                size_y = random.randint(10, 30)
                
                for x in range(center_x - size_x, center_x + size_x):
                    for y in range(center_y - size_y, center_y + size_y):
                        if 0 <= x < 128 and 0 <= y < 128:
                            distance = ((x - center_x) / size_x) ** 2 + ((y - center_y) / size_y) ** 2
                            if distance < random.uniform(0.7, 1.3):
                                intensity = 0.6 + random.random() * 0.3
                                img[y, x, :] = intensity
            else:
                size = random.randint(15, 25)
                cv2.circle(img, (center_x, center_y), size, (0.7, 0.7, 0.7), -1)
                
                for _ in range(random.randint(4, 8)):
                    angle = random.random() * 2 * np.pi
                    length = random.randint(10, 20)
                    for l in range(length):
                        x = int(center_x + l * np.cos(angle))
                        y = int(center_y + l * np.sin(angle))
                        if 0 <= x < 128 and 0 <= y < 128:
                            img[y, x, :] = 0.8

        else:
            center_x = random.randint(40, 88)
            center_y = random.randint(40, 88)
            size = random.randint(8, 22)
            
            cv2.circle(img, (center_x, center_y), size, (0.6, 0.6, 0.6), -1)
            kernel_size = random.choice([9, 11])
            img = cv2.GaussianBlur(img, (kernel_size, kernel_size), random.uniform(3.0, 4.0))

        noise_level = random.uniform(0.03, 0.07)
        noise = np.random.normal(0, noise_level, (128, 128, 3))
        img = np.clip(img + noise, 0, 1)

        X_list.append(img)
        y_list.append(label)

    X_array = np.array(X_list, dtype=np.float32)
    y_array = np.array(y_list, dtype=np.float32)

    X_array, y_array = create_augmented_dataset(X_array, y_array, augmentation_factor=2)

    np.save(data_dir / 'X.npy', X_array)
    np.save(data_dir / 'y.npy', y_array)

    print(f"   ✓ Created: {len(X_array)} images (with augmentation)")
    return X_array, y_array

# =============================================
# 5. IMAGE VALIDATION FUNCTION
# =============================================

def validate_ct_image(image_array, min_size=(256, 256), max_size=(2048, 2048)):
    """Validate CT image quality and characteristics"""
    issues = []
    recommendations = []
    
    if not isinstance(image_array, np.ndarray):
        return False, ["Invalid image format. Please upload a valid image file."]
    
    if len(image_array.shape) < 2:
        issues.append("Image must have at least 2 dimensions")
    
    if len(image_array.shape) == 2:
        height, width = image_array.shape
    else:
        height, width = image_array.shape[:2]
    
    if width < min_size[0] or height < min_size[1]:
        issues.append(f"Image too small. Minimum recommended: {min_size[0]}x{min_size[1]} pixels")
        recommendations.append("Use a higher resolution CT scan")
    
    if width > max_size[0] or height > max_size[1]:
        issues.append(f"Image too large. Maximum: {max_size[0]}x{max_size[1]} pixels")
        recommendations.append("Resize the image before uploading")
    
    if len(image_array.shape) == 2:
        contrast = np.std(image_array)
    else:
        contrast = np.std(image_array.mean(axis=2))
    
    if contrast < 0.1:
        issues.append("Low contrast detected")
        recommendations.append("Adjust window/level settings to lung window")
    
    if len(image_array.shape) == 2:
        mean_brightness = np.mean(image_array)
    else:
        mean_brightness = np.mean(image_array.mean(axis=2))
    
    if mean_brightness > 0.95:
        issues.append("Image is too bright (overexposed)")
        recommendations.append("Adjust brightness/contrast settings")
    elif mean_brightness < 0.05:
        issues.append("Image is too dark (underexposed)")
        recommendations.append("Adjust brightness/contrast settings")
    
    aspect_ratio = width / height
    if aspect_ratio < 0.8 or aspect_ratio > 1.2:
        issues.append(f"Unusual aspect ratio: {aspect_ratio:.2f}")
        recommendations.append("Use standard CT scan format (square or near-square)")
    
    return len(issues) == 0, issues + recommendations

# =============================================
# 6. ENHANCED MODEL ARCHITECTURE
# =============================================

model_metadata = {
    'name': 'Advanced Lung Nodule Analyzer',
    'version': '4.1-Pro',
    'parameters': '~250K',
    'status': '🟢 Active',
    'accuracy': 'Dynamic Pattern Recognition',
    'created_date': datetime.now().strftime('%Y-%m-%d'),
    'last_trained': None
}

def create_advanced_model() -> tf.keras.Model:
    """Create advanced model with comprehensive architecture"""
    print("\n🤖 Creating advanced model architecture...")

    model = models.Sequential([
        layers.Conv2D(32, (3, 3), activation='relu', padding='same', 
                      input_shape=(128, 128, 3)),
        layers.BatchNormalization(),
        layers.Conv2D(32, (3, 3), activation='relu', padding='same'),
        layers.MaxPooling2D((2, 2)),
        layers.Dropout(0.25),

        layers.Conv2D(64, (3, 3), activation='relu', padding='same'),
        layers.BatchNormalization(),
        layers.Conv2D(64, (3, 3), activation='relu', padding='same'),
        layers.MaxPooling2D((2, 2)),
        layers.Dropout(0.3),

        layers.Conv2D(128, (3, 3), activation='relu', padding='same'),
        layers.BatchNormalization(),
        layers.Conv2D(128, (3, 3), activation='relu', padding='same'),
        layers.GlobalAveragePooling2D(),
        layers.Dropout(0.4),

        layers.Dense(256, activation='relu'),
        layers.BatchNormalization(),
        layers.Dropout(0.5),
        layers.Dense(128, activation='relu'),
        layers.Dense(1, activation='sigmoid')
    ])

    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=0.0001),
        loss='binary_crossentropy',
        metrics=['accuracy']
    )

    param_count = model.count_params()
    model_metadata.update({
        'parameters': f"{param_count:,}",
        'name': 'Advanced Pattern Recognition CNN'
    })

    print(f"   ✓ Model created: {param_count:,} parameters")
    logger.info(f"Model created with {param_count:,} parameters")
    return model

# =============================================
# 7. COMPREHENSIVE MODEL METRICS
# =============================================

def calculate_comprehensive_metrics(model, X_test, y_test):
    """Calculate detailed performance metrics"""
    print("\n📈 Calculating comprehensive model metrics...")
    
    y_pred_proba = model.predict(X_test, verbose=0)
    y_pred = (y_pred_proba > 0.5).astype(int).flatten()
    
    try:
        basic_metrics = model.evaluate(X_test, y_test, verbose=0)
        if isinstance(basic_metrics, list):
            loss = float(basic_metrics[0]) if len(basic_metrics) > 0 else 0.0
            accuracy = float(basic_metrics[1]) if len(basic_metrics) > 1 else 0.0
        else:
            loss = float(basic_metrics)
            accuracy = 0.0
    except Exception as e:
        print(f"   ⚠️ Error in model evaluation: {e}")
        loss = 0.0
        accuracy = 0.0
    
    try:
        y_pred_binary = (y_pred_proba > 0.5).astype(int).flatten()
        
        tp = np.sum((y_test == 1) & (y_pred_binary == 1))
        tn = np.sum((y_test == 0) & (y_pred_binary == 0))
        fp = np.sum((y_test == 0) & (y_pred_binary == 1))
        fn = np.sum((y_test == 1) & (y_pred_binary == 0))
        
        sensitivity = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        f1_score = 2 * (precision * sensitivity) / (precision + sensitivity) if (precision + sensitivity) > 0 else 0.0
        
        from sklearn.metrics import roc_auc_score
        try:
            auc_score = roc_auc_score(y_test, y_pred_proba)
        except:
            auc_score = 0.5
        
    except Exception as e:
        print(f"   ⚠️ Error in metric calculation: {e}")
        tp = tn = fp = fn = 0
        sensitivity = specificity = precision = f1_score = 0.0
        auc_score = 0.5
    
    metrics = {
        'loss': loss,
        'accuracy': accuracy,
        'precision': precision,
        'recall': sensitivity,
        'sensitivity': sensitivity,
        'specificity': specificity,
        'f1_score': f1_score,
        'auc_score': auc_score,
        'confusion_matrix': {
            'true_positive': int(tp),
            'true_negative': int(tn),
            'false_positive': int(fp),
            'false_negative': int(fn)
        },
        'support': len(y_test)
    }
    
    logger.info(f"Model metrics - Accuracy: {metrics['accuracy']:.3f}, AUC: {metrics['auc_score']:.3f}")
    
    print(f"   ✓ Accuracy: {metrics['accuracy']:.1%}")
    print(f"   ✓ Precision: {metrics['precision']:.1%}")
    print(f"   ✓ Recall/Sensitivity: {metrics['sensitivity']:.1%}")
    print(f"   ✓ Specificity: {metrics['specificity']:.1%}")
    print(f"   ✓ F1-Score: {metrics['f1_score']:.1%}")
    print(f"   ✓ AUC Score: {metrics['auc_score']:.3f}")
    
    return metrics

# =============================================
# 8. ENHANCED TRAINING FUNCTION
# =============================================

def train_model(model: tf.keras.Model, X: np.ndarray, y: np.ndarray) -> Tuple[tf.keras.Model, Dict]:
    """Train the model with enhanced validation and metrics"""
    print(f"\n🏋️ Training model (15 epochs with enhanced validation)...")

    indices = np.random.permutation(len(X))
    split_idx = int(len(X) * 0.7)
    
    X_train_full = X[indices[:split_idx]]
    y_train_full = y[indices[:split_idx]]
    
    val_split_idx = int(len(X_train_full) * 0.2)
    X_train = X_train_full[val_split_idx:]
    y_train = y_train_full[val_split_idx:]
    X_val = X_train_full[:val_split_idx]
    y_val = y_train_full[:val_split_idx]
    
    X_test = X[indices[split_idx:]]
    y_test = y[indices[split_idx:]]

    print(f"   Training set: {len(X_train)} images")
    print(f"   Validation set: {len(X_val)} images")
    print(f"   Test set: {len(X_test)} images")
    
    print("   Starting training...")
    
    history = model.fit(
        X_train, y_train,
        validation_data=(X_val, y_val),
        epochs=15,
        batch_size=32,
        verbose=1
    )

    metrics = calculate_comprehensive_metrics(model, X_test, y_test)
    
    model.save('lung_model.h5')
    model_metadata['last_trained'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    with open('model_metrics.json', 'w') as f:
        json.dump(metrics, f, indent=2)
    
    print("   ✓ Training complete!")
    print("   ✓ Model saved: lung_model.h5")
    print("   ✓ Metrics saved: model_metrics.json")
    
    logger.info("Model training completed successfully")
    
    return model, metrics

# =============================================
# 9. ADVANCED PREDICTION ENGINE
# =============================================

class AdvancedPredictionEngine:
    """Advanced engine with medical pattern analysis"""

    def __init__(self):
        self.pattern_descriptions = {
            'calcification': 'Bright, dense, well-defined - typically benign',
            'irregular': 'Poorly defined margins, irregular shape - suspicious',
            'spiculated': 'Spiculated margins radiating outward - highly suspicious',
            'smooth': 'Smooth, round margins - typically benign',
            'homogeneous': 'Uniform density throughout - indeterminate',
            'textured': 'Mixed density patterns - requires follow-up',
            'artifact': 'Imaging artifact - requires re-scan',
            'lobulated': 'Lobulated margins - moderate suspicion'
        }

    def analyze_image_characteristics(self, image_array: np.ndarray) -> Dict[str, Any]:
        """Comprehensive image analysis"""
        if len(image_array.shape) == 3:
            img_gray = np.mean(image_array, axis=2)
        else:
            img_gray = image_array

        brightness = np.mean(img_gray)
        contrast = np.std(img_gray)
        dynamic_range = np.max(img_gray) - np.min(img_gray)

        try:
            sobel_x = ndimage.sobel(img_gray, axis=0)
            sobel_y = ndimage.sobel(img_gray, axis=1)
            edge_strength = np.mean(np.sqrt(sobel_x**2 + sobel_y**2))
        except Exception:
            edge_strength = 0.05

        histogram = np.histogram(img_gray, bins=256, range=(0, 1))[0]
        histogram = histogram / (histogram.sum() + 1e-10)
        entropy = -np.sum(histogram * np.log2(histogram + 1e-10))

        if brightness > 0.8:
            pattern = 'calcification'
            adjustment = -0.25
        elif edge_strength > 0.15:
            pattern = 'spiculated'
            adjustment = 0.3
        elif edge_strength > 0.1:
            pattern = 'irregular'
            adjustment = 0.2
        elif brightness < 0.3:
            pattern = 'artifact'
            adjustment = -0.3
        elif contrast < 0.15:
            pattern = 'homogeneous'
            adjustment = -0.1
        elif 0.4 <= brightness <= 0.6 and 0.2 <= contrast <= 0.3:
            pattern = 'lobulated'
            adjustment = 0.15
        else:
            pattern = 'textured'
            adjustment = 0.1

        brightness_score = 1 - abs(brightness - 0.5)
        contrast_score = min(contrast * 3, 1)
        edge_score = min(edge_strength * 10, 1)
        entropy_score = min(entropy / 8, 1)
        
        quality_score = (
            0.3 * brightness_score + 
            0.3 * contrast_score + 
            0.2 * edge_score + 
            0.2 * entropy_score
        )

        if quality_score > 0.8:
            quality = "🟢 Excellent"
            quality_color = "#27ae60"
        elif quality_score > 0.65:
            quality = "🟡 Good"
            quality_color = "#f1c40f"
        elif quality_score > 0.5:
            quality = "🟠 Fair"
            quality_color = "#e67e22"
        else:
            quality = "🔴 Poor"
            quality_color = "#e74c3c"

        return {
            'brightness': float(brightness),
            'contrast': float(contrast),
            'dynamic_range': float(dynamic_range),
            'edge_strength': float(edge_strength),
            'entropy': float(entropy),
            'pattern': pattern,
            'pattern_desc': self.pattern_descriptions.get(pattern, 'Unknown pattern'),
            'adjustment': adjustment,
            'quality': quality,
            'quality_color': quality_color,
            'quality_score': float(quality_score),
            'brightness_score': float(brightness_score),
            'contrast_score': float(contrast_score),
            'edge_score': float(edge_score),
            'entropy_score': float(entropy_score)
        }

    def generate_enhanced_prediction(self, model_pred: float, features: Dict[str, Any]) -> Dict[str, Any]:
        """Generate enhanced prediction with pattern analysis"""
        base_pred = float(model_pred)
        adjustment = features.get('adjustment', 0)
        brightness = features.get('brightness', 0.5)
        contrast = features.get('contrast', 0.1)
        quality_score = features.get('quality_score', 0.5)

        adjusted = base_pred + adjustment
        variation = (brightness - 0.5) * 0.1 + contrast * 0.05
        
        quality_factor = 1.0 + (quality_score - 0.5) * 0.5
        final_pred = adjusted * quality_factor + variation

        final_pred = np.clip(final_pred, 0.05, 0.95)

        if 0.4 < final_pred < 0.6:
            edge_strength = features.get('edge_strength', 0.05)
            quality_factor = features.get('quality_score', 0.5)
            
            if edge_strength > 0.08:
                final_pred = 0.65 + (quality_factor - 0.5) * 0.1
            else:
                final_pred = 0.35 - (quality_factor - 0.5) * 0.1

        confidence = final_pred if final_pred > 0.5 else 1 - final_pred
        confidence = confidence * (0.7 + 0.3 * quality_score)

        return {
            'final_prediction': float(final_pred),
            'base_prediction': float(base_pred),
            'adjusted_prediction': float(adjusted),
            'confidence': float(confidence),
            'quality_factor': float(quality_factor)
        }

prediction_engine = AdvancedPredictionEngine()

# =============================================
# 10. ENHANCED IMAGE PREPROCESSING
# =============================================

def preprocess_image(image) -> Tuple[np.ndarray, Tuple[int, int], List[str]]:
    """Preprocess uploaded image with validation"""
    try:
        validation_issues = []
        
        if isinstance(image, np.ndarray):
            if image.max() <= 1.0:
                img_pil = Image.fromarray((image * 255).astype('uint8'))
            else:
                img_pil = Image.fromarray(image.astype('uint8'))
        else:
            img_pil = image

        original_size = img_pil.size
        
        img_array_for_validation = np.array(img_pil, dtype=np.float32) / 255.0
        is_valid, issues = validate_ct_image(img_array_for_validation)
        
        if not is_valid:
            validation_issues.extend(issues)
        
        if img_pil.mode != 'RGB':
            img_pil = img_pil.convert('RGB')
            validation_issues.append(f"Converted from {img_pil.mode} to RGB")

        img_resized = img_pil.resize((128, 128))
        img_array = np.array(img_resized, dtype=np.float32) / 255.0

        return img_array, original_size, validation_issues

    except Exception as e:
        logger.error(f"Image processing error: {str(e)}")
        raise ValueError(f"Image processing error: {str(e)}")

# =============================================
# 11. BATCH PROCESSING FUNCTION
# =============================================

@login_required
def batch_analyze_images(image_list):
    """Process multiple images at once"""
    results = []
    summary_stats = {
        'total': len(image_list),
        'success': 0,
        'failed': 0,
        'high_risk': 0,
        'moderate_risk': 0,
        'low_risk': 0,
        'very_low_risk': 0
    }
    
    user_info = session_manager.get_user_info()
    batch_id = secrets.token_urlsafe(8)
    batch_start_time = datetime.now()
    
    logger.info(f"Batch analysis started by {user_info.get('username')} - ID: {batch_id}")
    
    for i, image in enumerate(image_list):
        try:
            img_array, original_size, validation_issues = preprocess_image(image)
            
            img_expanded = np.expand_dims(img_array, axis=0)
            model_pred = float(model.predict(img_expanded, verbose=0)[0][0])
            
            features = prediction_engine.analyze_image_characteristics(img_array)
            pred_result = prediction_engine.generate_enhanced_prediction(model_pred, features)
            final_pred = pred_result['final_prediction']
            
            if final_pred > 0.75:
                risk_category = "HIGH_RISK"
                summary_stats['high_risk'] += 1
            elif final_pred > 0.65:
                risk_category = "MODERATE_RISK"
                summary_stats['moderate_risk'] += 1
            elif final_pred > 0.45:
                risk_category = "LOW_RISK"
                summary_stats['low_risk'] += 1
            else:
                risk_category = "VERY_LOW_RISK"
                summary_stats['very_low_risk'] += 1
            
            results.append({
                'image_index': i + 1,
                'status': 'success',
                'prediction': final_pred,
                'risk_category': risk_category,
                'confidence': pred_result['confidence'],
                'pattern': features['pattern'],
                'quality': features['quality'],
                'validation_issues': validation_issues
            })
            
            summary_stats['success'] += 1
            
        except Exception as e:
            results.append({
                'image_index': i + 1,
                'status': 'error',
                'error': str(e),
                'traceback': traceback.format_exc()[-500:]
            })
            
            summary_stats['failed'] += 1
            logger.error(f"Batch analysis error for image {i+1}: {str(e)}")
    
    batch_end_time = datetime.now()
    processing_time = (batch_end_time - batch_start_time).total_seconds()
    
    summary_html = generate_batch_summary(results, summary_stats, batch_id, processing_time, user_info)
    
    logger.info(f"Batch analysis completed - ID: {batch_id}, Success: {summary_stats['success']}/{summary_stats['total']}")
    
    return summary_html

def generate_batch_summary(results, stats, batch_id, processing_time, user_info):
    """Generate HTML summary for batch analysis"""
    
    summary_html = f"""
    <div style="background: linear-gradient(135deg, #ffffff, #f8fafc); padding: 30px; border-radius: 20px; margin: 20px 0;">
        <h2 style="color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px;">📊 BATCH ANALYSIS SUMMARY</h2>
        
        <div style="background: #f8f9fa; padding: 20px; border-radius: 15px; margin: 20px 0;">
            <h3 style="color: #2c3e50; margin-top: 0;">Batch Information</h3>
            <table style="width: 100%; border-collapse: collapse;">
                <tr>
                    <td style="padding: 8px 0; color: #495057;"><strong>Batch ID:</strong></td>
                    <td style="padding: 8px 0; color: #2c3e50; font-family: monospace;">{batch_id}</td>
                </tr>
                <tr>
                    <td style="padding: 8px 0; color: #495057;"><strong>Analyzed by:</strong></td>
                    <td style="padding: 8px 0; color: #2c3e50;">{user_info.get('full_name', user_info.get('username'))}</td>
                </tr>
                <tr>
                    <td style="padding: 8px 0; color: #495057;"><strong>Processing Time:</strong></td>
                    <td style="padding: 8px 0; color: #2c3e50;">{processing_time:.2f} seconds</td>
                </tr>
                <tr>
                    <td style="padding: 8px 0; color: #495057;"><strong>Date/Time:</strong></td>
                    <td style="padding: 8px 0; color: #2c3e50;">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td>
                </tr>
            </table>
        </div>
        
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0;">
            <div style="background: linear-gradient(135deg, #27ae60, #2ecc71); color: white; padding: 20px; border-radius: 15px; text-align: center;">
                <div style="font-size: 2.5em; margin-bottom: 10px;">{stats['total']}</div>
                <div style="font-weight: 600;">Total Images</div>
            </div>
            <div style="background: linear-gradient(135deg, #3498db, #2980b9); color: white; padding: 20px; border-radius: 15px; text-align: center;">
                <div style="font-size: 2.5em; margin-bottom: 10px;">{stats['success']}</div>
                <div style="font-weight: 600;">Successful</div>
            </div>
            <div style="background: linear-gradient(135deg, #e74c3c, #c0392b); color: white; padding: 20px; border-radius: 15px; text-align: center;">
                <div style="font-size: 2.5em; margin-bottom: 10px;">{stats['failed']}</div>
                <div style="font-weight: 600;">Failed</div>
            </div>
        </div>
        
        <div style="background: #f8f9fa; padding: 20px; border-radius: 15px; margin: 20px 0;">
            <h3 style="color: #2c3e50; margin-top: 0;">Risk Distribution</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px;">
                <div style="background: #e74c3c; color: white; padding: 15px; border-radius: 10px; text-align: center;">
                    <div style="font-size: 1.8em; font-weight: 700;">{stats['high_risk']}</div>
                    <div>High Risk</div>
                </div>
                <div style="background: #e67e22; color: white; padding: 15px; border-radius: 10px; text-align: center;">
                    <div style="font-size: 1.8em; font-weight: 700;">{stats['moderate_risk']}</div>
                    <div>Moderate Risk</div>
                </div>
                <div style="background: #f1c40f; color: white; padding: 15px; border-radius: 10px; text-align: center;">
                    <div style="font-size: 1.8em; font-weight: 700;">{stats['low_risk']}</div>
                    <div>Low Risk</div>
                </div>
                <div style="background: #27ae60; color: white; padding: 15px; border-radius: 10px; text-align: center;">
                    <div style="font-size: 1.8em; font-weight: 700;">{stats['very_low_risk']}</div>
                    <div>Very Low Risk</div>
                </div>
            </div>
        </div>
        
        <div style="background: #f8f9fa; padding: 20px; border-radius: 15px; margin: 20px 0;">
            <h3 style="color: #2c3e50; margin-top: 0;">Detailed Results</h3>
            <div style="max-height: 400px; overflow-y: auto;">
                <table style="width: 100%; border-collapse: collapse; background: white; border-radius: 10px; overflow: hidden;">
                    <thead>
                        <tr style="background: linear-gradient(135deg, #1a2980, #26d0ce); color: white;">
                            <th style="padding: 12px 15px; text-align: left;">Image</th>
                            <th style="padding: 12px 15px; text-align: left;">Status</th>
                            <th style="padding: 12px 15px; text-align: left;">Prediction</th>
                            <th style="padding: 12px 15px; text-align: left;">Risk Category</th>
                            <th style="padding: 12px 15px; text-align: left;">Confidence</th>
                            <th style="padding: 12px 15px; text-align: left;">Pattern</th>
                        </tr>
                    </thead>
                    <tbody>
    """
    
    for result in results:
        if result['status'] == 'success':
            risk_color = {
                'HIGH_RISK': '#e74c3c',
                'MODERATE_RISK': '#e67e22',
                'LOW_RISK': '#f1c40f',
                'VERY_LOW_RISK': '#27ae60'
            }.get(result['risk_category'], '#95a5a6')
            
            summary_html += f"""
                        <tr style="border-bottom: 1px solid #e9ecef;">
                            <td style="padding: 10px 15px;">{result['image_index']}</td>
                            <td style="padding: 10px 15px;">
                                <span style="background: #27ae60; color: white; padding: 3px 8px; border-radius: 12px; font-size: 0.85em;">
                                    ✓ Success
                                </span>
                            </td>
                            <td style="padding: 10px 15px; font-weight: 600;">{result['prediction']:.3f}</td>
                            <td style="padding: 10px 15px;">
                                <span style="background: {risk_color}; color: white; padding: 3px 8px; border-radius: 12px; font-size: 0.85em;">
                                    {result['risk_category'].replace('_', ' ').title()}
                                </span>
                            </td>
                            <td style="padding: 10px 15px;">{result['confidence']:.1%}</td>
                            <td style="padding: 10px 15px;">{result['pattern'].title()}</td>
                        </tr>
            """
        else:
            summary_html += f"""
                        <tr style="border-bottom: 1px solid #e9ecef; background: #fff5f5;">
                            <td style="padding: 10px 15px;">{result['image_index']}</td>
                            <td style="padding: 10px 15px;" colspan="5">
                                <span style="background: #e74c3c; color: white; padding: 3px 8px; border-radius: 12px; font-size: 0.85em;">
                                    ✗ Failed
                                </span>
                                <div style="margin-top: 5px; color: #e74c3c; font-size: 0.9em;">{result['error']}</div>
                            </td>
                        </tr>
            """
    
    summary_html += """
                    </tbody>
                </table>
            </div>
        </div>
        
        <div style="background: linear-gradient(135deg, #fff8e1, #ffecb3); padding: 20px; border-radius: 15px; margin-top: 20px; border-left: 5px solid #ff9800;">
            <h4 style="color: #e65100; margin-top: 0;">⚠️ Batch Analysis Notes</h4>
            <ul style="margin: 0; padding-left: 20px; color: #5d4037;">
                <li>This batch analysis is for research and demonstration purposes only</li>
                <li>Results should not be used for clinical decision-making</li>
                <li>Each image is analyzed independently using the same model</li>
                <li>Failed images may require re-upload with different parameters</li>
            </ul>
        </div>
    </div>
    """
    
    return summary_html

# =============================================
# 12. EXPORT FUNCTIONALITY
# =============================================

@login_required
def export_analysis_report(image, report_text):
    """Export analysis report to JSON format"""
    try:
        user_info = session_manager.get_user_info()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if isinstance(image, np.ndarray):
            analysis_id = hashlib.md5(image.tobytes()).hexdigest()[:10]
        else:
            analysis_id = secrets.token_urlsafe(6)
        
        # Get current model accuracy from global metrics or use default
        current_accuracy = metrics.get('accuracy', 0.0) if 'metrics' in globals() else 0.0
        
        export_data = {
            'export_info': {
                'export_id': secrets.token_urlsafe(12),
                'timestamp': timestamp,
                'format_version': '1.0',
                'export_type': 'single_analysis'
            },
            'user_info': {
                'username': user_info.get('username', 'anonymous'),
                'full_name': user_info.get('full_name', ''),
                'role': user_info.get('role', 'user')
            },
            'analysis_info': {
                'analysis_id': analysis_id,
                'analysis_time': datetime.now().isoformat(),
                'model_used': model_metadata['name'],
                'model_version': model_metadata['version'],
                'training_accuracy': f"{current_accuracy:.1%}" if current_accuracy else "Unknown"
            },
            'report_content': report_text[:5000] if report_text else "No report content",
            'system_info': {
                'software_version': '4.1-Pro',
                'export_date': datetime.now().strftime('%Y-%m-%d'),
                'disclaimer': 'This report is for academic research purposes only. Not for clinical use.'
            }
        }
        
        exports_dir = Path('exports')
        exports_dir.mkdir(exist_ok=True)
        
        export_filename = f"lung_analysis_{timestamp}_{analysis_id}.json"
        export_path = exports_dir / export_filename
        
        with open(export_path, 'w') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Report exported: {export_filename} by user {user_info.get('username')}")
        
        return export_path, f"""
        <div style="background: linear-gradient(135deg, #27ae60, #2ecc71); color: white; padding: 20px; border-radius: 15px; text-align: center;">
            <h3 style="margin-top: 0; color: white;">✅ Report Exported Successfully</h3>
            <p style="font-size: 1.1em;">
            File: <strong>{export_filename}</strong><br>
            Saved to: <strong>exports/</strong> directory
            </p>
            <div style="background: rgba(255,255,255,0.2); padding: 15px; border-radius: 10px; margin-top: 15px; font-family: monospace; font-size: 0.9em;">
            Export ID: {export_data['export_info']['export_id']}
            </div>
        </div>
        """
        
    except Exception as e:
        logger.error(f"Export error: {str(e)}")
        return None, f"""
        <div style="background: linear-gradient(135deg, #e74c3c, #c0392b); color: white; padding: 20px; border-radius: 15px; text-align: center;">
            <h3 style="margin-top: 0; color: white;">❌ Export Failed</h3>
            <p>Error: {str(e)[:100]}...</p>
        </div>
        """

# =============================================
# 13. ENHANCED SECURE PREDICTION FUNCTION
# =============================================

@login_required
def analyze_lung_nodule(image, model: tf.keras.Model, model_metrics: Dict) -> str:
    """Main analysis function with comprehensive reporting"""
    try:
        start_time = time.time()
        user_info = session_manager.get_user_info()
        
        img_array, original_size, validation_issues = preprocess_image(image)
        
        analysis_id = hashlib.md5(img_array.tobytes()).hexdigest()[:10]
        logger.info(f"Analysis started - ID: {analysis_id}, User: {user_info.get('username')}")

        img_expanded = np.expand_dims(img_array, axis=0)
        model_pred = float(model.predict(img_expanded, verbose=0)[0][0])

        features = prediction_engine.analyze_image_characteristics(img_array)
        pred_result = prediction_engine.generate_enhanced_prediction(model_pred, features)
        final_pred = pred_result['final_prediction']
        confidence = pred_result['confidence']

        proc_time = time.time() - start_time

        if final_pred > 0.75:
            result = "🔴 **HIGH RISK - SUSPICIOUS FOR MALIGNANCY**"
            risk_level = "HIGH RISK"
            urgency = "URGENT EVALUATION"
            color = "#e74c3c"
            warning = "🚨 URGENT CLINICAL ATTENTION REQUIRED"
            recommendations = f"""
            1. **Immediate Actions:**
               • Thoracic oncology consultation within 24-48 hours
               • PET-CT for staging within 72 hours
               • Multidisciplinary tumor board review

            2. **Diagnostic Procedures:**
               • CT-guided biopsy for tissue diagnosis
               • Brain MRI if neurological symptoms
               • Pulmonary function testing

            3. **Pattern Analysis:**
               • **Detected Pattern:** {features['pattern'].title()}
               • **Description:** {features['pattern_desc']}
               • **Edge Irregularity:** High ({features['edge_strength']:.3f})
               • **Confidence Level:** {confidence:.1%}
            """

        elif final_pred > 0.65:
            result = "🟠 **MODERATE RISK - SUSPICIOUS FINDINGS**"
            risk_level = "INTERMEDIATE RISK"
            urgency = "PROMPT EVALUATION"
            color = "#e67e22"
            warning = "⚠️ FURTHER EVALUATION RECOMMENDED"
            recommendations = f"""
            1. **Recommended Actions:**
               • Pulmonology referral within 1-2 weeks
               • Contrast-enhanced CT within 1 month
               • Consider PET-CT if high clinical suspicion

            2. **Monitoring Strategy:**
               • Repeat CT in 3 months
               • Compare with prior imaging if available
               • Document growth rate if serial imaging

            3. **Pattern Analysis:**
               • **Detected Pattern:** {features['pattern'].title()}
               • **Description:** {features['pattern_desc']}
               • **Image Quality:** {features['quality']}
               • **Confidence Level:** {confidence:.1%}
            """

        elif final_pred > 0.45:
            result = "🟡 **LOW RISK - INDETERMINATE FINDING**"
            risk_level = "LOW-MODERATE RISK"
            urgency = "ROUTINE FOLLOW-UP"
            color = "#f39c12"
            warning = "ℹ️ SHORT-TERM FOLLOW-UP ADVISED"
            recommendations = f"""
            1. **Follow-up Strategy:**
               • Repeat CT in 6-12 months
               • Document baseline characteristics
               • Consider volumetry software for precise measurement

            2. **Clinical Correlation:**
               • Review patient risk factors
               • Assess smoking history
               • Evaluate for respiratory symptoms

            3. **Pattern Analysis:**
               • **Detected Pattern:** {features['pattern'].title()}
               • **Description:** {features['pattern_desc']}
               • **Texture Complexity:** {features['entropy']:.1f} bits
               • **Confidence Level:** {confidence:.1%}
            """

        else:
            result = "🟢 **VERY LOW RISK - LIKELY BENIGN**"
            risk_level = "MINIMAL RISK"
            urgency = "ROUTINE MONITORING"
            color = "#27ae60"
            warning = "✅ LIKELY BENIGN - ROUTINE MONITORING"
            recommendations = f"""
            1. **Standard Monitoring:**
               • Annual CT for 2 years if stable
               • Consider discharge if unchanged for 2+ years
               • Document in medical record

            2. **Patient Management:**
               • Discuss benign nature with patient
               • Provide smoking cessation resources
               • Review lung cancer screening guidelines

            3. **Pattern Analysis:**
               • **Detected Pattern:** {features['pattern'].title()}
               • **Description:** {features['pattern_desc']}
               • **Image Quality:** {features['quality']} (Score: {features['quality_score']:.2f}/1.0)
               • **Confidence Level:** {confidence:.1%}
            """

        bar_length = int(confidence * 20)
        confidence_bar = "█" * bar_length + "░" * (20 - bar_length)

        if confidence > 0.85:
            conf_level = "VERY HIGH CONFIDENCE"
            conf_emoji = "🟢"
        elif confidence > 0.75:
            conf_level = "HIGH CONFIDENCE"
            conf_emoji = "🟡"
        elif confidence > 0.65:
            conf_level = "MODERATE CONFIDENCE"
            conf_emoji = "🟠"
        else:
            conf_level = "LOW CONFIDENCE"
            conf_emoji = "🔴"

        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        validation_html = ""
        if validation_issues:
            validation_html = f"""
            ### ⚠️ IMAGE VALIDATION NOTES
            <div style="background: linear-gradient(135deg, #fff8e1, #ffecb3); padding: 20px; border-radius: 12px; margin: 15px 0; border-left: 5px solid #ff9800;">
                <p><strong>Note:</strong> The following issues were detected during image validation:</p>
                <ul style="margin: 10px 0 0 0; padding-left: 20px;">
            """
            for issue in validation_issues:
                validation_html += f"<li>{issue}</li>"
            validation_html += """
                </ul>
            </div>
            """

        user_display = f"**Analyzed by:** {user_info.get('username', 'Unknown')}"
        if user_info.get('full_name'):
            user_display += f" ({user_info.get('full_name')})"
        if user_info.get('role') == 'admin':
            user_display += " 👑"

        session_mins = session_manager.get_session_remaining_time()
        session_info = f"**Session expires in:** {session_mins} minutes"

        model_metrics_display = ""
        if model_metrics:
            model_metrics_display = f"""
            **Model Performance:**
            • Accuracy: {model_metrics.get('accuracy', 0):.1%}
            • Precision: {model_metrics.get('precision', 0):.1%}
            • Recall/Sensitivity: {model_metrics.get('sensitivity', 0):.1%}
            • Specificity: {model_metrics.get('specificity', 0):.1%}
            • F1-Score: {model_metrics.get('f1_score', 0):.1%}
            • AUC Score: {model_metrics.get('auc_score', 0):.3f}
            """

        report = f"""
        # 🫁 ADVANCED LUNG NODULE ANALYSIS REPORT

        ## {result}

        ### 🚨 {warning}

        ---

        ### 👤 USER INFORMATION
        {user_display}<br>
        {session_info}<br>
        **Analysis ID:** <span style="font-family: monospace; background-color: #f5f5f5; padding: 3px 8px; border-radius: 4px">{analysis_id}</span>

        ### 📊 CLINICAL ASSESSMENT
        **Risk Level:** <span style="color: {color}; font-weight: bold">{risk_level}</span><br>
        **Clinical Priority:** <span style="color: {color}; font-weight: bold">{urgency}</span><br>
        **Malignancy Probability:** <span style="color: {color}; font-weight: bold">{final_pred:.1%}</span><br>
        **Confidence Score:** <span style="color: {color}; font-weight: bold">{confidence:.1%} ({conf_emoji} {conf_level})</span><br>
        **Processing Time:** {proc_time:.2f} seconds

        ### 📈 CONFIDENCE VISUALIZATION
        {conf_emoji} **Confidence:** {confidence:.1%}
        ```
        [{confidence_bar}]
        ```

        {validation_html}

        ### 🔬 TECHNICAL ANALYSIS
        **Final Prediction:** <span style="background-color: #f8f9fa; padding: 3px 8px; border-radius: 4px; font-weight: bold">{final_pred:.4f}</span><br>
        **Base Model Output:** {model_pred:.4f}<br>
        **Pattern Detection:** <span style="background-color: #e3f2fd; padding: 3px 8px; border-radius: 4px; font-weight: bold">{features['pattern'].title()}</span><br>
        **Image Quality:** <span style="background-color: {features['quality_color']}; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold">{features['quality']}</span><br>
        **Image Dimensions:** {original_size[0]}×{original_size[1]} → 128×128 pixels

        ### 📊 IMAGE CHARACTERISTICS
        <table style="width: 100%; border-collapse: collapse; margin: 20px 0; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 3px 15px rgba(0,0,0,0.08);">
        <thead>
        <tr style="background: linear-gradient(135deg, #1a2980, #26d0ce); color: white;">
            <th style="padding: 15px; text-align: left; font-weight: 600;">Metric</th>
            <th style="padding: 15px; text-align: left; font-weight: 600;">Value</th>
            <th style="padding: 15px; text-align: left; font-weight: 600;">Score</th>
            <th style="padding: 15px; text-align: left; font-weight: 600;">Interpretation</th>
        </tr>
        </thead>
        <tbody>
        <tr style="border-bottom: 1px solid #e9ecef;">
            <td style="padding: 12px 15px; font-weight: 600; color: #2c3e50;">Brightness</td>
            <td style="padding: 12px 15px; font-family: monospace; color: #1a2980;">{features['brightness']:.3f}</td>
            <td style="padding: 12px 15px; font-family: monospace; color: #1a2980;">{features['brightness_score']:.2f}</td>
            <td style="padding: 12px 15px; color: {'#27ae60' if 0.3 <= features['brightness'] <= 0.7 else '#e74c3c'};">{'✅ Optimal' if 0.3 <= features['brightness'] <= 0.7 else '⚠️ Suboptimal'}</td>
        </tr>
        <tr style="border-bottom: 1px solid #e9ecef;">
            <td style="padding: 12px 15px; font-weight: 600; color: #2c3e50;">Contrast</td>
            <td style="padding: 12px 15px; font-family: monospace; color: #1a2980;">{features['contrast']:.3f}</td>
            <td style="padding: 12px 15px; font-family: monospace; color: #1a2980;">{features['contrast_score']:.2f}</td>
            <td style="padding: 12px 15px; color: {'#27ae60' if features['contrast'] > 0.15 else '#e74c3c'};">{'✅ Good' if features['contrast'] > 0.15 else '⚠️ Low'}</td>
        </tr>
        <tr style="border-bottom: 1px solid #e9ecef;">
            <td style="padding: 12px 15px; font-weight: 600; color: #2c3e50;">Edge Strength</td>
            <td style="padding: 12px 15px; font-family: monospace; color: #1a2980;">{features['edge_strength']:.3f}</td>
            <td style="padding: 12px 15px; font-family: monospace; color: #1a2980;">{features['edge_score']:.2f}</td>
            <td style="padding: 12px 15px; color: {'#27ae60' if features['edge_strength'] > 0.08 else '#3498db'};">{'🔍 High' if features['edge_strength'] > 0.08 else '📏 Low'}</td>
        </tr>
        <tr style="border-bottom: 1px solid #e9ecef;">
            <td style="padding: 12px 15px; font-weight: 600; color: #2c3e50;">Entropy</td>
            <td style="padding: 12px 15px; font-family: monospace; color: #1a2980;">{features['entropy']:.2f} bits</td>
            <td style="padding: 12px 15px; font-family: monospace; color: #1a2980;">{features['entropy_score']:.2f}</td>
            <td style="padding: 12px 15px; color: {'#9b59b6' if features['entropy'] > 4 else '#3498db'};">{'🌀 Complex' if features['entropy'] > 4 else '⚪ Simple'}</td>
        </tr>
        <tr>
            <td style="padding: 12px 15px; font-weight: 600; color: #2c3e50;">Dynamic Range</td>
            <td style="padding: 12px 15px; font-family: monospace; color: #1a2980;">{features['dynamic_range']:.3f}</td>
            <td style="padding: 12px 15px; font-family: monospace; color: #1a2980;">-</td>
            <td style="padding: 12px 15px; color: {'#27ae60' if features['dynamic_range'] > 0.4 else '#e74c3c'};">{'✅ Good' if features['dynamic_range'] > 0.4 else '⚠️ Limited'}</td>
        </tr>
        </tbody>
        </table>

        ### 🏥 CLINICAL RECOMMENDATIONS
        <div style="background: linear-gradient(135deg, #f8f9fa, #ffffff); padding: 25px; border-radius: 12px; border-left: 5px solid {color}; margin: 20px 0; box-shadow: 0 5px 15px rgba(0,0,0,0.05);">
        {recommendations}
        </div>

        ### 🛠️ SYSTEM INFORMATION
        <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; border: 2px solid #e9ecef; margin: 20px 0;">
        **Model:** {model_metadata['name']} v{model_metadata['version']}<br>
        **Parameters:** {model_metadata['parameters']}<br>
        **Training Date:** {model_metadata.get('last_trained', 'Not available')}<br>
        **Analysis Engine:** Advanced Pattern Recognition v1.2<br>
        **Status:** {model_metadata['status']}<br>
        {model_metrics_display}
        </div>

        ---

        ### 🎓 ACADEMIC CONTEXT
        **Project:** Lung Nodule Classification using CNN<br>
        **Student:** Kelvin Njagi Njoki (B144/24928/2022)<br>
        **Institution:** University of Embu<br>
        **Program:** Business Information Technology<br>
        **Thesis Year:** 2026<br>
        **Research Focus:** AI/ML applications in medical imaging, pattern recognition, and ethical AI implementation

        ---

        <div style="background: linear-gradient(135deg, #fff8e1, #ffecb3); padding: 20px; border-radius: 12px; margin: 25px 0; border-left: 5px solid #ff9800; box-shadow: 0 3px 10px rgba(255, 152, 0, 0.1);">
        ⚠️ **RESEARCH DISCLAIMER:** This system demonstrates advanced AI pattern recognition for academic research purposes only. It is NOT approved for clinical diagnosis, medical decision-making, or patient treatment. Always consult qualified healthcare professionals for medical decisions.
        </div>

        <div style="text-align: center; padding: 15px; background: linear-gradient(135deg, #f8f9fa, #e3f2fd); border-radius: 10px; margin-top: 20px; font-size: 0.9em; color: #7f8c8d; border: 1px solid #e0e6ff;">
        Report generated: {current_time}<br>
        <small>Analysis ID: {analysis_id} | Session: {session_manager.current_session[:10]}...</small>
        </div>
        """

        logger.info(f"Analysis completed - ID: {analysis_id}, Risk: {risk_level}, Prediction: {final_pred:.3f}")

        return report

    except Exception as e:
        error_details = traceback.format_exc()
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        logger.error(f"Analysis error: {str(e)}\n{error_details}")

        return f"""
        # ❌ ANALYSIS ERROR

        ## Technical Issue Detected

        **Error Details:**
        ```python
        {str(e)}
        ```

        **Troubleshooting Steps:**
        1. Verify the image format (JPEG/PNG recommended)
        2. Ensure image has sufficient contrast and brightness
        3. Check file size (<10MB recommended)
        4. Try converting the image to RGB format
        5. Use a different CT slice with clear lung window settings

        **System Status:**
        • Time: {current_time}
        • Model: {model_metadata['name']} v{model_metadata['version']}
        • Status: Please retry with a different image
        • User: {session_manager.current_user.get('username', 'Unknown')}

        **Support Information:**
        This is an academic research system. For persistent issues, please contact the system administrator.
        """

# =============================================
# 14. USER MANAGEMENT FUNCTIONS
# =============================================

def login_function(username: str, password: str) -> Tuple[str, bool]:
    """Handle user login with enhanced security"""
    if not username or not password:
        return "❌ Username and password are required", False
    
    if len(username) < 3 or len(username) > 50:
        return "❌ Username must be between 3 and 50 characters", False
    
    if len(password) < 6:
        return "❌ Password must be at least 6 characters", False
    
    success, message = session_manager.login(username, password, ip_address="127.0.0.1")
    
    if success:
        user_role = session_manager.current_user.get('role', 'user')
        return f"✅ {message}\n\nWelcome, {username}! ({user_role.upper()})", True
    else:
        return f"❌ Login Failed: {message}", False

def logout_function() -> Tuple[str, bool]:
    """Handle user logout"""
    session_manager.logout()
    return "✅ Successfully logged out!", False

# =============================================
# 15. PASSWORD RECOVERY FUNCTION
# =============================================

def request_security_question(username: str) -> Tuple[bool, str]:
    """Get security question for password recovery"""
    if not username:
        return False, "Please enter your username"
    
    success, result = user_db.get_security_question(username)
    if success:
        return True, f"**Security Question:** {result}\n\nPlease answer this question to reset your password."
    else:
        return False, result

def verify_security_answer_and_reset(username: str, answer: str, new_password: str, show_password: bool = False) -> Tuple[bool, str]:
    """Verify security answer and reset password"""
    if not username or not answer or not new_password:
        return False, "All fields are required"
    
    if len(new_password) < 8:
        return False, "Password must be at least 8 characters"
    
    # Verify security answer
    success, message = user_db.verify_security_answer(username, answer)
    if not success:
        return False, message
    
    # Reset password
    success, message = user_db.reset_password(username, new_password)
    
    password_display = new_password if show_password else "•" * 8
    
    if success:
        return True, f"✅ Password reset successful!\n\n**New Password:** {password_display}\n\nPlease login with your new password."
    else:
        return False, message

# =============================================
# 16. ADMIN USER MANAGEMENT FUNCTIONS
# =============================================

def admin_create_user(username: str, password: str, full_name: str, email: str, 
                      role: str, security_question: str, security_answer: str,
                      show_password: bool = False) -> Tuple[bool, str]:
    """Admin function to create a new user"""
    if not session_manager.is_admin():
        return False, "⛔ Admin privileges required"
    
    if not username or not password:
        return False, "Username and password are required"
    
    if len(username) < 3 or len(username) > 50:
        return False, "Username must be between 3 and 50 characters"
    
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    
    if not security_question or not security_answer:
        return False, "Security question and answer are required"
    
    admin_username = session_manager.current_user.get('username', 'admin')
    
    success, message = user_db.create_user(
        username=username,
        password=password,
        full_name=full_name,
        email=email,
        role=role,
        security_question=security_question,
        security_answer=security_answer
    )
    
    password_display = password if show_password else "•" * 8
    
    if success:
        return True, f"✅ User created successfully!\n\n**Username:** {username}\n**Password:** {password_display}\n\nUser is now pending admin approval."
    else:
        return False, f"❌ Error: {message}"

def admin_reset_password(username: str, new_password: str, show_password: bool = False) -> Tuple[bool, str]:
    """Admin function to reset user password"""
    if not session_manager.is_admin():
        return False, "⛔ Admin privileges required"
    
    if not username or not new_password:
        return False, "Username and new password are required"
    
    if len(new_password) < 8:
        return False, "Password must be at least 8 characters"
    
    admin_username = session_manager.current_user.get('username', 'admin')
    
    success, message = user_db.reset_password(username, new_password, admin_username)
    
    password_display = new_password if show_password else "•" * 8
    
    if success:
        return True, f"✅ Password reset successful!\n\n**Username:** {username}\n**New Password:** {password_display}"
    else:
        return False, f"❌ Error: {message}"

def admin_approve_user(username: str) -> Tuple[bool, str]:
    """Admin function to approve a pending user"""
    if not session_manager.is_admin():
        return False, "⛔ Admin privileges required"
    
    if not username:
        return False, "Username is required"
    
    admin_username = session_manager.current_user.get('username', 'admin')
    
    success, message = user_db.approve_user(username, admin_username)
    
    if success:
        return True, f"✅ User {username} approved successfully!"
    else:
        return False, f"❌ Error: {message}"

def admin_disable_user(username: str) -> Tuple[bool, str]:
    """Admin function to disable a user"""
    if not session_manager.is_admin():
        return False, "⛔ Admin privileges required"
    
    if not username:
        return False, "Username is required"
    
    admin_username = session_manager.current_user.get('username', 'admin')
    
    success, message = user_db.disable_user(username, admin_username)
    
    if success:
        return True, f"✅ User {username} disabled successfully!"
    else:
        return False, f"❌ Error: {message}"

def admin_activate_user(username: str) -> Tuple[bool, str]:
    """Admin function to activate a disabled user"""
    if not session_manager.is_admin():
        return False, "⛔ Admin privileges required"
    
    if not username:
        return False, "Username is required"
    
    admin_username = session_manager.current_user.get('username', 'admin')
    
    success, message = user_db.activate_user(username, admin_username)
    
    if success:
        return True, f"✅ User {username} activated successfully!"
    else:
        return False, f"❌ Error: {message}"

def admin_delete_user(username: str) -> Tuple[bool, str]:
    """Admin function to delete a user"""
    if not session_manager.is_admin():
        return False, "⛔ Admin privileges required"
    
    if not username:
        return False, "Username is required"
    
    if username == 'admin':
        return False, "Cannot delete admin account"
    
    admin_username = session_manager.current_user.get('username', 'admin')
    
    success, message = user_db.delete_user(username, admin_username)
    
    if success:
        return True, f"✅ User {username} deleted successfully!"
    else:
        return False, f"❌ Error: {message}"

@admin_required
def get_user_management_dashboard():
    """Get user management dashboard for admin"""
    try:
        users = user_db.get_all_users()
        user_stats = user_db.get_user_stats()
        pending_users = user_db.get_pending_users()
        
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        dashboard_html = f"""
        <div style="background: linear-gradient(135deg, #1a2980, #26d0ce); color: white; padding: 30px; border-radius: 20px; margin-bottom: 30px;">
            <h2 style="margin-top: 0; color: white;">👑 USER MANAGEMENT DASHBOARD</h2>
            <p>Last Updated: {current_time}</p>
        </div>
        
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px;">
            <div style="background: linear-gradient(135deg, #27ae60, #2ecc71); color: white; padding: 25px; border-radius: 15px; text-align: center;">
                <div style="font-size: 2.5em; margin-bottom: 10px;">{user_stats.get('total_users', 0)}</div>
                <div style="font-weight: 600;">Total Users</div>
            </div>
            <div style="background: linear-gradient(135deg, #3498db, #2980b9); color: white; padding: 25px; border-radius: 15px; text-align: center;">
                <div style="font-size: 2.5em; margin-bottom: 10px;">{user_stats.get('active_users', 0)}</div>
                <div style="font-weight: 600;">Active Users</div>
            </div>
            <div style="background: linear-gradient(135deg, #f39c12, #e67e22); color: white; padding: 25px; border-radius: 15px; text-align: center;">
                <div style="font-size: 2.5em; margin-bottom: 10px;">{user_stats.get('pending_users', 0)}</div>
                <div style="font-weight: 600;">Pending Approval</div>
            </div>
            <div style="background: linear-gradient(135deg, #e74c3c, #c0392b); color: white; padding: 25px; border-radius: 15px; text-align: center;">
                <div style="font-size: 2.5em; margin-bottom: 10px;">{user_stats.get('disabled_users', 0)}</div>
                <div style="font-weight: 600;">Disabled Users</div>
            </div>
        </div>
        
        <div style="background: white; padding: 25px; border-radius: 15px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); margin-bottom: 30px;">
            <h3 style="color: #2c3e50; margin-top: 0; border-bottom: 2px solid #3498db; padding-bottom: 10px;">
                ⏳ PENDING APPROVAL ({len(pending_users)} users)
            </h3>
            <div style="max-height: 300px; overflow-y: auto;">
        """
        
        if pending_users:
            dashboard_html += """
                <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                    <thead>
                        <tr style="background: linear-gradient(135deg, #f8f9fa, #e9ecef);">
                            <th style="padding: 12px 15px; text-align: left; color: #495057;">Username</th>
                            <th style="padding: 12px 15px; text-align: left; color: #495057;">Full Name</th>
                            <th style="padding: 12px 15px; text-align: left; color: #495057;">Email</th>
                            <th style="padding: 12px 15px; text-align: left; color: #495057;">Created At</th>
                            <th style="padding: 12px 15px; text-align: left; color: #495057;">Action</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            
            for user in pending_users:
                dashboard_html += f"""
                        <tr style="border-bottom: 1px solid #e9ecef;">
                            <td style="padding: 10px 15px; color: #2c3e50; font-weight: 600;">{user['username']}</td>
                            <td style="padding: 10px 15px; color: #495057;">{user.get('full_name', 'N/A')}</td>
                            <td style="padding: 10px 15px; color: #495057;">{user.get('email', 'N/A')}</td>
                            <td style="padding: 10px 15px; color: #495057; font-size: 0.9em;">{user.get('created_at', 'N/A')}</td>
                            <td style="padding: 10px 15px;">
                                <button onclick="approveUser('{user['username']}')" style="
                                    background: linear-gradient(135deg, #27ae60, #2ecc71);
                                    color: white;
                                    border: none;
                                    padding: 6px 12px;
                                    border-radius: 4px;
                                    cursor: pointer;
                                    font-size: 0.85em;
                                ">Approve</button>
                            </td>
                        </tr>
                """
            
            dashboard_html += """
                    </tbody>
                </table>
            """
        else:
            dashboard_html += """
                <div style="text-align: center; padding: 40px; color: #7f8c8d;">
                    <div style="font-size: 3em; margin-bottom: 15px;">📋</div>
                    <p style="font-size: 1.1em;">No pending users for approval</p>
                </div>
            """
        
        dashboard_html += """
            </div>
        </div>
        
        <div style="background: white; padding: 25px; border-radius: 15px; box-shadow: 0 5px 15px rgba(0,0,0,0.1);">
            <h3 style="color: #2c3e50; margin-top: 0; border-bottom: 2px solid #3498db; padding-bottom: 10px;">
                👥 ALL USERS ({len(users)} total)
            </h3>
            <div style="max-height: 500px; overflow-y: auto;">
        """
        
        if users:
            dashboard_html += """
                <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                    <thead>
                        <tr style="background: linear-gradient(135deg, #f8f9fa, #e9ecef);">
                            <th style="padding: 12px 15px; text-align: left; color: #495057;">Username</th>
                            <th style="padding: 12px 15px; text-align: left; color: #495057;">Full Name</th>
                            <th style="padding: 12px 15px; text-align: left; color: #495057;">Role</th>
                            <th style="padding: 12px 15px; text-align: left; color: #495057;">Status</th>
                            <th style="padding: 12px 15px; text-align: left; color: #495057;">Approved</th>
                            <th style="padding: 12px 15px; text-align: left; color: #495057;">Last Login</th>
                            <th style="padding: 12px 15px; text-align: left; color: #495057;">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            
            for user in users:
                status_color = {
                    'active': '#27ae60',
                    'pending': '#f39c12',
                    'disabled': '#e74c3c'
                }.get(user['status'], '#95a5a6')
                
                approved_color = '#27ae60' if user['is_approved'] else '#e74c3c'
                approved_text = '✅ Yes' if user['is_approved'] else '❌ No'
                
                dashboard_html += f"""
                        <tr style="border-bottom: 1px solid #e9ecef;">
                            <td style="padding: 10px 15px; color: #2c3e50; font-weight: 600;">{user['username']}</td>
                            <td style="padding: 10px 15px; color: #495057;">{user.get('full_name', 'N/A')}</td>
                            <td style="padding: 10px 15px;">
                                <span style="
                                    background: {'#9b59b6' if user['role'] == 'admin' else '#3498db'};
                                    color: white;
                                    padding: 3px 8px;
                                    border-radius: 12px;
                                    font-size: 0.85em;
                                ">{user['role'].upper()}</span>
                            </td>
                            <td style="padding: 10px 15px;">
                                <span style="
                                    background: {status_color};
                                    color: white;
                                    padding: 3px 8px;
                                    border-radius: 12px;
                                    font-size: 0.85em;
                                ">{user['status'].upper()}</span>
                            </td>
                            <td style="padding: 10px 15px;">
                                <span style="color: {approved_color}; font-weight: 600;">{approved_text}</span>
                            </td>
                            <td style="padding: 10px 15px; color: #495057; font-size: 0.9em;">{user.get('last_login', 'Never')}</td>
                            <td style="padding: 10px 15px;">
                """
                
                if user['status'] == 'disabled':
                    dashboard_html += f"""
                                <button onclick="activateUser('{user['username']}')" style="
                                    background: linear-gradient(135deg, #27ae60, #2ecc71);
                                    color: white;
                                    border: none;
                                    padding: 6px 12px;
                                    border-radius: 4px;
                                    cursor: pointer;
                                    font-size: 0.85em;
                                    margin-right: 5px;
                                ">Activate</button>
                    """
                elif user['status'] == 'active' and user['username'] != 'admin':
                    dashboard_html += f"""
                                <button onclick="disableUser('{user['username']}')" style="
                                    background: linear-gradient(135deg, #e74c3c, #c0392b);
                                    color: white;
                                    border: none;
                                    padding: 6px 12px;
                                    border-radius: 4px;
                                    cursor: pointer;
                                    font-size: 0.85em;
                                    margin-right: 5px;
                                ">Disable</button>
                    """
                
                if user['username'] != 'admin':
                    dashboard_html += f"""
                                <button onclick="resetUserPassword('{user['username']}')" style="
                                    background: linear-gradient(135deg, #3498db, #2980b9);
                                    color: white;
                                    border: none;
                                    padding: 6px 12px;
                                    border-radius: 4px;
                                    cursor: pointer;
                                    font-size: 0.85em;
                                    margin-right: 5px;
                                ">Reset PW</button>
                                <button onclick="deleteUser('{user['username']}')" style="
                                    background: linear-gradient(135deg, #e74c3c, #c0392b);
                                    color: white;
                                    border: none;
                                    padding: 6px 12px;
                                    border-radius: 4px;
                                    cursor: pointer;
                                    font-size: 0.85em;
                                ">Delete</button>
                    """
                
                dashboard_html += """
                            </td>
                        </tr>
                """
            
            dashboard_html += """
                    </tbody>
                </table>
            """
        else:
            dashboard_html += """
                <div style="text-align: center; padding: 40px; color: #7f8c8d;">
                    <div style="font-size: 3em; margin-bottom: 15px;">👥</div>
                    <p style="font-size: 1.1em;">No users found</p>
                </div>
            """
        
        dashboard_html += """
            </div>
        </div>
        
        <div style="margin-top: 30px; background: #f8f9fa; padding: 20px; border-radius: 15px; border-left: 5px solid #ff9800;">
            <h4 style="color: #e65100; margin-top: 0;">📋 USER MANAGEMENT NOTES</h4>
            <ul style="margin: 0; padding-left: 20px; color: #5d4037; font-size: 0.95em;">
                <li>All new users require admin approval before they can login</li>
                <li>Disabled users cannot login until re-activated by admin</li>
                <li>Admin account cannot be disabled or deleted</li>
                <li>Password resets generate new passwords that should be shared securely</li>
                <li>All actions are logged in the audit system</li>
            </ul>
        </div>
        
        <script>
        function approveUser(username) {{
            alert('Approve user: ' + username + '\\n\\nThis would trigger an approval action in the actual system.');
            // In a real implementation, this would call a backend function
        }}
        
        function disableUser(username) {{
            if (confirm('Are you sure you want to disable user: ' + username + '?')) {{
                alert('Disable user: ' + username + '\\n\\nThis would trigger a disable action in the actual system.');
            }}
        }}
        
        function activateUser(username) {{
            alert('Activate user: ' + username + '\\n\\nThis would trigger an activation action in the actual system.');
        }}
        
        function resetUserPassword(username) {{
            alert('Reset password for user: ' + username + '\\n\\nThis would open a password reset dialog in the actual system.');
        }}
        
        function deleteUser(username) {{
            if (confirm('Are you sure you want to delete user: ' + username + '?\\n\\nThis action cannot be undone.')) {{
                alert('Delete user: ' + username + '\\n\\nThis would trigger a deletion action in the actual system.');
            }}
        }}
        </script>
        """
        
        return dashboard_html
        
    except Exception as e:
        logger.error(f"User management dashboard error: {str(e)}")
        return f"<div style='color: #e74c3c; padding: 20px; background: #fff5f5; border-radius: 10px;'>Error loading user dashboard: {str(e)}</div>"

# =============================================
# 17. HELPER FUNCTIONS FOR PORT HANDLING
# =============================================

def is_port_available(port: int) -> bool:
    """Check if a port is available"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex(('localhost', port))
            return result != 0
    except Exception:
        return False

def find_available_port(start_port: int = 7860, max_attempts: int = 100) -> int:
    """Find an available port starting from start_port"""
    for port in range(start_port, start_port + max_attempts):
        if is_port_available(port):
            return port
    raise OSError(f"No available ports found in range {start_port}-{start_port + max_attempts - 1}")

# =============================================
# 18. SYSTEM DASHBOARD FUNCTIONS
# =============================================

@admin_required
def get_system_dashboard():
    """Get system dashboard information"""
    try:
        user_stats = user_db.get_user_stats()
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if os.path.exists('model_metrics.json'):
            with open('model_metrics.json', 'r') as f:
                model_metrics = json.load(f)
        else:
            model_metrics = {}
        
        log_file = 'logs/lung_classifier.log'
        recent_logs = []
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                lines = f.readlines()
                recent_logs = lines[-10:]
        
        dashboard_html = f"""
        <div style="background: linear-gradient(135deg, #1a2980, #26d0ce); color: white; padding: 30px; border-radius: 20px; margin-bottom: 30px;">
            <h2 style="margin-top: 0; color: white;">📊 SYSTEM DASHBOARD</h2>
            <p>Last Updated: {current_time}</p>
        </div>
        
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px;">
            <div style="background: white; padding: 25px; border-radius: 15px; box-shadow: 0 5px 15px rgba(0,0,0,0.1);">
                <h3 style="color: #2c3e50; margin-top: 0;">👥 USER STATISTICS</h3>
                <table style="width: 100%; border-collapse: collapse;">
                    <tr><td style="padding: 8px 0; color: #495057;">Total Users:</td><td style="padding: 8px 0; color: #2c3e50; font-weight: 600;">{user_stats.get('total_users', 0)}</td></tr>
                    <tr><td style="padding: 8px 0; color: #495057;">Active Users:</td><td style="padding: 8px 0; color: #2c3e50; font-weight: 600;">{user_stats.get('active_users', 0)}</td></tr>
                    <tr><td style="padding: 8px 0; color: #495057;">Pending Approval:</td><td style="padding: 8px 0; color: #2c3e50; font-weight: 600;">{user_stats.get('pending_users', 0)}</td></tr>
                    <tr><td style="padding: 8px 0; color: #495057;">Disabled Users:</td><td style="padding: 8px 0; color: #2c3e50; font-weight: 600;">{user_stats.get('disabled_users', 0)}</td></tr>
                    <tr><td style="padding: 8px 0; color: #495057;">Online Now:</td><td style="padding: 8px 0; color: #2c3e50; font-weight: 600;">{user_stats.get('online_users', 0)}</td></tr>
                </table>
            </div>
            
            <div style="background: white; padding: 25px; border-radius: 15px; box-shadow: 0 5px 15px rgba(0,0,0,0.1);">
                <h3 style="color: #2c3e50; margin-top: 0;">🤖 MODEL PERFORMANCE</h3>
                <table style="width: 100%; border-collapse: collapse;">
                    <tr><td style="padding: 8px 0; color: #495057;">Accuracy:</td><td style="padding: 8px 0; color: #2c3e50; font-weight: 600;">{model_metrics.get('accuracy', 0):.1%}</td></tr>
                    <tr><td style="padding: 8px 0; color: #495057;">Precision:</td><td style="padding: 8px 0; color: #2c3e50; font-weight: 600;">{model_metrics.get('precision', 0):.1%}</td></tr>
                    <tr><td style="padding: 8px 0; color: #495057;">Recall:</td><td style="padding: 8px 0; color: #2c3e50; font-weight: 600;">{model_metrics.get('sensitivity', 0):.1%}</td></tr>
                    <tr><td style="padding: 8px 0; color: #495057;">F1-Score:</td><td style="padding: 8px 0; color: #2c3e50; font-weight: 600;">{model_metrics.get('f1_score', 0):.1%}</td></tr>
                </table>
            </div>
            
            <div style="background: white; padding: 25px; border-radius: 15px; box-shadow: 0 5px 15px rgba(0,0,0,0.1);">
                <h3 style="color: #2c3e50; margin-top: 0;">⚙️ SYSTEM INFO</h3>
                <table style="width: 100%; border-collapse: collapse;">
                    <tr><td style="padding: 8px 0; color: #495057;">Version:</td><td style="padding: 8px 0; color: #2c3e50; font-weight: 600;">{model_metadata['version']}</td></tr>
                    <tr><td style="padding: 8px 0; color: #495057;">Parameters:</td><td style="padding: 8px 0; color: #2c3e50; font-weight: 600;">{model_metadata['parameters']}</td></tr>
                    <tr><td style="padding: 8px 0; color: #495057;">Last Trained:</td><td style="padding: 8px 0; color: #2c3e50; font-weight: 600;">{model_metadata.get('last_trained', 'N/A')}</td></tr>
                    <tr><td style="padding: 8px 0; color: #495057;">Status:</td><td style="padding: 8px 0; color: #2c3e50; font-weight: 600;">{model_metadata['status']}</td></tr>
                </table>
            </div>
        </div>
        
        <div style="background: white; padding: 25px; border-radius: 15px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); margin-bottom: 30px;">
            <h3 style="color: #2c3e50; margin-top: 0;">📋 RECENT SYSTEM LOGS</h3>
            <div style="max-height: 300px; overflow-y: auto; background: #f8f9fa; padding: 15px; border-radius: 10px; font-family: monospace; font-size: 0.9em;">
        """
        
        for log in recent_logs[-10:]:
            dashboard_html += f"<div style='margin-bottom: 5px; padding: 5px; border-bottom: 1px solid #e9ecef;'>{log.strip()}</div>"
        
        dashboard_html += """
            </div>
        </div>
        
        <div style="background: linear-gradient(135deg, #27ae60, #2ecc71); color: white; padding: 20px; border-radius: 15px; text-align: center;">
            <p style="margin: 0; font-size: 1.1em;">System is operational and ready for analysis</p>
        </div>
        """
        
        return dashboard_html
        
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        return f"<div style='color: #e74c3c; padding: 20px; background: #fff5f5; border-radius: 10px;'>Error loading dashboard: {str(e)}</div>"

# =============================================
# 19. INITIALIZE GLOBAL VARIABLES
# =============================================

# Global variables that will be initialized
model = None
accuracy = 0.0
metrics = {}

# =============================================
# 20. PROFESSIONAL INTERFACE DESIGN WITH AUTH
# =============================================

def create_secure_interface():
    """Create complete professional interface with authentication"""
    
    complete_css = """
    /* Your original CSS here - kept exactly the same */
    * {
        box-sizing: border-box;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }

    /* Enhanced upload area with original lung emoji */
    #medical-upload {
        border: 3px dashed #3498db !important;
        border-radius: 15px !important;
        background: linear-gradient(135deg, #f8f9fa, #e3f2fd) !important;
        transition: all 0.3s ease !important;
        min-height: 450px !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        position: relative !important;
        overflow: hidden !important;
        box-shadow: 0 8px 25px rgba(52, 152, 219, 0.15) !important;
        cursor: pointer !important;
    }

    #medical-upload::before {
        content: '🫁 DRAG & DROP CT SCAN HERE';
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        color: #2c3e50;
        font-size: 1.3em;
        font-weight: 700;
        z-index: 1;
        text-align: center;
        width: 100%;
        padding: 25px;
        opacity: 0.8;
        text-shadow: 2px 2px 4px rgba(255,255,255,0.9);
        letter-spacing: 0.5px;
        transition: all 0.3s ease;
    }

    #medical-upload:hover {
        border-color: #2980b9 !important;
        background: linear-gradient(135deg, #e3f2fd, #bbdefb) !important;
        transform: translateY(-5px) !important;
        box-shadow: 0 15px 35px rgba(52, 152, 219, 0.25) !important;
    }

    #medical-upload:hover::before {
        opacity: 1;
        transform: translate(-50%, -50%) scale(1.02);
    }

    #medical-upload img {
        position: relative !important;
        z-index: 2 !important;
        border-radius: 12px !important;
        max-height: 100% !important;
        max-width: 100% !important;
        object-fit: contain !important;
    }

    /* Enhanced analyze button */
    #analyze-button {
        background: linear-gradient(135deg, #27ae60, #2ecc71, #27ae60) !important;
        background-size: 200% 100% !important;
        border: none !important;
        font-weight: 800 !important;
        padding: 25px 50px !important;
        font-size: 1.3em !important;
        border-radius: 15px !important;
        color: #ffffff !important;
        width: 100% !important;
        margin-top: 25px !important;
        letter-spacing: 1.5px !important;
        transition: all 0.4s ease !important;
        box-shadow: 0 10px 30px rgba(46, 204, 113, 0.4) !important;
        text-transform: uppercase !important;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.3) !important;
        position: relative !important;
        overflow: hidden !important;
    }

    #analyze-button::before {
        content: '';
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 100%;
        background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
        transition: 0.5s;
    }

    #analyze-button:hover {
        transform: translateY(-5px) scale(1.02) !important;
        box-shadow: 0 20px 40px rgba(46, 204, 113, 0.6) !important;
        letter-spacing: 2px !important;
        background-position: 100% 0 !important;
    }

    #analyze-button:active {
        transform: translateY(-2px) scale(0.98) !important;
    }

    /* Enhanced results panel with better text visibility */
    #results-panel {
        min-height: 700px !important;
        background: linear-gradient(135deg, #ffffff, #f8fafc) !important;
        padding: 40px !important;
        border-radius: 20px !important;
        box-shadow: 0 15px 40px rgba(0,0,0,0.12) !important;
        border: 1px solid #e0e6ff !important;
        font-size: 16px !important;
        line-height: 1.8 !important;
        color: #2c3e50 !important;
        overflow-y: auto !important;
        max-height: 900px !important;
        position: relative !important;
    }

    #results-panel h1, #results-panel h2, #results-panel h3, #results-panel h4 {
        color: #2c3e50 !important;
        margin-bottom: 1em !important;
        font-weight: 600 !important;
        line-height: 1.3 !important;
    }

    #results-panel h1 {
        font-size: 2.2em !important;
        font-weight: 800 !important;
        background: linear-gradient(135deg, #1a2980, #26d0ce) !important;
        -webkit-background-clip: text !important;
        -webkit-text-fill-color: transparent !important;
        background-clip: text !important;
        margin-bottom: 1.5em !important;
        border-bottom: 3px solid #e0e6ff !important;
        padding-bottom: 15px !important;
    }

    #results-panel h2 {
        font-size: 1.8em !important;
        border-left: 5px solid #3498db !important;
        padding-left: 15px !important;
        margin-top: 2em !important;
        margin-bottom: 1em !important;
    }

    #results-panel h3 {
        font-size: 1.4em !important;
        color: #2c3e50 !important;
        margin-top: 1.5em !important;
        margin-bottom: 0.8em !important;
    }

    #results-panel p, #results-panel li, #results-panel span, #results-panel div {
        color: #2c3e50 !important;
        line-height: 1.8 !important;
        margin-bottom: 1em !important;
        font-size: 16px !important;
    }

    #results-panel strong, #results-panel b {
        color: #1a2980 !important;
        font-weight: 700 !important;
    }

    #results-panel em, #results-panel i {
        color: #7f8c8d !important;
        font-style: italic !important;
    }

    #results-panel ul, #results-panel ol {
        margin-left: 20px !important;
        margin-bottom: 1.5em !important;
    }

    #results-panel li {
        margin-bottom: 0.8em !important;
    }

    #results-panel code, #results-panel pre {
        background: #f8f9fa !important;
        border: 1px solid #dee2e6 !important;
        border-radius: 8px !important;
        padding: 12px 15px !important;
        font-family: 'Cascadia Code', 'Courier New', monospace !important;
        font-size: 0.95em !important;
        overflow-x: auto !important;
        color: #2c3e50 !important;
        margin: 15px 0 !important;
        box-shadow: inset 0 2px 5px rgba(0,0,0,0.05) !important;
    }

    #results-panel table {
        width: 100% !important;
        border-collapse: collapse !important;
        margin: 25px 0 !important;
        background: white !important;
        border-radius: 12px !important;
        overflow: hidden !important;
        box-shadow: 0 3px 15px rgba(0,0,0,0.08) !important;
        border: 1px solid #e9ecef !important;
    }

    #results-panel th {
        background: linear-gradient(135deg, #1a2980, #26d0ce) !important;
        color: white !important;
        padding: 18px 20px !important;
        text-align: left !important;
        font-weight: 600 !important;
        font-size: 1.05em !important;
        border-bottom: 2px solid rgba(255,255,255,0.2) !important;
    }

    #results-panel td {
        padding: 16px 20px !important;
        border-bottom: 1px solid #e9ecef !important;
        font-size: 1.em !important;
        color: #2c3e50 !important;
    }

    #results-panel tr:hover {
        background: #f8f9fa !important;
    }

    #results-panel tr:last-child td {
        border-bottom: none !important;
    }

    #results-panel::-webkit-scrollbar {
        width: 12px;
    }

    #results-panel::-webkit-scrollbar-track {
        background: #f1f1f1;
        border-radius: 10px;
    }

    #results-panel::-webkit-scrollbar-thumb {
        background: linear-gradient(135deg, #1a2980, #26d0ce);
        border-radius: 10px;
        border: 3px solid #f1f1f1;
    }

    #results-panel::-webkit-scrollbar-thumb:hover {
        background: linear-gradient(135deg, #162471, #20b4b2);
    }

    /* Main container */
    .gradio-container {
        max-width: 1700px !important;
        margin: 30px auto !important;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
        background: linear-gradient(135deg, #f8fafc 0%, #e3f2fd 30%, #f0f4ff 100%) !important;
        padding: 40px !important;
        border-radius: 25px !important;
        font-size: 16px !important;
        color: #2c3e50 !important;
        box-shadow: 0 25px 70px rgba(0,0,0,0.15) !important;
        border: 1px solid rgba(255,255,255,0.2) !important;
    }

    /* Typography */
    h1, h2, h3, h4 {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
        font-weight: 600 !important;
        line-height: 1.3 !important;
        color: #2c3e50 !important;
        margin-bottom: 1em !important;
    }

    h1 {
        font-size: 2.8em !important;
        font-weight: 800 !important;
        background: linear-gradient(135deg, #1a2980, #26d0ce) !important;
        -webkit-background-clip: text !important;
        -webkit-text-fill-color: transparent !important;
        background-clip: text !important;
    }

    h2 {
        font-size: 2em !important;
        border-bottom: 3px solid #3498db !important;
        padding-bottom: 10px !important;
        margin-bottom: 25px !important;
    }

    h3 {
        font-size: 1.5em !important;
        color: #2c3e50 !important;
    }

    /* Text styling */
    p, li, span, div {
        overflow-wrap: break-word !important;
        word-wrap: break-word !important;
        hyphens: auto !important;
        color: #2c3e50 !important;
        line-height: 1.6 !important;
    }

    /* Code blocks */
    pre, code {
        background: #f8f9fa !important;
        border: 2px solid #dee2e6 !important;
        border-radius: 10px !important;
        padding: 15px !important;
        font-family: 'Cascadia Code', 'Courier New', monospace !important;
        font-size: 0.95em !important;
        overflow-x: auto !important;
        white-space: pre-wrap !important;
        word-wrap: break-word !important;
        color: #2c3e50 !important;
        box-shadow: inset 0 2px 10px rgba(0,0,0,0.05) !important;
    }

    /* Tables */
    table {
        width: 100% !important;
        border-collapse: collapse !important;
        margin: 20px 0 !important;
        background: white !important;
        border-radius: 10px !important;
        overflow: hidden !important;
        box-shadow: 0 3px 15px rgba(0,0,0,0.08) !important;
    }

    th {
        background: linear-gradient(135deg, #1a2980, #26d0ce) !important;
        color: white !important;
        padding: 15px !important;
        text-align: left !important;
        font-weight: 600 !important;
    }

    td {
        padding: 12px 15px !important;
        border-bottom: 1px solid #e9ecef !important;
    }

    tr:hover {
        background: #f8f9fa !important;
    }

    /* Mobile responsiveness */
    @media (max-width: 768px) {
        .gradio-container {
            padding: 15px 10px !important;
            margin: 10px auto !important;
            border-radius: 15px !important;
            font-size: 14px !important;
        }

        h1 {
            font-size: 1.8em !important;
            line-height: 1.2 !important;
            margin-bottom: 15px !important;
        }

        h2 {
            font-size: 1.4em !important;
            margin-bottom: 15px !important;
        }

        h3 {
            font-size: 1.2em !important;
        }

        /* Upload area for mobile */
        #medical-upload {
            min-height: 300px !important;
            margin-bottom: 15px !important;
            border-width: 2px !important;
        }

        #medical-upload::before {
            font-size: 1em !important;
            padding: 15px !important;
            letter-spacing: 0.3px !important;
        }

        /* Button adjustments for mobile */
        #analyze-button {
            padding: 20px 15px !important;
            font-size: 1.1em !important;
            margin-top: 15px !important;
            min-height: 70px !important;
            letter-spacing: 1px !important;
            border-radius: 12px !important;
        }

        /* Layout adjustments for mobile */
        .gradio-row {
            flex-direction: column !important;
            gap: 20px !important;
        }

        .gradio-column {
            width: 100% !important;
            margin-bottom: 20px !important;
            padding: 0 !important;
        }

        /* Results panel for mobile */
        #results-panel {
            min-height: auto !important;
            padding: 20px 15px !important;
            font-size: 0.95em !important;
            max-height: none !important;
            border-radius: 15px !important;
        }

        /* Table adjustments for mobile */
        table {
            font-size: 0.85em !important;
        }

        th, td {
            padding: 8px 10px !important;
        }
    }

    /* Tablet devices (768px to 1024px) */
    @media (min-width: 769px) and (max-width: 1024px) {
        .gradio-container {
            max-width: 95% !important;
            padding: 25px !important;
            font-size: 15px !important;
        }

        #medical-upload {
            min-height: 400px !important;
        }

        #analyze-button {
            padding: 22px 35px !important;
            font-size: 1.2em !important;
        }
    }

    /* Animations */
    @keyframes float {
        0% { transform: translateY(0px) rotate(0deg); }
        50% { transform: translateY(-15px) rotate(2deg); }
        100% { transform: translateY(0px) rotate(0deg); }
    }

    @keyframes gradient-shift {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }

    /* Ensure all text in dark sections is white */
    div[style*="background: linear-gradient(135deg, #1a2980, #26d0ce)"] *,
    div[style*="background: linear-gradient(135deg, #667eea, #764ba2)"] *,
    div[style*="background: linear-gradient(135deg, #FF6B6B, #FF8E53, #FFD166)"] * {
        color: #ffffff !important;
        text-shadow: 1px 1px 2px rgba(0,0,0,0.3) !important;
    }

    /* Buttons in footer with black text */
    div[style*="background: linear-gradient(135deg, #FF6B6B, #FF8E53, #FFD166)"] div[style*="background: rgba(255, 255, 255, 0.25)"] p {
        color: #000000 !important;
        font-weight: 700 !important;
        text-shadow: none !important;
    }

    /* Loading states */
    .gradio-button[disabled] {
        opacity: 0.7 !important;
        cursor: not-allowed !important;
    }

    /* Markdown improvements */
    .markdown-text {
        font-size: 1em !important;
        line-height: 1.7 !important;
    }

    .markdown-text strong {
        color: #2c3e50 !important;
        font-weight: 600 !important;
    }

    .markdown-text em {
        color: #7f8c8d !important;
        font-style: italic !important;
    }

    /* Ensure good contrast */
    * {
        -webkit-text-size-adjust: 100% !important;
        text-size-adjust: 100% !important;
    }

    body {
        text-rendering: optimizeLegibility !important;
        -webkit-font-smoothing: antialiased !important;
        -moz-osx-font-smoothing: grayscale !important;
    }

    /* Accordion styling */
    .gradio-accordion {
        margin: 30px 0 !important;
        border: 2px solid #e9ecef !important;
        border-radius: 15px !important;
        overflow: hidden !important;
    }

    .gradio-accordion > div:first-child {
        background: linear-gradient(135deg, #f8f9fa, #e9ecef) !important;
        padding: 20px !important;
        font-weight: 600 !important;
        font-size: 1.1em !important;
        color: #2c3e50 !important;
        cursor: pointer !important;
        transition: all 0.3s ease !important;
    }

    .gradio-accordion > div:first-child:hover {
        background: linear-gradient(135deg, #e9ecef, #dee2e6) !important;
    }
    
    /* Batch upload styling */
    .batch-upload {
        border: 3px dashed #9b59b6 !important;
        background: linear-gradient(135deg, #f9f0ff, #e6d4ff) !important;
    }
    
    .batch-upload::before {
        content: '📁 DRAG & DROP MULTIPLE CT SCANS HERE' !important;
        color: #8e44ad !important;
    }
    
    /* Admin panel styling */
    .admin-panel {
        background: linear-gradient(135deg, #2c3e50, #34495e) !important;
        color: white !important;
        border: 2px solid #3498db !important;
    }
    
    /* Password show/hide toggle */
    .password-toggle {
        cursor: pointer;
        color: #3498db;
        font-size: 0.9em;
        margin-left: 10px;
    }
    
    .password-toggle:hover {
        color: #2980b9;
        text-decoration: underline;
    }
    
    /* Password visibility toggle styling */
    .password-wrapper {
        position: relative;
        width: 100%;
    }
    
    .password-wrapper input {
        width: 100%;
        padding-right: 40px !important;
    }
    
    .password-toggle-btn {
        position: absolute;
        right: 10px;
        top: 50%;
        transform: translateY(-50%);
        background: none;
        border: none;
        cursor: pointer;
        color: #3498db;
        font-size: 1.2em;
        padding: 5px;
    }
    
    .password-toggle-btn:hover {
        color: #2980b9;
    }
    """

    with gr.Blocks(title="Secure Lung Nodule Analyzer - Academic Research v4.1",
                   theme=gr.themes.Soft(primary_hue="blue", secondary_hue="green"),
                   css=complete_css) as demo:

        # Store session state
        is_logged_in = gr.State(False)
        current_user = gr.State("")
        current_role = gr.State("")
        
        # Tab state for controlling which tab is active
        active_tab = gr.State("analysis")

        # HEADER WITH ORIGINAL DESIGN
        gr.HTML("""
        <div style="
            background: linear-gradient(135deg, #1a2980, #26d0ce);
            padding: 40px 30px;
            border-radius: 20px;
            color: white;
            text-align: center;
            margin-bottom: 30px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.3);
            border: 1px solid rgba(255,255,255,0.1);
            position: relative;
            overflow: hidden;
        ">
            <div style="position: absolute; top: -50px; right: -50px; width: 200px; height: 200px;
                        background: rgba(255,255,255,0.05); border-radius: 50%;"></div>
            <div style="position: absolute; bottom: -80px; left: -80px; width: 250px; height: 250px;
                        background: rgba(255,255,255,0.03); border-radius: 50%;"></div>

            <div style="display: flex; align-items: center; justify-content: center; gap: 25px; margin-bottom: 20px; position: relative; z-index: 2;">
                <div style="font-size: 4em; animation: pulse 2s infinite;">🫁</div>
                <div>
                    <h1 style="margin: 0; font-size: 3em; font-weight: 800; letter-spacing: -1px; text-shadow: 2px 2px 4px rgba(0,0,0,0.3);">
                    ADVANCED LUNG NODULE ANALYZER
                    </h1>
                    <h2 style="margin: 15px 0 0 0; font-weight: 300; font-size: 1.3em; opacity: 0.9;">
                    Enhanced Security Edition | Dynamic Pattern Recognition System v4.1
                    </h2>
                </div>
            </div>

            <div style="
                background: rgba(255,255,255,0.15);
                padding: 15px 30px;
                border-radius: 50px;
                display: inline-block;
                margin-top: 20px;
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255,255,255,0.2);
                position: relative;
                z-index: 2;
            ">
                <p style="margin: 0; font-size: 1.em; font-weight: 500;">
                Academic Research Project | Kelvin Njagi Njoki | B144/24928/2022 | University of Embu
                </p>
            </div>

            <div style="margin-top: 25px; position: relative; z-index: 2;">
                <div id="user-status" style="
                    background: rgba(0,0,0,0.2);
                    padding: 12px 25px;
                    border-radius: 25px;
                    display: inline-block;
                    backdrop-filter: blur(5px);
                    border: 1px solid rgba(255,255,255,0.3);
                ">
                    <p style="margin: 0; font-size: 1.1em; font-weight: 600; color: #fff;">
                    Status: <span style="color: #ff6b6b;">Please Login to Access Analysis</span>
                    </p>
                </div>
            </div>
        </div>

        <style>
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
        </style>
        """)

        # STATUS PANEL WITH ORIGINAL PURPLE GRADIENT (ONLY SHOWN WHEN LOGGED IN)
        status_row = gr.Row(visible=False)
        with status_row:
            with gr.Column():
                status_html = gr.HTML("")

        # LOGIN MODAL
        with gr.Row(visible=True) as login_row:
            with gr.Column(scale=1):
                gr.Markdown("### 🔐 SECURE SYSTEM LOGIN")

                with gr.Group():
                    login_username = gr.Textbox(
                        label="Username",
                        placeholder="Enter your username",
                        max_lines=1,
                        value="demo"
                    )
                    
                    # Password with visibility toggle
                    with gr.Row():
                        login_password = gr.Textbox(
                            label="Password",
                            placeholder="Enter your password",
                            type="password",
                            max_lines=1,
                            value="Demo@123"
                        )
                        login_password_show = gr.Checkbox(label="👁️", value=False, scale=0, min_width=60)

                login_btn = gr.Button("🔑 Secure Login", variant="primary", size="lg")
                login_message = gr.Markdown("""
                **Demo Credentials:**
                - Username: `demo` | Password: `Demo@123`
                - Username: `admin` | Password: `Admin@Secure123!`
                
                ⚠️ **Security Notice:** Accounts are locked after 5 failed attempts.
                """)
                
                # Password Recovery Section
                with gr.Accordion("🔓 Forgot Password?", open=False):
                    gr.Markdown("### Password Recovery")
                    
                    with gr.Row():
                        recovery_username = gr.Textbox(
                            label="Username",
                            placeholder="Enter your username",
                            max_lines=1
                        )
                    
                    get_question_btn = gr.Button("Get Security Question", variant="secondary", size="sm")
                    security_question_display = gr.Markdown("")
                    
                    with gr.Row():
                        security_answer = gr.Textbox(
                            label="Security Answer",
                            placeholder="Answer your security question",
                            max_lines=1
                        )
                    
                    with gr.Row():
                        new_password = gr.Textbox(
                            label="New Password",
                            placeholder="Enter new password (min 8 chars)",
                            type="password",
                            max_lines=1
                        )
                        show_password = gr.Checkbox(
                            label="Show Password",
                            value=False
                        )
                    
                    recover_btn = gr.Button("Reset Password", variant="primary", size="sm")
                    recovery_message = gr.Markdown("")

        # MAIN WORKFLOW AREA (HIDDEN UNTIL LOGGED IN)
        with gr.Row(visible=False) as main_row:
            # LEFT PANEL - UPLOAD AND CONTROLS
            with gr.Column(scale=1):
                gr.Markdown("### 📤 UPLOAD CT SCAN IMAGE")
                
                # Tabs for single vs batch upload
                with gr.Tabs() as upload_tabs:
                    with gr.TabItem("Single Image"):
                        image_input = gr.Image(
                            label="",
                            type="numpy",
                            height=400,
                            elem_id="medical-upload",
                            image_mode="RGB",
                            show_label=False,
                            interactive=True
                        )
                    
                    with gr.TabItem("Batch Upload (Admin)", visible=False) as batch_upload_tab:
                        with gr.Accordion("📁 Batch Upload Multiple Images", open=False):
                            batch_image_input = gr.File(
                                label="Select multiple CT scan images",
                                file_count="multiple",
                                file_types=["image"],
                                elem_classes="batch-upload"
                            )
                            batch_analyze_btn = gr.Button(
                                "📊 Analyze Batch",
                                variant="secondary",
                                size="lg"
                            )
                            batch_results = gr.HTML("")

                # Upload guidelines
                gr.HTML("""
                <div style="
                    background: linear-gradient(135deg, #f8f9fa, #e9ecef);
                    padding: 25px;
                    border-radius: 15px;
                    margin: 25px 0;
                    border: 3px dashed #3498db;
                    transition: all 0.3s ease;
                    box-shadow: 0 5px 15px rgba(52, 152, 219, 0.1);
                ">
                    <div style="display: flex; align-items: center; gap: 20px; margin-bottom: 20px;">
                        <div style="
                            width: 60px;
                            height: 60px;
                            background: linear-gradient(135deg, #3498db, #2980b9);
                            border-radius: 50%;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                            font-size: 1.8em;
                        ">📋</div>
                        <div>
                            <strong style="font-size: 1.2em; color: #2c3e50; display: block; margin-bottom: 8px;">
                            UPLOAD GUIDELINES
                            </strong>
                            <p style="margin: 0; color: #495057; font-size: 0.95em;">
                            For optimal analysis and accurate results
                            </p>
                        </div>
                    </div>

                    <div style="
                        background: white;
                        padding: 20px;
                        border-radius: 10px;
                        box-shadow: 0 3px 10px rgba(0,0,0,0.05);
                    ">
                        <div style="display: grid; grid-template-columns: 1fr; gap: 12px;">
                            <div style="display: flex; align-items: center; gap: 10px;">
                                <div style="color: #3498db; font-size: 1.2em;">✅</div>
                                <div>
                                    <p style="margin: 0; color: #2c3e50; font-weight: 600;">Optimal Formats</p>
                                    <p style="margin: 5px 0 0 0; color: #7f8c8d; font-size: 0.9em;">JPEG, PNG, DICOM (converted)</p>
                                </div>
                            </div>

                            <div style="display: flex; align-items: center; gap: 10px;">
                                <div style="color: #27ae60; font-size: 1.2em;">📏</div>
                                <div>
                                    <p style="margin: 0; color: #2c3e50; font-weight: 600;">Image Size</p>
                                    <p style="margin: 5px 0 0 0; color: #7f8c8d; font-size: 0.9em;">512×512 to 1024×1024 pixels</p>
                                </div>
                            </div>

                            <div style="display: flex; align-items: center; gap: 10px;">
                                <div style="color: #9b59b6; font-size: 1.2em;">⚙️</div>
                                <div>
                                    <p style="margin: 0; color: #2c3e50; font-weight: 600;">Window Settings</p>
                                    <p style="margin: 5px 0 0 0; color: #7f8c8d; font-size: 0.9em;">Lung window preferred</p>
                                </div>
                            </div>

                            <div style="display: flex; align-items: center; gap: 10px;">
                                <div style="color: #e74c3c; font-size: 1.2em;">💾</div>
                                <div>
                                    <p style="margin: 0; color: #2c3e50; font-weight: 600;">File Size</p>
                                    <p style="margin: 5px 0 0 0; color: #7f8c8d; font-size: 0.9em;">Maximum 10MB per image</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                """)

                # Action buttons
                analyze_btn = gr.Button(
                    "🚀 START ADVANCED ANALYSIS",
                    variant="primary",
                    size="lg",
                    elem_id="analyze-button",
                    scale=1
                )
                
                with gr.Row():
                    export_btn = gr.Button("📥 Export Report", variant="secondary", size="lg")
                    clear_btn = gr.Button("🗑️ Clear", variant="secondary", size="lg")
                
                # Export status
                export_status = gr.HTML("")

                # Analysis tips
                gr.HTML("""
                <div style="
                    background: linear-gradient(135deg, #fff8e1, #ffecb3);
                    padding: 20px;
                    border-radius: 12px;
                    margin-top: 20px;
                    border-left: 5px solid #ff9800;
                    box-shadow: 0 3px 10px rgba(255, 152, 0, 0.1);
                ">
                    <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 15px;">
                        <div style="font-size: 1.5em;">💡</div>
                        <div>
                            <strong style="font-size: 1.1em; color: #e65100;">ANALYSIS TIPS</strong>
                        </div>
                    </div>
                    <ul style="margin: 0; padding-left: 20px; color: #5d4037; font-size: 0.95em; line-height: 1.6;">
                        <li>Center the nodule in the image for best results</li>
                        <li>Use lung window settings for optimal contrast</li>
                        <li>Avoid motion artifacts and breathing blur</li>
                        <li>Include surrounding lung tissue for context</li>
                        <li>System validates image quality automatically</li>
                    </ul>
                </div>
                """)

            # RIGHT PANEL - RESULTS AND DASHBOARD
            with gr.Column(scale=1.5):
                # Tabs for different views
                with gr.Tabs(selected="analysis") as results_tabs:
                    with gr.TabItem("📊 Analysis Results", id="analysis"):
                        # Initial results placeholder
                        initial_results = gr.HTML("""
                        <div style="
                            background: linear-gradient(135deg, #ffffff, #f8fafc);
                            padding: 40px;
                            border-radius: 20px;
                            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
                            min-height: 650px;
                            border: 1px solid #e0e6ff;
                            display: flex;
                            flex-direction: column;
                            justify-content: center;
                            align-items: center;
                            text-align: center;
                            position: relative;
                            overflow: hidden;
                        ">
                            <div style="position: absolute; top: -100px; right: -100px; width: 300px; height: 300px;
                                        background: linear-gradient(135deg, rgba(26, 41, 128, 0.05), rgba(38, 208, 206, 0.05));
                                        border-radius: 50%;"></div>
                            <div style="position: absolute; bottom: -80px; left: -80px; width: 250px; height: 250px;
                                        background: linear-gradient(135deg, rgba(102, 126, 234, 0.05), rgba(118, 75, 162, 0.05));
                                        border-radius: 50%;"></div>

                            <div style="
                                width: 150px;
                                height: 150px;
                                background: linear-gradient(135deg, #1a2980, #26d0ce);
                                border-radius: 50%;
                                display: flex;
                                align-items: center;
                                justify-content: center;
                                margin-bottom: 30px;
                                box-shadow: 0 15px 35px rgba(26, 41, 128, 0.3);
                                position: relative;
                                z-index: 2;
                                animation: float 3s ease-in-out infinite;
                            ">
                                <div style="font-size: 4em; color: white;">🫁</div>
                            </div>

                            <h2 style="color: #2c3e50; margin-bottom: 20px; font-size: 2.2em; font-weight: 700; position: relative; z-index: 2;">
                                Advanced Lung Nodule Analysis
                            </h2>

                            <p style="color: #495057; line-height: 1.7; margin-bottom: 40px; max-width: 700px;
                                    font-size: 1.1em; position: relative; z-index: 2;">
                                Upload a CT scan image to begin comprehensive pattern recognition analysis.
                                Our enhanced system combines deep learning with medical pattern analysis to provide
                                detailed risk assessment and clinical recommendations for academic research.
                            </p>

                            <div style="
                                display: grid;
                                grid-template-columns: repeat(3, 1fr);
                                gap: 25px;
                                width: 100%;
                                max-width: 900px;
                                margin: 40px 0;
                                position: relative;
                                z-index: 2;
                            ">
                                <div style="
                                    background: linear-gradient(135deg, #e8f4fc, #d1e7ff);
                                    padding: 25px;
                                    border-radius: 15px;
                                    text-align: center;
                                    border: 3px solid #3498db;
                                    transition: all 0.3s ease;
                                    box-shadow: 0 5px 15px rgba(52, 152, 219, 0.1);
                                ">
                                    <div style="
                                        width: 70px;
                                        height: 70px;
                                        background: linear-gradient(135deg, #3498db, #2980b9);
                                        border-radius: 50%;
                                        display: flex;
                                        align-items: center;
                                        justify-content: center;
                                        margin: 0 auto 20px auto;
                                        font-size: 2em;
                                        color: white;
                                    ">🤖</div>
                                    <h3 style="margin: 0 0 15px 0; color: #2c3e50; font-size: 1.2em; font-weight: 700;">ENHANCED AI</h3>
                                    <ul style="margin: 0; padding-left: 20px; color: #495057; font-size: 0.95em; line-height: 1.6; text-align: left;">
                                        <li>CNN architecture v4.1</li>
                                        <li>Pattern recognition</li>
                                        <li>Quality validation</li>
                                    </ul>
                                </div>

                                <div style="
                                    background: linear-gradient(135deg, #f0f8f0, #d4f1d4);
                                    padding: 25px;
                                    border-radius: 15px;
                                    text-align: center;
                                    border: 3px solid #27ae60;
                                    transition: all 0.3s ease;
                                    box-shadow: 0 5px 15px rgba(39, 174, 96, 0.1);
                                ">
                                    <div style="
                                        width: 70px;
                                        height: 70px;
                                        background: linear-gradient(135deg, #27ae60, #229954);
                                        border-radius: 50%;
                                        display: flex;
                                        align-items: center;
                                        justify-content: center;
                                        margin: 0 auto 20px auto;
                                        font-size: 2em;
                                        color: white;
                                    ">⚕️</div>
                                    <h3 style="margin: 0 0 15px 0; color: #2c3e50; font-size: 1.2em; font-weight: 700;">MEDICAL ANALYSIS</h3>
                                    <ul style="margin: 0; padding-left: 20px; color: #495057; font-size: 0.95em; line-height: 1.6; text-align: left;">
                                        <li>Edge detection</li>
                                        <li>Pattern classification</li>
                                        <li>Risk stratification</li>
                                    </ul>
                                </div>

                                <div style="
                                    background: linear-gradient(135deg, #f9f0ff, #e6d4ff);
                                    padding: 25px;
                                    border-radius: 15px;
                                    text-align: center;
                                    border: 3px solid #9b59b6;
                                    transition: all 0.3s ease;
                                    box-shadow: 0 5px 15px rgba(155, 89, 182, 0.1);
                                ">
                                    <div style="
                                        width: 70px;
                                        height: 70px;
                                        background: linear-gradient(135deg, #9b59b6, #8e44ad);
                                        border-radius: 50%;
                                        display: flex;
                                        align-items: center;
                                        justify-content: center;
                                        margin: 0 auto 20px auto;
                                        font-size: 2em;
                                        color: white;
                                    ">📊</div>
                                    <h3 style="margin: 0 0 15px 0; color: #2c3e50; font-size: 1.2em; font-weight: 700;">COMPREHENSIVE REPORT</h3>
                                    <ul style="margin: 0; padding-left: 20px; color: #495057; font-size: 0.95em; line-height: 1.6; text-align: left;">
                                        <li>Detailed metrics</li>
                                        <li>Clinical recommendations</li>
                                        <li>Export functionality</li>
                                    </ul>
                                </div>
                            </div>

                            <div style="
                                background: linear-gradient(135deg, rgba(26, 41, 128, 0.05), rgba(38, 208, 206, 0.05));
                                padding: 20px 30px;
                                border-radius: 12px;
                                margin-top: 30px;
                                border: 2px solid rgba(52, 152, 219, 0.2);
                                text-align: left;
                                width: 100%;
                                max-width: 900px;
                                position: relative;
                                z-index: 2;
                                backdrop-filter: blur(5px);
                            ">
                                <p style="margin: 0; color: #2d3436; font-size: 1em; font-weight: 600; display: flex; align-items: center; gap: 10px;">
                                    <span style="font-size: 1.3em;">🔬</span>
                                    <span>Active System: Enhanced Pattern Recognition v4.1</span>
                                </p>
                                <p style="margin: 10px 0 0 0; color: #636e72; font-size: 0.95em;">
                                    Each analysis generates unique results based on comprehensive image characteristics and medical pattern recognition.
                                </p>
                            </div>
                        </div>
                        """)

                        output_display = gr.Markdown(
                            "",
                            elem_id="results-panel"
                        )
                    
                    # FIXED: Dashboard tab should be properly connected
                    with gr.TabItem("📈 System Dashboard", id="dashboard", visible=False) as dashboard_tab:
                        dashboard_display = gr.HTML("")
                        refresh_dashboard_btn = gr.Button("🔄 Refresh Dashboard", variant="secondary")
                    
                    # FIXED: User Management tab should be properly connected
                    with gr.TabItem("👑 User Management", id="users", visible=False) as user_management_tab:
                        user_management_display = gr.HTML("")
                        refresh_users_btn = gr.Button("🔄 Refresh User List", variant="secondary")
                        
                        # User Creation Form
                        with gr.Accordion("➕ Create New User", open=False):
                            gr.Markdown("### Create New User Account")
                            
                            with gr.Row():
                                new_user_username = gr.Textbox(
                                    label="Username",
                                    placeholder="Enter unique username",
                                    max_lines=1
                                )
                                new_user_password = gr.Textbox(
                                    label="Password",
                                    placeholder="Enter password (min 8 chars)",
                                    type="password",
                                    max_lines=1
                                )
                                new_user_password_show = gr.Checkbox(label="👁️", value=False, scale=0, min_width=60)
                            
                            with gr.Row():
                                new_user_full_name = gr.Textbox(
                                    label="Full Name",
                                    placeholder="Enter full name",
                                    max_lines=1
                                )
                                new_user_email = gr.Textbox(
                                    label="Email",
                                    placeholder="Enter email address",
                                    max_lines=1
                                )
                            
                            with gr.Row():
                                new_user_role = gr.Dropdown(
                                    label="Role",
                                    choices=["user", "admin"],
                                    value="user"
                                )
                                new_user_show_password = gr.Checkbox(
                                    label="Show in Confirmation",
                                    value=False
                                )
                            
                            with gr.Row():
                                new_user_security_question = gr.Textbox(
                                    label="Security Question",
                                    placeholder="e.g., What is your favorite color?",
                                    max_lines=1
                                )
                                new_user_security_answer = gr.Textbox(
                                    label="Security Answer",
                                    placeholder="Answer for password recovery",
                                    max_lines=1
                                )
                            
                            create_user_btn = gr.Button("👤 Create User", variant="primary")
                            create_user_message = gr.Markdown("")
                        
                        # User Actions
                        with gr.Accordion("⚙️ User Actions", open=False):
                            gr.Markdown("### Manage Existing Users")
                            
                            with gr.Row():
                                action_username = gr.Textbox(
                                    label="Username",
                                    placeholder="Enter username to manage",
                                    max_lines=1
                                )
                            
                            with gr.Row():
                                approve_user_btn = gr.Button("✅ Approve User", variant="secondary")
                                disable_user_btn = gr.Button("⛔ Disable User", variant="secondary")
                                activate_user_btn = gr.Button("🔄 Activate User", variant="secondary")
                            
                            with gr.Row():
                                reset_pw_btn = gr.Button("🔑 Reset Password", variant="secondary")
                                delete_user_btn = gr.Button("🗑️ Delete User", variant="secondary", elem_id="delete-btn")
                            
                            with gr.Row():
                                new_password_for_reset = gr.Textbox(
                                    label="New Password",
                                    placeholder="Enter new password for reset",
                                    type="password",
                                    max_lines=1,
                                    visible=False
                                )
                                show_reset_password = gr.Checkbox(
                                    label="Show Password",
                                    value=False,
                                    visible=False
                                )
                                reset_password_btn = gr.Button("✅ Confirm Reset", variant="primary", visible=False)
                            
                            user_action_message = gr.Markdown("")

        # USER PANEL (Right side when logged in)
        with gr.Row(visible=False) as user_panel_row:
            with gr.Column(scale=1):
                # User Info Panel
                user_info_panel = gr.HTML("")
                
                # Session info
                session_info = gr.HTML("")
                
                # Admin controls (only visible to admins)
                admin_controls = gr.Column(visible=False)
                with admin_controls:
                    gr.Markdown("### 👑 ADMIN CONTROLS")
                    view_dashboard_btn = gr.Button("📊 View System Dashboard", variant="secondary")
                    view_user_management_btn = gr.Button("👥 User Management", variant="secondary")

                logout_btn = gr.Button("🚪 Logout", variant="secondary", size="lg")

        # TECHNICAL DETAILS ACCORDION
        with gr.Accordion("🔬 TECHNICAL SPECIFICATIONS & SYSTEM ARCHITECTURE", open=False, visible=False) as tech_accordion:
            gr.Markdown("""
            ## Enhanced System Architecture v4.1

            ### 🤖 ENHANCED DEEP LEARNING MODEL
            **Architecture:** Convolutional Neural Network (CNN) with Enhanced Security
            **Input Size:** 128×128×3 RGB channels
            **Parameters:** ~250,000
            **Training Accuracy:** Dynamic Pattern Recognition
            **Precision:** Dynamic Pattern Recognition
            **Recall/Sensitivity:** Dynamic Pattern Recognition
            **F1-Score:** Dynamic Pattern Recognition
            **AUC Score:** Dynamic Pattern Recognition
            **Framework:** TensorFlow 2.x with Keras API

            ### 📊 ENHANCED ANALYSIS PIPELINE
            1. **Image Validation & Preprocessing:**
               - Automatic quality assessment
               - RGB normalization (0-1 scale)
               - Resize to 128×128 pixels
               - Validation for medical imaging standards

            2. **Enhanced Feature Extraction:**
               - Multi-layer convolutional blocks with batch normalization
               - Advanced dropout for regularization
               - Global average pooling with enhanced features
               - Pattern recognition algorithms

            3. **Comprehensive Pattern Recognition:**
               - Edge detection with medical heuristics
               - Texture and density analysis
               - Risk pattern classification
               - Confidence scoring system

            ### 🔒 ENHANCED SECURITY FEATURES
            - **Advanced Authentication:** Bcrypt hashing with salt rounds
            - **Session Management:** 24-hour sessions with activity tracking
            - **Brute Force Protection:** Account lockout after 5 failed attempts
            - **Audit Logging:** Comprehensive activity tracking
            - **User Management:** Admin-only user creation and management
            - **Password Recovery:** Security question-based recovery system
            - **Role-Based Access:** Separate permissions for users and admins

            ### ⚙️ SYSTEM PERFORMANCE
            - **Processing Speed:** < 0.5 seconds per image
            - **Memory Usage:** Optimized for medical imaging workloads
            - **Accuracy:** Dynamic Pattern Recognition
            - **Batch Processing:** Support for multiple image analysis
            - **Export Functionality:** JSON report generation

            ### 🎓 ACADEMIC RESEARCH FOCUS
            1. Demonstrate AI/ML applications in medical imaging
            2. Implement advanced pattern recognition for lung nodule assessment
            3. Develop comprehensive clinical reporting systems with security
            4. Explore ethical AI implementation in healthcare
            5. Contribute to medical AI education and research

            **Research Status:** Active Development - Enhanced Security Edition
            **Last Updated:** 2026-01-29
            **Version:** 4.1-Pro
            """)

        # FOOTER WITH ORIGINAL COLOR SCHEME
        gr.HTML("""
        <div style="
            text-align: center;
            padding: 35px 30px;
            margin-top: 50px;
            background: linear-gradient(135deg, #FF6B6B, #FF8E53, #FFD166);
            color: white;
            border-radius: 20px;
            box-shadow: 0 10px 30px rgba(255, 107, 107, 0.3);
            position: relative;
            overflow: hidden;
        ">
            <div style="position: absolute; top: -50px; left: -50px; width: 200px; height: 200px;
                        background: rgba(255, 255, 255, 0.1); border-radius: 50%;"></div>
            <div style="position: absolute; bottom: -80px; right: -80px; width: 250px; height: 250px;
                        background: rgba(255, 255, 255, 0.08); border-radius: 50%;"></div>

            <h3 style="margin: 0 0 20px 0; color: #ffffff; text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
                       font-size: 1.5em; font-weight: 700; position: relative; z-index: 2;">
            ⚕️ MEDICAL & ETHICAL DISCLAIMER
            </h3>

            <div style="
                background: rgba(255, 255, 255, 0.25);
                padding: 25px;
                border-radius: 15px;
                margin: 20px 0;
                text-align: left;
                border: 2px solid rgba(255, 255, 255, 0.3);
                backdrop-filter: blur(10px);
                position: relative;
                z-index: 2;
            ">
                <div style="
                    background: rgba(255, 255, 255, 0.3);
                    padding: 12px 20px;
                    border-radius: 10px;
                    margin-bottom: 20px;
                    text-align: center;
                    border: 2px solid rgba(255, 255, 255, 0.4);
                ">
                    <p style="margin: 0; font-size: 1.1em; font-weight: 700; color: #000000; letter-spacing: 0.5px;">
                    ⚠️ THIS ENHANCED SYSTEM IS FOR ACADEMIC RESEARCH AND DEMONSTRATION PURPOSES ONLY
                    </p>
                </div>

                <div style="
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 20px;
                    margin: 25px 0;
                ">
                    <div style="
                        background: rgba(255, 255, 255, 0.2);
                        padding: 20px;
                        border-radius: 12px;
                        border-left: 5px solid #FF6B6B;
                    ">
                        <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 15px;">
                            <div style="font-size: 2em;">⚠️</div>
                            <div>
                                <p style="margin: 0; font-size: 1.1em; font-weight: 600; color: #fff;">IMPORTANT LIMITATIONS</p>
                            </div>
                        </div>
                        <ul style="margin: 0; padding-left: 25px; color: #fff; font-size: 0.95em; line-height: 1.6;">
                            <li>Results are simulated for academic demonstration</li>
                            <li>System is NOT validated for clinical use</li>
                            <li>Should NOT replace medical professionals</li>
                            <li>Synthetic training data used</li>
                            <li>Enhanced security for research purposes only</li>
                        </ul>
                    </div>

                    <div style="
                        background: rgba(255, 255, 255, 0.2);
                        padding: 20px;
                        border-radius: 12px;
                        border-left: 5px solid #FFD166;
                    ">
                        <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 15px;">
                            <div style="font-size: 2em;">🎓</div>
                            <div>
                                <p style="margin: 0; font-size: 1.1em; font-weight: 600; color: #fff;">EDUCATIONAL PURPOSE</p>
                            </div>
                        </div>
                        <ul style="margin: 0; padding-left: 25px; color: #fff; font-size: 0.95em; line-height: 1.6;">
                            <li>Advanced machine learning demonstration project</li>
                            <li>Pattern recognition in medical imaging</li>
                            <li>Academic research for thesis work</li>
                            <li>Security implementation demonstration</li>
                            <li>Complies with academic integrity standards</li>
                        </ul>
                    </div>
                </div>

                <div style="
                    background: rgba(0, 0, 0, 0.2);
                    padding: 25px;
                    border-radius: 12px;
                    margin-top: 20px;
                    text-align: center;
                    border: 2px solid rgba(255, 255, 255, 0.2);
                ">
                    <div style="font-size: 3em; margin-bottom: 15px; color: #fff;">🫁</div>
                    <p style="margin: 0 0 15px 0; color: #fff; font-size: 1.1em; font-weight: 600; line-height: 1.6;">
                    Accuracy metrics and predictions are simulated for academic research only.
                    Enhanced security features are for demonstration purposes.
                    </p>
                    <p style="margin: 0; color: rgba(255, 255, 255, 0.9); font-size: 1.em; line-height: 1.6;">
                    <strong>Always consult qualified healthcare professionals for medical decisions.</strong>
                    </p>
                </div>
            </div>

            <div style="
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-top: 30px;
                padding-top: 25px;
                border-top: 2px solid rgba(255, 255, 255, 0.3);
                flex-wrap: wrap;
                position: relative;
                z-index: 2;
            ">
                <div style="text-align: left; flex: 1; min-width: 200px; margin-bottom: 15px;">
                    <div style="display: flex; align-items: center; gap: 15px;">
                        <div style="font-size: 2em;">🎓</div>
                        <div>
                            <p style="margin: 0; font-size: 1em; font-weight: 600; color: #fff;">RESEARCH PROJECT</p>
                            <p style="margin: 8px 0 0 0; font-size: 0.9em; color: rgba(255, 255, 255, 0.9);">
                            Enhanced Lung Nodule Classification using CNN
                            </p>
                        </div>
                    </div>
                </div>

                <div style="text-align: center; flex: 1; min-width: 250px; margin-bottom: 15px;">
                    <div style="
                        background: rgba(255, 255, 255, 0.25);
                        padding: 12px 25px;
                        border-radius: 25px;
                        display: inline-block;
                        backdrop-filter: blur(5px);
                        border: 2px solid rgba(255, 255, 255, 0.3);
                    ">
                        <p style="margin: 5px 0; font-size: 1.1em; color: #000; line-height: 1.4; font-weight: 700;">
                        <strong>👨‍🎓 Kelvin Njagi Njoki</strong><br>
                        <span style="font-size: 0.9em; color: #000;">B144/24928/2022</span>
                        </p>
                    </div>
                </div>

                <div style="text-align: right; flex: 1; min-width: 200px; margin-bottom: 15px;">
                    <div style="display: flex; align-items: center; justify-content: flex-end; gap: 15px;">
                        <div>
                            <p style="margin: 0; font-size: 1em; font-weight: 600; color: #fff;">UNIVERSITY OF EMBU</p>
                            <p style="margin: 8px 0 0 0; font-size: 0.9em; color: rgba(255, 255, 255, 0.9);">
                            © 2026 All Rights Reserved - Enhanced Academic Project v4.1
                            </p>
                        </div>
                        <div style="font-size: 2em;">🏛️</div>
                    </div>
                </div>
            </div>
        </div>
        """)

        # =============================================
        # EVENT HANDLERS - FIXED VERSION
        # =============================================

        def update_session_info():
            """Update session information display"""
            if session_manager.is_authenticated():
                remaining_mins = session_manager.get_session_remaining_time()
                user_info = session_manager.get_user_info()
                
                session_html = f"""
                <div style="
                    background: linear-gradient(135deg, #3498db, #2980b9);
                    padding: 20px;
                    border-radius: 15px;
                    color: white;
                    margin-bottom: 20px;
                    box-shadow: 0 5px 15px rgba(52, 152, 219, 0.3);
                ">
                    <h4 style="margin-top: 0; color: white;">⏱️ SESSION INFO</h4>
                    <p style="margin: 10px 0;">
                    <strong>Session expires in:</strong> {remaining_mins} minutes<br>
                    <strong>Last activity:</strong> {session_manager.last_activity.strftime('%H:%M:%S') if session_manager.last_activity else 'N/A'}<br>
                    <strong>Role:</strong> {user_info.get('role', 'user').upper()}
                    </p>
                </div>
                """
                return session_html
            return ""

        def update_ui_after_login(is_logged_in_state, username, role):
            """Update UI elements based on login state - COMPLETELY FIXED VERSION"""
            if is_logged_in_state:
                user_info = session_manager.get_user_info()
                full_name = user_info.get('full_name', username)
                
                status_html_content = f"""
                <div style="
                    background: linear-gradient(135deg, #667eea, #764ba2);
                    padding: 30px;
                    border-radius: 20px;
                    color: white;
                    box-shadow: 0 10px 30px rgba(102, 126, 234, 0.4);
                    border: 1px solid rgba(255,255,255,0.05);
                    position: relative;
                    overflow: hidden;
                ">
                    <div style="position: absolute; top: 0; right: 0; width: 100px; height: 100px;
                                background: rgba(255,255,255,0.05); border-radius: 0 0 0 100%;"></div>

                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; position: relative; z-index: 2;">
                        <div>
                            <h3 style="margin: 0; font-size: 1.5em; font-weight: 600;">SYSTEM STATUS</h3>
                            <p style="margin: 5px 0 0 0; opacity: 0.9;">Welcome, {full_name}!</p>
                        </div>
                        <span style="
                            background: linear-gradient(135deg, #4CAF50, #2ecc71);
                            padding: 10px 25px;
                            border-radius: 25px;
                            font-size: 1.em;
                            font-weight: 700;
                            box-shadow: 0 5px 20px rgba(76, 175, 80, 0.4);
                            letter-spacing: 0.5px;
                        ">✅ OPERATIONAL</span>
                    </div>

                    <div style="
                        background: rgba(255,255,255,0.08);
                        padding: 20px;
                        border-radius: 15px;
                        margin-top: 20px;
                        border-left: 5px solid #4CAF50;
                        backdrop-filter: blur(5px);
                        position: relative;
                        z-index: 2;
                    ">
                        <p style="margin: 0 0 10px 0; font-size: 1.2em; font-weight: 600;">
                        {model_metadata['name']} v{model_metadata['version']}
                        </p>
                        <p style="margin: 0; font-size: 0.95em; opacity: 0.9;">
                        {model_metadata['parameters']} parameters • Training Accuracy: Dynamic Pattern Recognition
                        </p>

                        <div style="
                            display: grid;
                            grid-template-columns: repeat(3, 1fr);
                            gap: 15px;
                            margin-top: 20px;
                            padding-top: 20px;
                            border-top: 1px solid rgba(255,255,255,0.1);
                        ">
                            <div style="text-align: center;">
                                <div style="font-size: 2em; margin-bottom: 5px;">🤖</div>
                                <p style="margin: 0; font-size: 0.85em; opacity: 0.9;">Enhanced AI</p>
                            </div>
                            <div style="text-align: center;">
                                <div style="font-size: 2em; margin-bottom: 5px;">{'👑' if role == 'admin' else '👤'}</div>
                                <p style="margin: 0; font-size: 0.85em; opacity: 0.9;">{'Administrator' if role == 'admin' else 'User'}</p>
                            </div>
                            <div style="text-align: center;">
                                <div style="font-size: 2em; margin-bottom: 5px;">🔒</div>
                                <p style="margin: 0; font-size: 0.85em; opacity: 0.9;">Secure Session</p>
                            </div>
                        </div>
                    </div>
                </div>
                """

                user_info_html = f"""
                <div style="
                    background: linear-gradient(135deg, #667eea, #764ba2);
                    padding: 30px;
                    border-radius: 20px;
                    color: white;
                    box-shadow: 0 10px 30px rgba(102, 126, 234, 0.4);
                    border: 1px solid rgba(255,255,255,0.05);
                    margin-bottom: 25px;
                ">
                    <h3 style="margin: 0 0 20px 0; font-size: 1.5em; font-weight: 600;">
                    👤 USER INFORMATION
                    </h3>

                    <div style="
                        background: rgba(255,255,255,0.08);
                        padding: 20px;
                        border-radius: 15px;
                        border-left: 5px solid #4CAF50;
                        backdrop-filter: blur(5px);
                    ">
                        <p style="margin: 0 0 10px 0; font-size: 1.2em; font-weight: 600;">
                        {full_name}
                        </p>
                        <p style="margin: 0; font-size: 0.95em; opacity: 0.9;">
                        Username: {username}<br>
                        Role: <span style="color: #2ecc71; font-weight: 600;">{role.upper()}</span><br>
                        Status: <span style="color: #2ecc71; font-weight: 600;">ACTIVE</span>
                        </p>

                        <div style="
                            display: grid;
                            grid-template-columns: repeat(2, 1fr);
                            gap: 15px;
                            margin-top: 20px;
                            padding-top: 20px;
                            border-top: 1px solid rgba(255,255,255,0.1);
                        ">
                            <div style="text-align: center;">
                                <div style="font-size: 2em; margin-bottom: 5px;">📊</div>
                                <p style="margin: 0; font-size: 0.85em; opacity: 0.9;">Analysis Access</p>
                            </div>
                            <div style="text-align: center;">
                                <div style="font-size: 2em; margin-bottom: 5px;">{'👑' if role == 'admin' else '📁'}</div>
                                <p style="margin: 0; font-size: 0.85em; opacity: 0.9;">{'Admin Tools' if role == 'admin' else 'Basic Access'}</p>
                            </div>
                        </div>
                    </div>
                </div>
                """

                session_info_html = update_session_info()
                
                # FIX: Set correct visibility for admin controls and tabs
                is_admin = role == 'admin'
                batch_upload_visible = is_admin
                admin_controls_visible = is_admin
                dashboard_tab_visible = is_admin
                user_management_tab_visible = is_admin

                return (
                    gr.update(visible=True),   # status_row
                    gr.update(visible=False),  # login_row
                    gr.update(visible=True),   # main_row
                    gr.update(visible=True),   # user_panel_row
                    gr.update(visible=True),   # tech_accordion
                    gr.update(visible=True),   # tech_accordion visible for all logged in users
                    gr.update(value=status_html_content),  # status_html
                    gr.update(value=user_info_html),  # user_info_panel
                    gr.update(value=session_info_html),  # session_info
                    gr.update(visible=admin_controls_visible),  # admin_controls
                    gr.update(visible=batch_upload_visible),  # batch_upload_tab
                    gr.update(visible=dashboard_tab_visible),  # dashboard_tab
                    gr.update(visible=user_management_tab_visible),  # user_management_tab
                    gr.update(selected="analysis"),  # results_tabs
                    True,  # is_logged_in
                    username,  # current_user
                    role,  # current_role
                    "analysis"  # active_tab
                )
            else:
                return (
                    gr.update(visible=False),  # status_row
                    gr.update(visible=True),   # login_row
                    gr.update(visible=False),  # main_row
                    gr.update(visible=False),  # user_panel_row
                    gr.update(visible=False),  # tech_accordion
                    gr.update(visible=False),  # tech_accordion
                    gr.update(value=""),  # status_html
                    gr.update(value=""),  # user_info_panel
                    gr.update(value=""),  # session_info
                    gr.update(visible=False),  # admin_controls
                    gr.update(visible=False),  # batch_upload_tab
                    gr.update(visible=False),  # dashboard_tab
                    gr.update(visible=False),  # user_management_tab
                    gr.update(selected="analysis"),  # results_tabs
                    False,  # is_logged_in
                    "",  # current_user
                    "",  # current_role
                    "analysis"  # active_tab
                )

        def handle_login(username, password, is_logged_in_state, show_password=False):
            """Handle login attempt"""
            # Toggle password visibility
            password_type = "text" if show_password else "password"
            
            success, message = login_function(username, password)
            
            if success:
                role = session_manager.current_user.get('role', 'user')
                return update_ui_after_login(True, username, role) + (gr.update(value=""), gr.update(type=password_type))
            else:
                return update_ui_after_login(False, "", "") + (gr.update(value=message), gr.update(type=password_type))

        def handle_logout():
            """Handle logout"""
            message, _ = logout_function()
            return update_ui_after_login(False, "", "") + (gr.update(value=message), gr.update(type="password"))

        def handle_analyze(image):
            """Handle single image analysis"""
            if image is None:
                return "Please upload an image first.", gr.update(visible=True)
            
            session_manager.refresh_session()
            
            report = analyze_lung_nodule(image, model, metrics)
            
            return report, gr.update(visible=False)

        def handle_batch_analyze(files):
            """Handle batch image analysis"""
            if not files:
                return "Please select at least one image file."
            
            session_manager.refresh_session()
            
            images = []
            for file in files:
                try:
                    img = Image.open(file.name)
                    images.append(img)
                except Exception as e:
                    logger.error(f"Error loading image {file.name}: {str(e)}")
            
            if not images:
                return "No valid images could be loaded from the selected files."
            
            report = batch_analyze_images(images)
            
            return report

        def handle_export(image, report_text):
            """Handle report export"""
            if image is None or not report_text:
                return None, "Please complete an analysis first before exporting."
            
            export_path, export_message = export_analysis_report(image, report_text)
            return export_path, export_message

        def handle_clear():
            """Clear inputs and outputs"""
            return None, "", "", gr.update(visible=True)

        def handle_refresh_dashboard():
            """Refresh system dashboard"""
            if session_manager.is_admin():
                dashboard_content = get_system_dashboard()
                return dashboard_content
            else:
                return "⛔ ACCESS DENIED\n\nAdmin privileges required to view system dashboard."

        def handle_refresh_user_management():
            """Refresh user management dashboard"""
            if session_manager.is_admin():
                user_management_content = get_user_management_dashboard()
                return user_management_content
            else:
                return "⛔ ACCESS DENIED\n\nAdmin privileges required to view user management."

        def switch_to_dashboard_tab():
            """Switch to dashboard tab"""
            return gr.update(selected="dashboard")

        def switch_to_user_management_tab():
            """Switch to user management tab"""
            return gr.update(selected="users")

        # =============================================
        # PASSWORD VISIBILITY TOGGLE HANDLERS
        # =============================================

        def toggle_password_visibility(show_password):
            """Toggle password visibility"""
            return gr.update(type="text" if show_password else "password")

        def toggle_new_password_visibility(show_password):
            """Toggle new password visibility"""
            return gr.update(type="text" if show_password else "password")

        def toggle_reset_password_visibility(show_password):
            """Toggle reset password visibility"""
            return gr.update(type="text" if show_password else "password")

        # =============================================
        # PASSWORD RECOVERY HANDLERS
        # =============================================

        def handle_get_security_question(username):
            """Handle security question request"""
            if not username:
                return "Please enter your username", gr.update(value="")
            
            success, result = request_security_question(username)
            if success:
                return result, gr.update(value="")
            else:
                return f"❌ {result}", gr.update(value="")

        def handle_password_recovery(username, answer, new_password, show_password):
            """Handle password recovery"""
            success, message = verify_security_answer_and_reset(username, answer, new_password, show_password)
            
            if success:
                return "✅ " + message, gr.update(value=""), gr.update(value=""), gr.update(value=""), gr.update(type="password")
            else:
                return "❌ " + message, gr.update(), gr.update(), gr.update(), gr.update(type="password")

        # =============================================
        # ADMIN USER MANAGEMENT HANDLERS - FIXED VERSION
        # =============================================

        def handle_create_user(username, password, full_name, email, role, security_question, security_answer, show_password, show_password_checkbox):
            """Handle user creation by admin - FIXED VERSION"""
            if not session_manager.is_admin():
                return False, "⛔ Admin privileges required", gr.update(type="password")
            
            if not username or not password:
                return False, "Username and password are required", gr.update(type="password" if not show_password else "text")
            
            success, message = admin_create_user(
                username, password, full_name, email, role, 
                security_question, security_answer, show_password_checkbox
            )
            
            # Toggle password visibility based on checkbox
            password_type = "text" if show_password else "password"
            
            return success, message, gr.update(type=password_type)

        def handle_approve_user(username):
            """Handle user approval by admin"""
            if not session_manager.is_admin():
                return False, "⛔ Admin privileges required", gr.update()
            
            if not username:
                return False, "Username is required", gr.update()
            
            success, message = admin_approve_user(username)
            if success:
                # Refresh user management dashboard
                user_management_content = get_user_management_dashboard()
                return True, message, user_management_content
            else:
                return False, message, gr.update()

        def handle_disable_user(username):
            """Handle user disable by admin"""
            if not session_manager.is_admin():
                return False, "⛔ Admin privileges required", gr.update()
            
            if not username:
                return False, "Username is required", gr.update()
            
            success, message = admin_disable_user(username)
            if success:
                # Refresh user management dashboard
                user_management_content = get_user_management_dashboard()
                return True, message, user_management_content
            else:
                return False, message, gr.update()

        def handle_activate_user(username):
            """Handle user activation by admin"""
            if not session_manager.is_admin():
                return False, "⛔ Admin privileges required", gr.update()
            
            if not username:
                return False, "Username is required", gr.update()
            
            success, message = admin_activate_user(username)
            if success:
                # Refresh user management dashboard
                user_management_content = get_user_management_dashboard()
                return True, message, user_management_content
            else:
                return False, message, gr.update()

        def handle_reset_password_ui(username):
            """Show password reset UI - FIXED VERSION"""
            if not username:
                return gr.update(visible=False), gr.update(visible=False), gr.update(visible=False), ""
            
            if not session_manager.is_admin():
                return gr.update(visible=False), gr.update(visible=False), gr.update(visible=False), "⛔ Admin privileges required"
            
            return gr.update(visible=True), gr.update(visible=True), gr.update(visible=True), f"Reset password for user: {username}"

        def handle_reset_password(username, new_password, show_password):
            """Handle password reset by admin - FIXED VERSION"""
            if not session_manager.is_admin():
                return False, "⛔ Admin privileges required", gr.update(visible=False), gr.update(visible=False), gr.update(visible=False), gr.update()
            
            if not username or not new_password:
                return False, "Username and new password are required", gr.update(), gr.update(), gr.update(), gr.update()
            
            success, message = admin_reset_password(username, new_password, show_password)
            
            if success:
                # Refresh user management dashboard
                user_management_content = get_user_management_dashboard()
                return True, message, gr.update(visible=False), gr.update(visible=False), gr.update(visible=False), user_management_content
            else:
                return False, message, gr.update(), gr.update(), gr.update(), gr.update()

        def handle_delete_user(username):
            """Handle user deletion by admin"""
            if not session_manager.is_admin():
                return False, "⛔ Admin privileges required", gr.update()
            
            if not username:
                return False, "Username is required", gr.update()
            
            success, message = admin_delete_user(username)
            if success:
                # Refresh user management dashboard
                user_management_content = get_user_management_dashboard()
                return True, message, user_management_content
            else:
                return False, message, gr.update()

        # =============================================
        # CONNECT EVENT HANDLERS - FIXED VERSION
        # =============================================

        # Login/logout handlers
        login_btn.click(
            handle_login,
            inputs=[login_username, login_password, is_logged_in, login_password_show],
            outputs=[status_row, login_row, main_row, user_panel_row, tech_accordion, 
                    tech_accordion, status_html, user_info_panel, session_info,
                    admin_controls, batch_upload_tab, dashboard_tab, user_management_tab,
                    results_tabs, is_logged_in, current_user, current_role, active_tab,
                    login_message, login_password]
        )

        logout_btn.click(
            handle_logout,
            outputs=[status_row, login_row, main_row, user_panel_row, tech_accordion,
                    tech_accordion, status_html, user_info_panel, session_info,
                    admin_controls, batch_upload_tab, dashboard_tab, user_management_tab,
                    results_tabs, is_logged_in, current_user, current_role, active_tab,
                    login_message, login_password]
        )

        # Password visibility toggle for login
        login_password_show.change(
            toggle_password_visibility,
            inputs=[login_password_show],
            outputs=[login_password]
        )

        # Connect analysis button
        analyze_btn.click(
            handle_analyze,
            inputs=[image_input],
            outputs=[output_display, initial_results]
        )

        # Connect batch analysis button
        batch_analyze_btn.click(
            handle_batch_analyze,
            inputs=[batch_image_input],
            outputs=[batch_results]
        )

        # Connect export button
        export_btn.click(
            handle_export,
            inputs=[image_input, output_display],
            outputs=[gr.File(label="Download Report"), export_status]
        )

        # Connect clear button
        clear_btn.click(
            handle_clear,
            outputs=[image_input, output_display, export_status, initial_results]
        )

        # FIXED: Connect dashboard buttons to switch tabs
        view_dashboard_btn.click(
            switch_to_dashboard_tab,
            outputs=[results_tabs]
        )

        view_user_management_btn.click(
            switch_to_user_management_tab,
            outputs=[results_tabs]
        )

        refresh_dashboard_btn.click(
            handle_refresh_dashboard,
            outputs=[dashboard_display]
        )

        refresh_users_btn.click(
            handle_refresh_user_management,
            outputs=[user_management_display]
        )

        # Connect password recovery handlers
        get_question_btn.click(
            handle_get_security_question,
            inputs=[recovery_username],
            outputs=[security_question_display, recovery_message]
        )

        recover_btn.click(
            handle_password_recovery,
            inputs=[recovery_username, security_answer, new_password, show_password],
            outputs=[recovery_message, recovery_username, security_answer, new_password, new_password]
        )

        # Password visibility toggle for recovery
        show_password.change(
            toggle_new_password_visibility,
            inputs=[show_password],
            outputs=[new_password]
        )

        # Connect admin user management handlers - FIXED VERSION
        create_user_btn.click(
            handle_create_user,
            inputs=[new_user_username, new_user_password, new_user_full_name, 
                   new_user_email, new_user_role, new_user_security_question,
                   new_user_security_answer, new_user_password_show, new_user_show_password],
            outputs=[create_user_message, new_user_password]
        ).then(
            lambda: ("", "", "", "", "", ""),
            outputs=[new_user_username, new_user_password, new_user_full_name, 
                    new_user_email, new_user_security_question, new_user_security_answer]
        )

        # Password visibility toggle for new user
        new_user_password_show.change(
            toggle_new_password_visibility,
            inputs=[new_user_password_show],
            outputs=[new_user_password]
        )

        # Connect user management actions - FIXED VERSION
        approve_user_btn.click(
            handle_approve_user,
            inputs=[action_username],
            outputs=[user_action_message, user_management_display]
        )

        disable_user_btn.click(
            handle_disable_user,
            inputs=[action_username],
            outputs=[user_action_message, user_management_display]
        )

        activate_user_btn.click(
            handle_activate_user,
            inputs=[action_username],
            outputs=[user_action_message, user_management_display]
        )

        reset_pw_btn.click(
            handle_reset_password_ui,
            inputs=[action_username],
            outputs=[new_password_for_reset, show_reset_password, reset_password_btn, user_action_message]
        )

        # Password visibility toggle for reset
        show_reset_password.change(
            toggle_reset_password_visibility,
            inputs=[show_reset_password],
            outputs=[new_password_for_reset]
        )

        reset_password_btn.click(
            handle_reset_password,
            inputs=[action_username, new_password_for_reset, show_reset_password],
            outputs=[user_action_message, new_password_for_reset, show_reset_password, reset_password_btn, user_management_display]
        )

        delete_user_btn.click(
            handle_delete_user,
            inputs=[action_username],
            outputs=[user_action_message, user_management_display]
        )

        # Initialize user management dashboard on load
        demo.load(
            lambda: get_user_management_dashboard() if session_manager.is_admin() else "⛔ Admin privileges required",
            outputs=[user_management_display]
        )

        # Initialize system dashboard on load
        demo.load(
            lambda: get_system_dashboard() if session_manager.is_admin() else "⛔ Admin privileges required",
            outputs=[dashboard_display]
        )

    return demo

# =============================================
# 21. MAIN FUNCTION WITH PORT HANDLING
# =============================================

def main():
    """Main function to run the enhanced system"""
    print("\n" + "="*80)
    print("🔒 STARTING ENHANCED SECURE SYSTEM WITH USER MANAGEMENT...")
    print("="*80)
    
    global model, accuracy, metrics

    try:
        # Step 1: Check/create data
        data_dir = Path('lung_data')
        x_path = data_dir / 'X.npy'
        y_path = data_dir / 'y.npy'
        
        if x_path.exists() and y_path.exists():
            print("\n📁 Loading existing dataset...")
            X = np.load(x_path)
            y = np.load(y_path)
            print(f"   ✓ Loaded: {len(X)} training images")
        else:
            print("\n📊 Generating new synthetic dataset with augmentation...")
            X, y = create_enhanced_data(250)

        # Step 2: Load or train model
        model_path = Path('lung_model.h5')
        if model_path.exists():
            print("\n🤖 Loading trained model...")
            model = tf.keras.models.load_model(str(model_path))
            
            metrics_path = Path('model_metrics.json')
            if metrics_path.exists():
                with open(metrics_path, 'r') as f:
                    metrics = json.load(f)
                accuracy = metrics.get('accuracy', 0.5)
                print(f"   ✓ Model loaded with {accuracy:.1%} accuracy")
                print(f"   ✓ Comprehensive metrics loaded")
            else:
                print("   ⚠️ Calculating model metrics...")
                indices = np.random.permutation(len(X))
                split_idx = int(len(X) * 0.8)
                X_test = X[indices[split_idx:]]
                y_test = y[indices[split_idx:]]
                
                metrics = calculate_comprehensive_metrics(model, X_test, y_test)
                accuracy = metrics.get('accuracy', 0.5)
                print(f"   ✓ Model evaluated: {accuracy:.1%} accuracy")
            
        else:
            print("\n🤖 Training new model with enhanced features...")
            model = create_advanced_model()
            model, metrics = train_model(model, X, y)
            accuracy = metrics.get('accuracy', 0.5)

        model_metadata['accuracy'] = f"{accuracy:.1%}"
        
        # Step 3: Create enhanced secure interface
        print("\n🖥️ Building enhanced secure interface with user management...")
        demo = create_secure_interface()

        # Step 4: Find available port and launch
        print("\n🔍 Finding available port...")
        try:
            available_port = find_available_port(7860)
            print(f"   ✓ Found available port: {available_port}")
        except OSError:
            print("   ⚠️ Using default port 7860 (may fail if in use)")
            available_port = 7860

        print("\n" + "="*80)
        print("✅ ENHANCED SYSTEM WITH USER MANAGEMENT READY FOR LAUNCH!")
        print("="*80)
        print(f"\n🌐 System will launch on port: {available_port}")
        print("\n📋 Available Demo Accounts:")
        print("   👤 User: demo | Password: Demo@123")
        print("   👑 Admin: admin | Password: Admin@Secure123!")
        print("\n🔐 User Management Features:")
        print("   • Admin-only user creation and approval")
        print("   • User activation/deactivation")
        print("   • Password reset (admin and self-recovery)")
        print("   • Security question-based password recovery")
        print("   • Comprehensive user listing and management")
        print("\n🔑 Password Visibility Feature:")
        print("   • Toggle password visibility with 👁️ eye icon")
        print("   • Works for login, recovery, and user management")

        # Launch with appropriate settings
        try:
            import google.colab
            print("\n🔗 Launching in Google Colab environment...")
            print(f"📱 Access the interface at: https://localhost:{available_port}")
            demo.launch(
                server_name="0.0.0.0",
                server_port=available_port,
                share=True,
                debug=False,
                height=800
            )
        except ImportError:
            print("\n🌐 Launching local server...")
            demo.launch(
                server_name="0.0.0.0",
                server_port=available_port,
                share=False,
                height=800
            )
            print(f"\n✅ System launched on http://localhost:{available_port}")
            print("📱 Access from any device on your network")

    except Exception as e:
        print(f"\n❌ System initialization error: {str(e)}")
        traceback.print_exc()
        print("\n🔧 Troubleshooting:")
        print("1. Try running on a different port by setting GRADIO_SERVER_PORT environment variable")
        print("2. Restart the runtime/terminal")
        print("3. Check if port is already in use")
        print("4. Ensure all dependencies are installed")
        logger.error(f"System initialization failed: {str(e)}")

# =============================================
# RUN ENHANCED SYSTEM
# =============================================

if __name__ == "__main__":
    main()
