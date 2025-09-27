from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, send_file, make_response, session, abort
import pandas as pd
import numpy as np
import pickle
import os
from werkzeug.utils import secure_filename
import json
from datetime import datetime, timedelta
import plotly.graph_objs as go
import plotly.utils
import io
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.units import inch
import tabula
import pdfplumber
import PyPDF2
import re
import logging
from functools import wraps

# Security imports
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
import secrets

# Custom security modules
from auth import user_manager, log_security_event, sanitize_input
from forms import (LoginForm, RegistrationForm, PredictionForm, SecureFileUploadForm,
                  AdminUserManagementForm, AdminPasswordResetForm, sanitize_form_data, validate_file_content)

# Load environment variables
load_dotenv()

# Initialize Flask app with security
app = Flask(__name__)

# Security Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour CSRF token validity
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Initialize security extensions
csrf = CSRFProtect(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[os.getenv('DEFAULT_RATE_LIMIT', '100 per hour')]
)
limiter.init_app(app)

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.getenv('LOG_FILE', 'fraud_detection.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@login_manager.user_loader
def load_user(user_id):
    """Load user for Flask-Login"""
    return user_manager.get_user(user_id)

# Security decorators and helpers
def admin_required(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            log_security_event('UNAUTHORIZED_ADMIN_ACCESS',
                             username=current_user.username if current_user.is_authenticated else 'Anonymous',
                             ip_address=request.remote_addr)
            flash('Admin privileges required.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def developer_admin_required(f):
    """Decorator to require developer/system admin role - STRICT ACCESS CONTROL"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            log_security_event('UNAUTHORIZED_DEVELOPER_ACCESS_ATTEMPT',
                             username='Anonymous',
                             ip_address=request.remote_addr,
                             details='Unauthenticated access attempt to developer panel')
            abort(404)  # Hide the existence of the route

        if not current_user.is_developer_admin():
            log_security_event('UNAUTHORIZED_DEVELOPER_ACCESS_ATTEMPT',
                             username=current_user.username,
                             ip_address=request.remote_addr,
                             details=f'User {current_user.username} attempted to access developer panel')
            abort(404)  # Hide the existence of the route

        log_security_event('DEVELOPER_PANEL_ACCESS',
                         username=current_user.username,
                         ip_address=request.remote_addr,
                         details='Authorized developer panel access')
        return f(*args, **kwargs)
    return decorated_function

def validate_and_sanitize_input(data):
    """Validate and sanitize input data"""
    try:
        sanitized_data = {}
        for key, value in data.items():
            if isinstance(value, str):
                sanitized_data[key] = sanitize_input(value)
            else:
                sanitized_data[key] = value
        return sanitized_data
    except Exception as e:
        logger.error(f"Input sanitization error: {e}")
        return data

def secure_file_upload(file, upload_folder='uploads'):
    """Securely handle file uploads"""
    try:
        if not file or file.filename == '':
            return None, "No file selected"

        # Secure the filename
        filename = secure_filename(file.filename)
        if not filename:
            return None, "Invalid filename"

        # Check file extension
        allowed_extensions = os.getenv('ALLOWED_EXTENSIONS', 'csv,xlsx,xls,pdf').split(',')
        file_ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''

        if file_ext not in allowed_extensions:
            return None, f"File type '{file_ext}' not allowed"

        # Create upload directory if it doesn't exist
        os.makedirs(upload_folder, exist_ok=True)

        # Generate unique filename to prevent conflicts
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        unique_filename = f"{timestamp}_{filename}"
        filepath = os.path.join(upload_folder, unique_filename)

        # Save file
        file.save(filepath)

        # Validate file content
        is_valid, message = validate_file_content(filepath, allowed_extensions)
        if not is_valid:
            os.remove(filepath)  # Remove invalid file
            return None, message

        logger.info(f"File uploaded successfully: {unique_filename}")
        return filepath, "File uploaded successfully"

    except Exception as e:
        logger.error(f"File upload error: {e}")
        return None, f"File upload failed: {str(e)}"

def handle_error_safely(error, user_message="An error occurred"):
    """Handle errors safely without exposing sensitive information"""
    error_id = secrets.token_hex(8)
    logger.error(f"Error ID {error_id}: {str(error)}")

    # Log security event if it's a potential attack
    if any(keyword in str(error).lower() for keyword in ['injection', 'script', 'sql', 'xss']):
        log_security_event('POTENTIAL_ATTACK',
                         username=current_user.username if current_user.is_authenticated else 'Anonymous',
                         ip_address=request.remote_addr,
                         details=f"Error ID: {error_id}")

    return f"{user_message}. Error ID: {error_id}"

def validate_input_data(data):
    """Validate input data for potential issues"""
    issues = []

    try:
        # Check for suspicious patterns
        if data.get('amount', 0) > 1000000:
            issues.append("Very large transaction amount")

        if data.get('oldbalanceOrg', 0) < 0:
            issues.append("Negative original balance")

        if data.get('newbalanceOrig', 0) < 0:
            issues.append("Negative new balance")

        # Check balance consistency
        old_balance = data.get('oldbalanceOrg', 0)
        new_balance = data.get('newbalanceOrig', 0)
        amount = data.get('amount', 0)

        if data.get('type') in ['PAYMENT', 'TRANSFER', 'CASH_OUT', 'DEBIT']:
            expected_balance = old_balance - amount
            if abs(new_balance - expected_balance) > 0.01 and new_balance != 0:
                issues.append("Balance calculation may be inconsistent")

    except Exception as e:
        logger.error(f"Data validation error: {e}")
        issues.append("Data validation error")

    return issues
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 1000 * 1024 * 1024  # 1000MB max file size

# Allowed file extensions
ALLOWED_EXTENSIONS = {'csv', 'xlsx', 'xls', 'pdf', 'txt', 'json'}

# Create upload directory
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Load models
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, 'models')

try:
    with open(os.path.join(MODELS_DIR, 'model_xgb.pkl'), 'rb') as f:
        xgb_model = pickle.load(f)
    print("XGBoost model loaded successfully")
except:
    xgb_model = None
    print("Warning: XGBoost model not found")

try:
    with open('models/iso_forest.pkl', 'rb') as f:
        isolation_forest_model = pickle.load(f)
    print("Isolation Forest model loaded successfully")
except:
    isolation_forest_model = None
    print("Warning: Isolation Forest model not found")

try:
    with open('models/scaler.pkl', 'rb') as f:
        scaler = pickle.load(f)
    print("Scaler loaded successfully")
except:
    scaler = None
    print("Warning: Scaler not found")

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_tables_from_pdf(filepath):
    """
    Extract tabular data from PDF using multiple methods
    Returns a pandas DataFrame or raises an exception
    """
    print(f"Attempting to extract tables from PDF: {filepath}")

    # Method 1: Try tabula-py (works well with PDFs that have clear table structures)
    try:
        print("Trying tabula-py extraction...")
        tables = tabula.read_pdf(filepath, pages='all', multiple_tables=True)

        if tables and len(tables) > 0:
            # Find the largest table (most likely to be the main data)
            largest_table = max(tables, key=len)

            if len(largest_table) > 0:
                print(f"✅ Tabula-py found table with {len(largest_table)} rows")
                return clean_extracted_dataframe(largest_table)

    except Exception as e:
        print(f"Tabula-py failed: {e}")

    # Method 2: Try pdfplumber (better for complex layouts)
    try:
        print("Trying pdfplumber extraction...")
        with pdfplumber.open(filepath) as pdf:
            all_tables = []

            for page_num, page in enumerate(pdf.pages):
                tables = page.extract_tables()
                if tables:
                    print(f"Found {len(tables)} tables on page {page_num + 1}")
                    all_tables.extend(tables)

            if all_tables:
                # Convert the largest table to DataFrame
                largest_table = max(all_tables, key=len)
                df = pd.DataFrame(largest_table[1:], columns=largest_table[0])
                print(f"✅ PDFplumber found table with {len(df)} rows")
                return clean_extracted_dataframe(df)

    except Exception as e:
        print(f"PDFplumber failed: {e}")

    # Method 3: Try text extraction and parsing (fallback)
    try:
        print("Trying text extraction and parsing...")
        with open(filepath, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            text = ""

            for page in pdf_reader.pages:
                text += page.extract_text() + "\n"

            # Try to parse structured text into a table
            df = parse_text_to_dataframe(text)
            if df is not None and len(df) > 0:
                print(f"✅ Text parsing found data with {len(df)} rows")
                return clean_extracted_dataframe(df)

    except Exception as e:
        print(f"Text extraction failed: {e}")

    # If all methods fail
    raise ValueError("Could not extract tabular data from PDF. Please ensure the PDF contains properly formatted tables.")

def clean_extracted_dataframe(df):
    """Clean and standardize extracted DataFrame"""
    print("Cleaning extracted DataFrame...")

    # Remove empty rows and columns
    df = df.dropna(how='all').dropna(axis=1, how='all')

    # Clean column names
    df.columns = df.columns.astype(str)
    df.columns = [col.strip().lower().replace(' ', '').replace('_', '') for col in df.columns]

    # Map common column variations to standard names (with correct case)
    column_mapping = {
        'timestep': 'step',
        'time': 'step',
        'transactiontype': 'type',
        'transtype': 'type',
        'txntype': 'type',
        'transactionamount': 'amount',
        'amt': 'amount',
        'value': 'amount',
        'oldbalance': 'oldbalanceOrg',
        'oldbalanceorg': 'oldbalanceOrg',  # Fix case mismatch
        'originalbalance': 'oldbalanceOrg',
        'prevbalance': 'oldbalanceOrg',
        'newbalance': 'newbalanceOrig',
        'newbalanceorig': 'newbalanceOrig',  # Fix case mismatch
        'currentbalance': 'newbalanceOrig',
        'balanceafter': 'newbalanceOrig',
        'fraud': 'isFraud',
        'fraudulent': 'isFraud',
        'isfraudulent': 'isFraud'
    }

    # Apply column mapping
    df.columns = [column_mapping.get(col, col) for col in df.columns]

    # Convert data types (use correct column names after mapping)
    numeric_columns = ['step', 'amount', 'oldbalanceOrg', 'newbalanceOrig']
    for col in numeric_columns:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
            print(f"Converted {col} to numeric: {df[col].dtype}")

    # Clean string columns
    string_columns = ['type']
    for col in string_columns:
        if col in df.columns:
            df[col] = df[col].astype(str).str.strip().str.upper()

    # Remove rows with all NaN values in required columns (use correct column names)
    required_cols = ['step', 'amount', 'oldbalanceOrg', 'newbalanceOrig', 'type']
    available_required_cols = [col for col in required_cols if col in df.columns]

    if available_required_cols:
        df = df.dropna(subset=available_required_cols, how='all')

    # Fill any remaining NaN values with 0 for numeric columns
    numeric_cols = ['step', 'amount', 'oldbalanceOrg', 'newbalanceOrig']
    for col in numeric_cols:
        if col in df.columns:
            df[col] = df[col].fillna(0)

    # Fill NaN values in string columns
    if 'type' in df.columns:
        df['type'] = df['type'].fillna('UNKNOWN')

    print(f"Cleaned DataFrame: {len(df)} rows, {len(df.columns)} columns")
    print(f"Columns: {list(df.columns)}")
    print(f"Data types:\n{df.dtypes}")

    return df

def parse_text_to_dataframe(text):
    """Parse extracted text into a DataFrame (fallback method)"""
    lines = text.split('\n')

    # Look for patterns that might indicate tabular data
    potential_rows = []

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Look for lines with multiple numeric values (potential data rows)
        numbers = re.findall(r'\d+\.?\d*', line)
        if len(numbers) >= 3:  # At least 3 numbers might indicate a data row
            # Split by whitespace and clean
            parts = line.split()
            if len(parts) >= 4:  # Minimum expected columns
                potential_rows.append(parts)

    if len(potential_rows) < 2:  # Need at least header + 1 data row
        return None

    # Try to create DataFrame
    try:
        # Assume first row might be headers or use generic headers
        if len(potential_rows) > 0:
            max_cols = max(len(row) for row in potential_rows)

            # Create generic headers if needed
            headers = [f'col_{i}' for i in range(max_cols)]

            # Pad rows to same length
            padded_rows = []
            for row in potential_rows:
                padded_row = row + [''] * (max_cols - len(row))
                padded_rows.append(padded_row[:max_cols])

            df = pd.DataFrame(padded_rows, columns=headers)
            return df

    except Exception as e:
        print(f"Error parsing text to DataFrame: {e}")
        return None

    return None

def validate_input_data(data):
    """Validate input data for common issues"""
    issues = []

    # Check for negative values where they shouldn't be
    if data['amount'] < 0:
        issues.append("Amount cannot be negative")
    if data['oldbalanceOrg'] < 0:
        issues.append("Original balance cannot be negative")
    if data['newbalanceOrig'] < 0:
        issues.append("New balance cannot be negative")

    # Check for logical inconsistencies
    if data['amount'] > data['oldbalanceOrg'] and data['type'] in ['PAYMENT', 'DEBIT']:
        issues.append("Transaction amount exceeds available balance")

    # Check transaction type
    valid_types = ['CASH_OUT', 'DEBIT', 'PAYMENT', 'TRANSFER', 'CASH_IN']
    if data['type'] not in valid_types:
        issues.append(f"Invalid transaction type. Must be one of: {valid_types}")

    return issues

def prepare_features_for_prediction(data):
    """Prepare features exactly as they were during model training"""
    # Validate input data first
    validation_issues = validate_input_data(data)
    if validation_issues:
        print(f"Data validation warnings: {validation_issues}")

    # Create all the engineered features that were used during training
    features = []

    # Basic features
    features.append(float(data['step']))
    features.append(float(data['amount']))
    features.append(float(data['oldbalanceOrg']))

    # Engineered features (same as in training)
    balance_drop_ratio = (data['oldbalanceOrg'] - data['newbalanceOrig']) / (data['oldbalanceOrg'] + 1e-6)
    features.append(float(balance_drop_ratio))

    zero_balance_after = int(data['newbalanceOrig'] == 0)
    features.append(float(zero_balance_after))

    # Transaction type one-hot encoding (matching training data)
    # Based on the training data, the order should be: CASH_OUT, DEBIT, PAYMENT, TRANSFER
    type_cash_out = 1 if data['type'] == 'CASH_OUT' else 0
    type_debit = 1 if data['type'] == 'DEBIT' else 0
    type_payment = 1 if data['type'] == 'PAYMENT' else 0
    type_transfer = 1 if data['type'] == 'TRANSFER' else 0

    features.extend([float(type_cash_out), float(type_debit), float(type_payment), float(type_transfer)])



    return np.array(features).reshape(1, -1)

def calculate_threat_score(fraud_probability):
    """Calculate threat score based on fraud probability"""
    if fraud_probability >= 0.8:
        return "CRITICAL", "red"
    elif fraud_probability >= 0.6:
        return "HIGH", "orange"
    elif fraud_probability >= 0.4:
        return "MEDIUM", "yellow"
    elif fraud_probability >= 0.2:
        return "LOW", "lightgreen"
    else:
        return "MINIMAL", "green"

def get_prediction_explanation(data, probability):
    """Provide explanation for the prediction"""
    explanations = []

    # High-risk patterns
    if data['type'] in ['TRANSFER', 'CASH_OUT']:
        explanations.append(f"Transaction type '{data['type']}' is high-risk")

    if data['newbalanceOrig'] == 0:
        explanations.append("Account balance becomes zero after transaction")

    if data['amount'] > data['oldbalanceOrg'] * 0.8:
        explanations.append("Transaction amount is very high relative to balance")

    if data['amount'] % 1000 == 0 and data['amount'] > 10000:
        explanations.append("Round amount transactions above 10K are suspicious")

    # Low-risk patterns
    if data['type'] == 'PAYMENT' and data['amount'] < data['oldbalanceOrg'] * 0.1:
        explanations.append("Small payment transactions are typically legitimate")

    if data['type'] == 'DEBIT' and data['amount'] < 5000:
        explanations.append("Small debit transactions are usually normal")

    if not explanations:
        explanations.append("Standard transaction pattern detected")

    return explanations

def calculate_anomaly_score(anomaly_score):
    """Calculate anomaly score based on isolation forest score"""
    # Isolation Forest returns -1 for anomalies and 1 for normal points
    # We'll also use the decision function score for more granular classification
    if anomaly_score == -1:
        return "ANOMALY DETECTED", "red", True
    else:
        return "NORMAL", "green", False

def prepare_features_for_anomaly_detection(data):
    """Prepare features for anomaly detection model (original 10 raw features)"""
    # The Isolation Forest was trained on the original raw features:
    # ['step', 'type', 'amount', 'nameOrig', 'oldbalanceOrg', 'newbalanceOrig',
    #  'nameDest', 'oldbalanceDest', 'newbalanceDest', 'isFlaggedFraud']

    features = []

    # Original raw features in the same order as training
    features.append(float(data['step']))

    # Encode transaction type as numeric (same as training)
    type_mapping = {'CASH_IN': 0, 'CASH_OUT': 1, 'DEBIT': 2, 'PAYMENT': 3, 'TRANSFER': 4}
    features.append(float(type_mapping.get(data['type'], 3)))  # Default to PAYMENT

    features.append(float(data['amount']))

    # For missing nameOrig, use a default numeric value
    features.append(0.0)  # nameOrig (encoded)

    features.append(float(data['oldbalanceOrg']))
    features.append(float(data['newbalanceOrig']))

    # For missing nameDest, use a default numeric value
    features.append(0.0)  # nameDest (encoded)

    # For missing oldbalanceDest and newbalanceDest, use defaults
    features.append(0.0)  # oldbalanceDest
    features.append(0.0)  # newbalanceDest

    # For missing isFlaggedFraud, use default
    features.append(0.0)  # isFlaggedFraud

    return np.array(features).reshape(1, -1)

def detect_anomaly(features, data=None):
    """Detect anomaly using Isolation Forest with enhanced business logic"""
    if isolation_forest_model is None:
        return None, None, None, None

    try:
        # Scale features using the scaler trained on raw data
        if scaler is not None:
            features_scaled = scaler.transform(features)
        else:
            features_scaled = features

        # Get anomaly prediction (-1 for anomaly, 1 for normal)
        prediction = isolation_forest_model.predict(features_scaled)[0]

        # Get anomaly score (more negative = more anomalous)
        decision_score = isolation_forest_model.decision_function(features_scaled)[0]

        # Enhanced anomaly scoring with business logic
        base_anomaly_score = abs(decision_score)

        # Apply business logic adjustments if data is provided
        if data is not None:
            # High-risk transaction patterns increase anomaly score
            if data['type'] in ['TRANSFER', 'CASH_OUT']:
                base_anomaly_score += 0.1

            # Zero balance after transaction is highly anomalous
            if data['newbalanceOrig'] == 0 and data['oldbalanceOrg'] > 0:
                base_anomaly_score += 0.2

            # Large transactions relative to balance
            if data['amount'] > data['oldbalanceOrg'] * 0.9:
                base_anomaly_score += 0.15

            # Round amounts are suspicious
            if data['amount'] % 1000 == 0 and data['amount'] > 5000:
                base_anomaly_score += 0.05

            # Very small or very large amounts
            if data['amount'] < 1 or data['amount'] > 1000000:
                base_anomaly_score += 0.1

        # Improved threshold-based classification with fine-tuned thresholds
        if prediction == -1 or base_anomaly_score > 0.25:
            if base_anomaly_score > 0.5:
                anomaly_level, color = "CRITICAL ANOMALY", "red"
            elif base_anomaly_score > 0.4:
                anomaly_level, color = "HIGH ANOMALY", "orange"
            elif base_anomaly_score > 0.3:
                anomaly_level, color = "MEDIUM ANOMALY", "yellow"
            else:
                anomaly_level, color = "LOW ANOMALY", "lightblue"
            is_anomaly = True
        else:
            anomaly_level, color = "NORMAL", "green"
            is_anomaly = False

        return base_anomaly_score, anomaly_level, color, is_anomaly
    except Exception as e:
        print(f"Error in anomaly detection: {e}")
        return None, None, None, None

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    """Secure login page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = LoginForm()

    if form.validate_on_submit():
        try:
            username = sanitize_input(form.username.data)
            password = form.password.data

            user = user_manager.authenticate_user(username, password)

            if user:
                login_user(user, remember=False)
                log_security_event('LOGIN_SUCCESS', username=username, ip_address=request.remote_addr)

                next_page = request.args.get('next')
                if next_page and next_page.startswith('/'):
                    return redirect(next_page)
                return redirect(url_for('dashboard'))
            else:
                log_security_event('LOGIN_FAILED', username=username, ip_address=request.remote_addr)
                flash('Invalid username or password. Please try again.', 'error')

        except Exception as e:
            error_msg = handle_error_safely(e, "Login failed")
            flash(error_msg, 'error')

    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def register():
    """User registration page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = RegistrationForm()

    if form.validate_on_submit():
        try:
            username = sanitize_input(form.username.data)
            email = sanitize_input(form.email.data)
            phone = sanitize_input(form.phone.data)
            password = form.password.data

            # Register user
            success, message = user_manager.register_user(username, email, phone, password)

            if success:
                log_security_event('USER_REGISTERED', username=username, ip_address=request.remote_addr)
                flash('Registration successful! You can now log in.', 'success')
                return redirect(url_for('login'))
            else:
                flash(message, 'error')

        except Exception as e:
            error_msg = handle_error_safely(e, "Registration failed")
            flash(error_msg, 'error')

    elif request.method == 'POST':
        # Handle form validation errors
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{field}: {error}', 'error')

    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    """Secure logout"""
    username = current_user.username if current_user.is_authenticated else 'Unknown'
    logout_user()
    log_security_event('LOGOUT', username=username, ip_address=request.remote_addr)
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('intro'))

@app.route('/')
def home():
    """Redirect to intro page as landing page"""
    return render_template('intro.html')

@app.route('/intro')
def intro():
    """Intro/Landing page"""
    return render_template('intro.html')

@app.route('/dashboard')
@login_required
@limiter.limit("30 per minute")
def dashboard():
    """Main dashboard page - requires authentication"""
    try:
        return render_template('dashboard.html', user=current_user)
    except Exception as e:
        error_msg = handle_error_safely(e, "Dashboard loading failed")
        flash(error_msg, 'error')
        return redirect(url_for('intro'))

@app.route('/predict', methods=['GET', 'POST'])
@login_required
@limiter.limit("20 per minute")
def predict():
    """Secure single transaction prediction"""
    form = PredictionForm()

    if form.validate_on_submit():
        try:
            # Sanitize and validate input data
            data = {
                'step': form.step.data,
                'amount': form.amount.data,
                'oldbalanceOrg': form.old_balance_org.data,
                'newbalanceOrig': form.new_balance_orig.data,
                'type': form.transaction_type.data
            }

            # Additional validation
            if data['amount'] <= 0:
                flash('Amount must be greater than zero.', 'error')
                return render_template('predict.html', form=form)

            # Log prediction request
            log_security_event('PREDICTION_REQUEST',
                             username=current_user.username,
                             ip_address=request.remote_addr,
                             details=f"Amount: {data['amount']}")

            # Validate input data
            validation_issues = validate_input_data(data)
            if validation_issues:
                flash(f'Data validation warnings: {", ".join(validation_issues)}', 'warning')
            
            # Prepare features using the improved function
            features = prepare_features_for_prediction(data)

            # Predict with XGBoost (no scaling needed for XGBoost model)
            if xgb_model:
                try:
                    prediction = xgb_model.predict(features)[0]
                    probability = xgb_model.predict_proba(features)[0][1]

                    # Apply additional business logic for better accuracy
                    # High-risk transaction patterns
                    if data['type'] in ['TRANSFER', 'CASH_OUT'] and data['newbalanceOrig'] == 0:
                        probability = min(probability + 0.3, 1.0)  # Increase fraud probability

                    # Large amounts relative to balance
                    if data['amount'] > data['oldbalanceOrg'] * 0.8:
                        probability = min(probability + 0.2, 1.0)

                    # Round amounts (often fraudulent)
                    if data['amount'] % 1000 == 0 and data['amount'] > 10000:
                        probability = min(probability + 0.1, 1.0)

                    # Recalculate prediction based on adjusted probability
                    prediction = 1 if probability > 0.5 else 0

                    threat_level, color = calculate_threat_score(probability)
                    explanations = get_prediction_explanation(data, probability)

                    result = {
                        'prediction': int(prediction),
                        'probability': float(probability),
                        'threat_level': threat_level,
                        'color': color,
                        'explanations': explanations,
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }



                    # Track user activity
                    user_manager.update_user_activity(current_user.id, 'prediction')

                    return render_template('predict.html', result=result)
                except Exception as model_error:
                    print(f"Model prediction error: {model_error}")
                    flash(f'Prediction error: {str(model_error)}', 'error')
            else:
                flash('Model not available', 'error')
                
        except Exception as e:
            error_msg = handle_error_safely(e, "Prediction failed")
            flash(error_msg, 'error')

    elif request.method == 'POST':
        # Handle form validation errors
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{field}: {error}', 'error')

    return render_template('predict.html', form=form)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per minute")
def upload_file():
    """Secure file upload and batch analysis"""
    form = SecureFileUploadForm()

    if form.validate_on_submit():
        try:
            file = form.file.data

            # Log upload attempt
            log_security_event('FILE_UPLOAD_ATTEMPT',
                             username=current_user.username,
                             ip_address=request.remote_addr,
                             details=f"Filename: {file.filename}")

            # Secure file upload
            filepath, message = secure_file_upload(file)

            if not filepath:
                flash(message, 'error')
                return render_template('upload.html', form=form)

            filename = os.path.basename(filepath)

            try:
                # Process file based on extension
                if filename.endswith('.csv'):
                    print(f"Processing CSV file: {filename}")
                    df = pd.read_csv(filepath)
                elif filename.endswith(('.xlsx', '.xls')):
                    print(f"Processing Excel file: {filename}")
                    df = pd.read_excel(filepath)
                elif filename.endswith('.pdf'):
                    print(f"Processing PDF file: {filename}")
                    try:
                        df = extract_tables_from_pdf(filepath)
                        print(f"PDF extraction successful: {len(df)} rows, {len(df.columns)} columns")
                        print(f"PDF columns: {list(df.columns)}")
                        flash(f'Successfully extracted {len(df)} rows from PDF', 'success')
                    except Exception as pdf_error:
                        print(f"PDF extraction error: {pdf_error}")
                        flash(f'PDF extraction failed: {str(pdf_error)}. Please ensure your PDF contains properly formatted tables.', 'error')
                        return redirect(request.url)
                else:
                    flash('File type not supported for prediction. Supported formats: CSV, Excel (.xlsx/.xls), PDF', 'error')
                    return redirect(request.url)

                # Validate required columns (after column mapping)
                print(f"Validating columns for {filename}")
                print(f"Available columns: {list(df.columns)}")

                required_columns = ['step', 'amount', 'oldbalanceOrg', 'newbalanceOrig', 'type']
                missing_columns = [col for col in required_columns if col not in df.columns]

                if missing_columns:
                    print(f"Missing columns: {missing_columns}")
                    flash(f'Missing required columns: {", ".join(missing_columns)}. Please ensure your file contains: step, amount, oldbalanceOrg, newbalanceOrig, type', 'error')
                    return redirect(request.url)

                print("✅ All required columns found")

                # Check if DataFrame is empty
                if len(df) == 0:
                    print("❌ DataFrame is empty")
                    flash('No data found in the uploaded file. Please check the file format and content.', 'error')
                    return redirect(request.url)

                print(f"✅ Successfully processed {filename}: {len(df)} rows, {len(df.columns)} columns")
                print(f"Sample data:\n{df.head()}")

                # Process predictions
                print("🔄 Starting batch predictions...")
                results = process_batch_predictions(df)
                print(f"✅ Batch predictions completed: {len(results)} results")

                # Track user activity
                user_manager.update_user_activity(current_user.id, 'upload')

                # Add file type info to results for better tracking
                for result in results:
                    result['file_type'] = 'PDF' if filename.endswith('.pdf') else ('Excel' if filename.endswith(('.xlsx', '.xls')) else 'CSV')

                return render_template('batch_results.html', results=results, filename=filename)

            except Exception as e:
                error_msg = handle_error_safely(e, "File processing failed")
                flash(error_msg, 'error')
            finally:
                # Clean up uploaded file
                try:
                    if os.path.exists(filepath):
                        os.remove(filepath)
                except Exception as cleanup_error:
                    logger.error(f"Failed to cleanup file {filepath}: {cleanup_error}")

        except Exception as e:
            error_msg = handle_error_safely(e, "Upload failed")
            flash(error_msg, 'error')

    elif request.method == 'POST':
        # Handle form validation errors
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{field}: {error}', 'error')

    return render_template('upload.html', form=form)

# Admin routes
@app.route('/admin_access')
def admin_access():
    """Admin access information page"""
    return render_template('admin_access.html')

@app.route('/admin')
@login_required
@admin_required
@limiter.limit("30 per minute")
def admin_panel():
    """Admin control panel"""
    try:
        users = list(user_manager.get_all_users())
        stats = user_manager.get_user_statistics()

        log_security_event('ADMIN_PANEL_ACCESS',
                         username=current_user.username,
                         ip_address=request.remote_addr)

        return render_template('admin.html', users=users, stats=stats)
    except Exception as e:
        error_msg = handle_error_safely(e, "Admin panel loading failed")
        flash(error_msg, 'error')
        return redirect(url_for('dashboard'))

@app.route('/admin/toggle_user/<user_id>', methods=['POST'])
@login_required
@admin_required
def admin_toggle_user(user_id):
    """Toggle user active/inactive status"""
    try:
        success, message = user_manager.toggle_user_status(user_id)

        log_security_event('ADMIN_USER_TOGGLE',
                         username=current_user.username,
                         ip_address=request.remote_addr,
                         details=f"User ID: {user_id}")

        return jsonify({'success': success, 'message': message})
    except Exception as e:
        error_msg = handle_error_safely(e, "User status toggle failed")
        return jsonify({'success': False, 'message': error_msg})

@app.route('/admin/delete_user/<user_id>', methods=['DELETE'])
@login_required
@admin_required
def admin_delete_user(user_id):
    """Delete a user"""
    try:
        success, message = user_manager.delete_user(user_id)

        log_security_event('ADMIN_USER_DELETE',
                         username=current_user.username,
                         ip_address=request.remote_addr,
                         details=f"User ID: {user_id}")

        return jsonify({'success': success, 'message': message})
    except Exception as e:
        error_msg = handle_error_safely(e, "User deletion failed")
        return jsonify({'success': False, 'message': error_msg})

@app.route('/admin/reset_password/<user_id>', methods=['POST'])
@login_required
@admin_required
def admin_reset_password(user_id):
    """Reset user password"""
    try:
        data = request.get_json()
        new_password = data.get('new_password')

        if not new_password:
            return jsonify({'success': False, 'message': 'New password is required'})

        # Validate password strength
        from auth import validate_password_strength
        is_valid, message = validate_password_strength(new_password)
        if not is_valid:
            return jsonify({'success': False, 'message': message})

        # Reset password
        user = user_manager.get_user(user_id)
        if user:
            import bcrypt
            user.password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            user.updated_at = datetime.now().isoformat()
            user_manager._save_users_to_file()

            log_security_event('ADMIN_PASSWORD_RESET',
                             username=current_user.username,
                             ip_address=request.remote_addr,
                             details=f"Reset password for user: {user.username}")

            return jsonify({'success': True, 'message': 'Password reset successfully'})
        else:
            return jsonify({'success': False, 'message': 'User not found'})

    except Exception as e:
        error_msg = handle_error_safely(e, "Password reset failed")
        return jsonify({'success': False, 'message': error_msg})

# Developer Admin Panel - RESTRICTED ACCESS
@app.route('/dev_admin_test')
@login_required
def developer_admin_test():
    """Test route to debug developer admin access"""
    try:
        user_info = {
            'username': current_user.username,
            'role': current_user.role,
            'is_admin': current_user.is_admin(),
            'is_developer_admin': current_user.is_developer_admin() if hasattr(current_user, 'is_developer_admin') else 'Method not found'
        }
        return jsonify(user_info)
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/dev_admin_simple')
@login_required
def developer_admin_simple():
    """Simple test route for developer admin"""
    try:
        if not current_user.is_admin():
            return "Not admin user"

        if current_user.username not in ['admin', 'developer', 'sysadmin']:
            return f"Username '{current_user.username}' not in developer list"

        return f"<h1>Developer Admin Panel Test</h1><p>Welcome {current_user.username}!</p><p>You have developer access.</p>"
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/dev_admin')
@login_required
@limiter.limit("20 per minute")
def developer_admin_panel():
    """Developer/System Admin Panel - STRICT ACCESS CONTROL"""
    try:
        # Check if user has developer admin access
        if not current_user.is_admin():
            flash('Admin access required.', 'error')
            return redirect(url_for('dashboard'))

        # Check if user is in developer list
        if current_user.username not in ['admin', 'developer', 'sysadmin']:
            flash('Developer access required.', 'error')
            return redirect(url_for('dashboard'))

        # Get basic data first
        try:
            users = list(user_manager.get_all_users())
        except Exception as e:
            users = []

        try:
            monitoring_data = user_manager.get_system_monitoring_data()
        except Exception as e:
            monitoring_data = {
                'user_stats': {'total_users': len(users), 'active_users': 0, 'total_predictions': 0, 'total_uploads': 0},
                'system_info': {'error': 'System monitoring unavailable'},
                'recent_activity': [],
                'upload_stats': {'total_uploads': 0, 'total_predictions': 0, 'active_sessions': 0},
                'timestamp': datetime.now().isoformat()
            }

        try:
            security_events = user_manager.get_security_events(limit=50)
        except Exception as e:
            security_events = []

        log_security_event('DEVELOPER_PANEL_VIEW',
                         username=current_user.username,
                         ip_address=request.remote_addr,
                         details='Developer admin panel accessed')

        return render_template('simple_admin.html',
                             users=users)
    except Exception as e:
        error_msg = handle_error_safely(e, "Developer admin panel loading failed")
        log_security_event('DEVELOPER_PANEL_ERROR',
                         username=current_user.username,
                         ip_address=request.remote_addr,
                         details=f'Error: {error_msg}')
        flash(error_msg, 'error')
        return redirect(url_for('dashboard'))

@app.route('/dev_admin/toggle_user/<user_id>', methods=['POST'])
@login_required
@developer_admin_required
def dev_admin_toggle_user(user_id):
    """Developer admin: Toggle user status"""
    try:
        success, message = user_manager.toggle_user_status(user_id)

        log_security_event('DEV_ADMIN_USER_TOGGLE',
                         username=current_user.username,
                         ip_address=request.remote_addr,
                         details=f"Toggled status for user ID: {user_id}")

        return jsonify({'success': success, 'message': message})
    except Exception as e:
        error_msg = handle_error_safely(e, "User status toggle failed")
        return jsonify({'success': False, 'message': error_msg})

@app.route('/dev_admin/delete_user/<user_id>', methods=['DELETE'])
@login_required
@developer_admin_required
def dev_admin_delete_user(user_id):
    """Developer admin: Delete user"""
    try:
        user = user_manager.get_user(user_id)
        if user and user.username == current_user.username:
            return jsonify({'success': False, 'message': 'Cannot delete your own account'})

        success, message = user_manager.delete_user(user_id)

        log_security_event('DEV_ADMIN_USER_DELETE',
                         username=current_user.username,
                         ip_address=request.remote_addr,
                         details=f"Deleted user ID: {user_id}")

        return jsonify({'success': success, 'message': message})
    except Exception as e:
        error_msg = handle_error_safely(e, "User deletion failed")
        return jsonify({'success': False, 'message': error_msg})

@app.route('/dev_admin/reset_password/<user_id>', methods=['POST'])
@login_required
@developer_admin_required
def dev_admin_reset_password(user_id):
    """Developer admin: Reset user password"""
    try:
        data = request.get_json()
        new_password = data.get('new_password')

        if not new_password:
            return jsonify({'success': False, 'message': 'New password is required'})

        # Validate password strength
        from auth import validate_password_strength
        is_valid, message = validate_password_strength(new_password)
        if not is_valid:
            return jsonify({'success': False, 'message': message})

        # Reset password
        user = user_manager.get_user(user_id)
        if user:
            import bcrypt
            user.password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            user.updated_at = datetime.now().isoformat()
            user.login_attempts = 0  # Reset failed attempts
            user.locked_until = None  # Unlock account
            user_manager._save_users_to_file()

            log_security_event('DEV_ADMIN_PASSWORD_RESET',
                             username=current_user.username,
                             ip_address=request.remote_addr,
                             details=f"Reset password for user: {user.username}")

            return jsonify({'success': True, 'message': 'Password reset successfully'})
        else:
            return jsonify({'success': False, 'message': 'User not found'})

    except Exception as e:
        error_msg = handle_error_safely(e, "Password reset failed")
        return jsonify({'success': False, 'message': error_msg})

@app.route('/dev_admin/unlock_user/<user_id>', methods=['POST'])
@login_required
@developer_admin_required
def dev_admin_unlock_user(user_id):
    """Developer admin: Unlock user account"""
    try:
        user = user_manager.get_user(user_id)
        if user:
            user.login_attempts = 0
            user.locked_until = None
            user.updated_at = datetime.now().isoformat()
            user_manager._save_users_to_file()

            log_security_event('DEV_ADMIN_USER_UNLOCK',
                             username=current_user.username,
                             ip_address=request.remote_addr,
                             details=f"Unlocked user: {user.username}")

            return jsonify({'success': True, 'message': 'User account unlocked successfully'})
        else:
            return jsonify({'success': False, 'message': 'User not found'})

    except Exception as e:
        error_msg = handle_error_safely(e, "User unlock failed")
        return jsonify({'success': False, 'message': error_msg})

@app.route('/dev_admin/export_users')
@login_required
@developer_admin_required
def dev_admin_export_users():
    """Developer admin: Export user data"""
    try:
        import csv
        from io import StringIO

        output = StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow(['Username', 'Email', 'Phone', 'Role', 'Status', 'Created', 'Last Login',
                        'Total Logins', 'Total Predictions', 'Total Uploads', 'Failed Attempts'])

        # Write user data
        for user in user_manager.get_all_users():
            writer.writerow([
                user.username,
                user.email or '',
                user.phone or '',
                user.role,
                'Active' if user.is_active else 'Inactive',
                user.created_at[:10] if user.created_at else '',
                user.last_login[:19] if user.last_login else '',
                user.total_logins,
                user.total_predictions,
                user.total_uploads,
                user.login_attempts
            ])

        output.seek(0)

        log_security_event('DEV_ADMIN_DATA_EXPORT',
                         username=current_user.username,
                         ip_address=request.remote_addr,
                         details='User data exported')

        return send_file(
            io.BytesIO(output.getvalue().encode()),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'user_data_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        )

    except Exception as e:
        error_msg = handle_error_safely(e, "Data export failed")
        flash(error_msg, 'error')
        return redirect(url_for('developer_admin_panel'))

def process_batch_predictions(df):
    """Process batch predictions for uploaded file"""
    print(f"🔄 Processing batch predictions for {len(df)} rows")
    print(f"DataFrame columns: {list(df.columns)}")
    print(f"DataFrame dtypes:\n{df.dtypes}")

    results = []

    for idx, row in df.iterrows():
        try:
            print(f"Processing row {idx + 1}/{len(df)}")
            # Prepare data for both models
            data = {
                'step': row['step'],
                'amount': row['amount'],
                'oldbalanceOrg': row['oldbalanceOrg'],
                'newbalanceOrig': row['newbalanceOrig'],
                'type': row['type']
            }

            result_row = {'row': idx + 1}

            # XGBoost prediction with improved feature preparation
            if xgb_model:
                try:
                    features = prepare_features_for_prediction(data)

                    # XGBoost model was trained on engineered features WITHOUT scaling
                    # So we use the features directly without the scaler
                    prediction = xgb_model.predict(features)[0]
                    probability = xgb_model.predict_proba(features)[0][1]

                    # Apply business logic for better accuracy
                    if data['type'] in ['TRANSFER', 'CASH_OUT'] and data['newbalanceOrig'] == 0:
                        probability = min(probability + 0.3, 1.0)

                    if data['amount'] > data['oldbalanceOrg'] * 0.8:
                        probability = min(probability + 0.2, 1.0)

                    if data['amount'] % 1000 == 0 and data['amount'] > 10000:
                        probability = min(probability + 0.1, 1.0)

                    # Recalculate prediction
                    prediction = 1 if probability > 0.5 else 0

                    threat_level, color = calculate_threat_score(probability)

                    result_row.update({
                        'prediction': int(prediction),
                        'probability': float(probability),
                        'threat_level': threat_level,
                        'color': color
                    })
                except Exception as e:
                    print(f"Error in XGBoost prediction for row {idx}: {e}")
                    # Set default values if prediction fails
                    result_row.update({
                        'prediction': 0,
                        'probability': 0.0,
                        'threat_level': 'UNKNOWN',
                        'color': 'gray'
                    })

            # Anomaly detection
            anomaly_features = prepare_features_for_anomaly_detection(data)
            anomaly_score, anomaly_level, anomaly_color, is_anomaly = detect_anomaly(anomaly_features, data)

            if anomaly_score is not None:
                result_row.update({
                    'anomaly_score': float(anomaly_score),
                    'anomaly_level': anomaly_level,
                    'anomaly_color': anomaly_color,
                    'is_anomaly': is_anomaly
                })

            results.append(result_row)
            print(f"✅ Row {idx + 1} processed successfully")
        except Exception as e:
            print(f"❌ Error processing row {idx + 1}: {e}")
            print(f"Row data: {row.to_dict()}")
            # Add a failed result entry
            result_row = {
                'row': idx + 1,
                'prediction': 0,
                'probability': 0.0,
                'threat_level': 'ERROR',
                'color': 'gray',
                'anomaly_score': 0.0,
                'anomaly_level': 'ERROR',
                'anomaly_color': 'gray',
                'is_anomaly': False
            }
            results.append(result_row)
            continue

    print(f"✅ Batch processing completed: {len(results)} results generated")
    return results

def create_sample_dataset():
    """Create comprehensive sample dataset for download"""
    sample_data = {
        'step': [1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        'type': ['PAYMENT', 'PAYMENT', 'DEBIT', 'TRANSFER', 'CASH_OUT', 'PAYMENT', 'DEBIT',
                'TRANSFER', 'CASH_OUT', 'PAYMENT', 'TRANSFER', 'CASH_OUT', 'PAYMENT',
                'DEBIT', 'TRANSFER', 'CASH_OUT', 'PAYMENT', 'DEBIT', 'TRANSFER', 'CASH_OUT', 'PAYMENT'],
        'amount': [9839.64, 1864.28, 2500.0, 181.0, 181.0, 11668.14, 1000.0, 215310.30,
                  311685.89, 7817.71, 6267.0, 54295.32, 7107.77, 500.0, 850002.52,
                  850002.52, 4024.36, 750.0, 1561932.86, 1561932.86, 2000.0],
        'nameOrig': ['C1231006815', 'C1666544295', 'C1111111111', 'C1305486145', 'C840083671',
                    'C2048537720', 'C2222222222', 'C1313267530', 'C1994759586', 'C90045638',
                    'C932583850', 'C1872553021', 'C154988899', 'C3333333333', 'C1566511282',
                    'C1110939687', 'C1265012928', 'C4444444444', 'C1902850431', 'C1110939687', 'C5555555555'],
        'oldbalanceOrg': [170136.0, 21249.0, 25000.0, 181.0, 181.0, 41554.0, 15000.0, 215310.30,
                         311685.89, 53860.0, 6267.0, 54295.32, 183195.0, 8000.0, 850002.52,
                         850002.52, 10000.0, 12000.0, 1561932.86, 1561932.86, 20000.0],
        'newbalanceOrig': [160296.36, 19384.72, 22500.0, 0.0, 0.0, 29885.86, 14000.0, 0.0,
                          0.0, 46042.29, 0.0, 0.0, 176087.23, 7500.0, 0.0,
                          0.0, 5975.64, 11250.0, 0.0, 0.0, 18000.0],
        'nameDest': ['M1979787155', 'M2044282225', '', 'C553264065', 'C38997010', 'M1230701703',
                    '', 'C1560014080', 'C932583850', 'M573487274', 'C1902850431', 'C1618352388',
                    'M408069119', '', 'C1110939687', 'C1902850431', 'M1176932104', '',
                    'C1110939687', 'C1902850431', 'M5555555555'],
        'oldbalanceDest': [0.0, 0.0, 0.0, 0.0, 21182.0, 0.0, 0.0, 705.0, 6267.0, 0.0,
                          1189684.65, 0.0, 0.0, 0.0, 0.0, 339682.13, 0.0, 0.0,
                          0.0, 0.0, 0.0],
        'newbalanceDest': [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 216015.30, 317952.89, 0.0,
                          1507637.54, 54295.32, 0.0, 0.0, 0.0, 1189684.65, 0.0, 0.0,
                          0.0, 1561932.86, 0.0],
        'isFraud': [0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0],
        'isFlaggedFraud': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    }

    return pd.DataFrame(sample_data)

def download_csv_format(df):
    """Download dataset in CSV format"""
    output = io.StringIO()
    df.to_csv(output, index=False)
    output.seek(0)

    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=fraud_detection_sample.csv'
    response.headers['Content-Type'] = 'text/csv'
    return response

def download_excel_format(df):
    """Download dataset in Excel format"""
    output = io.BytesIO()

    # Create Excel writer with formatting
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        # Write main data
        df.to_excel(writer, sheet_name='Fraud_Detection_Data', index=False)

        # Get the workbook and worksheet
        workbook = writer.book
        worksheet = writer.sheets['Fraud_Detection_Data']

        # Add formatting
        from openpyxl.styles import Font, PatternFill, Alignment

        # Header formatting
        header_font = Font(bold=True, color='FFFFFF')
        header_fill = PatternFill(start_color='366092', end_color='366092', fill_type='solid')

        # Apply header formatting
        for cell in worksheet[1]:
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = Alignment(horizontal='center')

        # Auto-adjust column widths
        for column in worksheet.columns:
            max_length = 0
            column_letter = column[0].column_letter
            for cell in column:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except:
                    pass
            adjusted_width = min(max_length + 2, 20)
            worksheet.column_dimensions[column_letter].width = adjusted_width

        # Add a summary sheet
        summary_data = {
            'Metric': ['Total Transactions', 'Fraudulent Transactions', 'Legitimate Transactions',
                      'Fraud Rate (%)', 'Average Transaction Amount', 'Max Transaction Amount'],
            'Value': [
                len(df),
                len(df[df['isFraud'] == 1]),
                len(df[df['isFraud'] == 0]),
                f"{(len(df[df['isFraud'] == 1]) / len(df) * 100):.2f}%",
                f"${df['amount'].mean():.2f}",
                f"${df['amount'].max():.2f}"
            ]
        }
        summary_df = pd.DataFrame(summary_data)
        summary_df.to_excel(writer, sheet_name='Summary', index=False)

        # Format summary sheet
        summary_sheet = writer.sheets['Summary']
        for cell in summary_sheet[1]:
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = Alignment(horizontal='center')

    output.seek(0)

    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=fraud_detection_sample.xlsx'
    response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    return response

def download_pdf_format(df):
    """Download dataset in PDF format"""
    output = io.BytesIO()

    # Create PDF document
    doc = SimpleDocTemplate(output, pagesize=A4, topMargin=0.5*inch, bottomMargin=0.5*inch)
    story = []

    # Get styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=16,
        spaceAfter=30,
        alignment=1,  # Center alignment
        textColor=colors.darkblue
    )

    # Add title
    title = Paragraph("Fraud Detection Sample Dataset", title_style)
    story.append(title)
    story.append(Spacer(1, 12))

    # Add summary information
    summary_style = styles['Normal']
    summary_text = f"""
    <b>Dataset Summary:</b><br/>
    • Total Transactions: {len(df)}<br/>
    • Fraudulent Transactions: {len(df[df['isFraud'] == 1])}<br/>
    • Legitimate Transactions: {len(df[df['isFraud'] == 0])}<br/>
    • Fraud Rate: {(len(df[df['isFraud'] == 1]) / len(df) * 100):.2f}%<br/>
    • Average Amount: ${df['amount'].mean():.2f}<br/>
    • Date Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>
    """

    summary_para = Paragraph(summary_text, summary_style)
    story.append(summary_para)
    story.append(Spacer(1, 20))

    # Prepare data for table (first 15 rows to fit on page)
    display_df = df.head(15)

    # Create table data
    table_data = []

    # Add headers
    headers = ['Step', 'Type', 'Amount', 'Old Balance', 'New Balance', 'Is Fraud']
    table_data.append(headers)

    # Add data rows
    for _, row in display_df.iterrows():
        table_row = [
            str(row['step']),
            str(row['type']),
            f"${row['amount']:,.2f}",
            f"${row['oldbalanceOrg']:,.2f}",
            f"${row['newbalanceOrig']:,.2f}",
            'Yes' if row['isFraud'] == 1 else 'No'
        ]
        table_data.append(table_row)

    # Create table
    table = Table(table_data, repeatRows=1)

    # Style the table
    table.setStyle(TableStyle([
        # Header styling
        ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),

        # Data styling
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),

        # Fraud highlighting
        ('BACKGROUND', (-1, 1), (-1, -1), colors.lightcoral),  # Fraud column
    ]))

    # Highlight fraud rows
    for i, (_, row) in enumerate(display_df.iterrows(), 1):
        if row['isFraud'] == 1:
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, i), (-1, i), colors.mistyrose),
            ]))

    story.append(table)
    story.append(Spacer(1, 20))

    # Add footer note
    footer_text = f"""
    <b>Note:</b> This PDF shows the first 15 transactions from the complete dataset.
    Download the CSV or Excel format for the complete dataset with all {len(df)} transactions.
    <br/><br/>
    <b>Column Descriptions:</b><br/>
    • <b>Step:</b> Time step of the transaction<br/>
    • <b>Type:</b> Transaction type (PAYMENT, TRANSFER, CASH_OUT, DEBIT)<br/>
    • <b>Amount:</b> Transaction amount in USD<br/>
    • <b>Old Balance:</b> Account balance before transaction<br/>
    • <b>New Balance:</b> Account balance after transaction<br/>
    • <b>Is Fraud:</b> Whether the transaction is fraudulent (Yes/No)<br/>
    """

    footer_para = Paragraph(footer_text, styles['Normal'])
    story.append(footer_para)

    # Build PDF
    doc.build(story)
    output.seek(0)

    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=fraud_detection_sample.pdf'
    response.headers['Content-Type'] = 'application/pdf'
    return response

@app.route('/api/live_data')
def live_data():
    """API endpoint for live visualization data"""
    # Simulate live data
    data = {
        'timestamp': datetime.now().strftime('%H:%M:%S'),
        'fraud_count': np.random.randint(0, 10),
        'total_transactions': np.random.randint(100, 1000),
        'threat_levels': {
            'critical': np.random.randint(0, 5),
            'high': np.random.randint(0, 15),
            'medium': np.random.randint(0, 25),
            'low': np.random.randint(0, 50)
        }
    }
    return jsonify(data)

@app.route('/visualizations')
def visualizations():
    return render_template('visualizations.html')



@app.route('/download_sample')
def download_sample():
    """Download sample dataset for testing - default CSV format"""
    return download_sample_format('csv')

@app.route('/download_sample/<format_type>')
def download_sample_format(format_type):
    """Download sample dataset in specified format"""
    try:
        # Create sample data
        sample_data = create_sample_dataset()

        if format_type.lower() == 'csv':
            return download_csv_format(sample_data)
        elif format_type.lower() in ['excel', 'xlsx', 'xls']:
            return download_excel_format(sample_data)
        elif format_type.lower() == 'pdf':
            return download_pdf_format(sample_data)
        else:
            flash('Invalid file format requested', 'error')
            return redirect(url_for('upload_file'))

    except Exception as e:
        flash(f'Error downloading sample file: {str(e)}', 'error')
        return redirect(url_for('upload_file'))

@app.route('/download_test_pdf')
def download_test_pdf():
    """Download test PDF for upload testing"""
    try:
        return send_file('static/test_fraud_data.pdf',
                        as_attachment=True,
                        download_name='test_fraud_data.pdf',
                        mimetype='application/pdf')
    except Exception as e:
        flash(f'Error downloading test PDF: {str(e)}', 'error')
        return redirect(url_for('upload_file'))

if __name__ == '__main__':
    app.run(debug=True)