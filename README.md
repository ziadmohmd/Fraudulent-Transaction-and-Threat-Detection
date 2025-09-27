# Fraudulent Transaction and Threat Detection

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0.0-lightgrey.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A comprehensive web-based fraud detection system that uses machine learning to identify fraudulent transactions in real-time. Built with Flask, featuring advanced ML models, secure authentication, and intuitive dashboards.

## 🚀 Features

### Core Functionality
- **Real-time Fraud Detection**: Single transaction analysis using XGBoost and Isolation Forest models
- **Batch Processing**: Upload CSV, Excel, or PDF files for bulk fraud analysis
- **Anomaly Detection**: Advanced outlier detection using multiple ML algorithms
- **Interactive Visualizations**: Real-time charts and graphs for fraud patterns
- **PDF Processing**: Extract tabular data from PDF documents for analysis

### Security & Authentication
- **Secure User Authentication**: Flask-Login with bcrypt password hashing
- **Role-based Access Control**: Admin and regular user roles
- **Rate Limiting**: Flask-Limiter to prevent abuse
- **CSRF Protection**: Flask-WTF for secure forms
- **Input Validation**: Comprehensive sanitization and validation
- **Security Logging**: Detailed audit trails for all activities

### Admin Features
- **User Management**: Create, disable, reset passwords, and delete users
- **System Monitoring**: Real-time CPU, memory, and disk usage tracking
- **Security Events**: Monitor failed logins, unauthorized access attempts
- **Activity Dashboard**: Live user activity and system statistics
- **Developer Admin Panel**: Restricted system administration interface

### Data Processing
- **Multiple File Formats**: Support for CSV, Excel (.xlsx/.xls), and PDF files
- **Data Validation**: Automatic column mapping and type conversion
- **Sample Datasets**: Downloadable test data in multiple formats
- **Export Capabilities**: Generate reports in CSV, Excel, and PDF formats

## 🛠️ Technology Stack

- **Backend**: Flask 3.0.0, Python 3.8+
- **Machine Learning**: XGBoost, Scikit-learn, Isolation Forest
- **Data Processing**: Pandas, NumPy
- **Visualization**: Plotly
- **Security**: Flask-Login, Flask-WTF, Flask-Limiter, bcrypt
- **PDF Processing**: tabula-py, pdfplumber, PyPDF2, reportlab
- **Database**: JSON file-based user storage (easily extensible to SQL databases)

## 📋 Prerequisites

- Python 3.8 or higher
- pip package manager
- Virtual environment (recommended)

## 🚀 Installation

1. **Clone the repository** (if applicable) or navigate to the project directory

2. **Create a virtual environment**:
   ```bash
   python -m venv myenv
   ```

3. **Activate the virtual environment**:
   - Windows:
     ```bash
     myenv\Scripts\activate
     ```
   - Linux/Mac:
     ```bash
     source myenv/bin/activate
     ```

4. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

5. **Run the application**:
   ```bash
   python run_app.py
   ```

   Or directly:
   ```bash
   python app.py
   ```

6. **Access the application**:
   - Main Dashboard: http://127.0.0.1:5000/
   - Login: http://127.0.0.1:5000/login
   - Register: http://127.0.0.1:5000/register

## 📖 Usage

### For Regular Users

1. **Register/Login**: Create an account or log in with existing credentials
2. **Single Prediction**: Use the predict page to analyze individual transactions
3. **Batch Upload**: Upload CSV/Excel/PDF files for bulk analysis
4. **View Results**: See fraud probabilities, threat levels, and explanations
5. **Download Samples**: Get sample datasets to test the system

### For Administrators

1. **Admin Panel**: Access via `/admin` (admin role required)
2. **User Management**: View, enable/disable, reset passwords, delete users
3. **System Monitoring**: Monitor system performance and security events

### For Developers

1. **Developer Admin Panel**: Access via `/dev_admin` (restricted access)
2. **System Oversight**: Complete system monitoring and control
3. **Security Monitoring**: Real-time security event tracking
4. **User Data Export**: Export comprehensive user and activity data

## 📁 Project Structure

```
FraudShield/
├── app.py                 # Main Flask application
├── auth.py                # Authentication and user management
├── forms.py               # WTForms for secure form handling
├── run_app.py            # Application launcher
├── requirements.txt       # Python dependencies
├── DEVELOPER_ADMIN_DOCUMENTATION.md  # Developer docs
├── models/               # Pre-trained ML models
│   ├── model_xgb.pkl
│   ├── iso_forest.pkl
│   └── scaler.pkl
├── templates/            # HTML templates
│   ├── base.html
│   ├── dashboard.html
│   ├── login.html
│   └── ...
├── static/               # Static files (CSS, JS, images)
├── uploads/              # Uploaded files directory
├── Sample_datasets/      # Sample data for testing
├── data/                 # Training data
├── Code/                 # Jupyter notebooks for model development
└── myenv/               # Virtual environment (created during setup)
```

## 🔧 Configuration

### Environment Variables
Create a `.env` file in the root directory:

```env
SECRET_KEY=your-secret-key-here
LOG_LEVEL=INFO
LOG_FILE=fraud_detection.log
DEFAULT_RATE_LIMIT=100 per hour
ALLOWED_EXTENSIONS=csv,xlsx,xls,pdf
```

### Security Settings
- **Session Timeout**: 1 hour
- **Rate Limits**: Configurable per endpoint
- **Password Requirements**: Minimum 8 characters, complexity validation
- **File Upload Limits**: 1000MB max, secure filename handling

## 🤖 Machine Learning Models

### XGBoost Classifier
- **Purpose**: Primary fraud detection model
- **Features**: Engineered features including transaction type, balance changes, zero balance flags
- **Performance**: High accuracy on imbalanced datasets

### Isolation Forest
- **Purpose**: Unsupervised anomaly detection
- **Features**: Raw transaction features for outlier identification
- **Advantages**: No need for labeled data, effective for novel fraud patterns

### Feature Engineering
- Transaction type one-hot encoding
- Balance change ratios
- Zero balance indicators
- Round amount detection
- Business logic rules

## 📊 API Endpoints

### Public Endpoints
- `GET /` - Landing page
- `GET /intro` - Introduction page
- `GET /login` - User login
- `POST /login` - Process login
- `GET /register` - User registration
- `POST /register` - Process registration

### Authenticated Endpoints
- `GET /dashboard` - User dashboard
- `GET /predict` - Single prediction form
- `POST /predict` - Process single prediction
- `GET /upload` - File upload form
- `POST /upload` - Process file upload
- `GET /visualizations` - Data visualizations

### Admin Endpoints
- `GET /admin` - Admin panel
- `POST /admin/toggle_user/<user_id>` - Toggle user status
- `DELETE /admin/delete_user/<user_id>` - Delete user
- `POST /admin/reset_password/<user_id>` - Reset password

### Developer Endpoints (Restricted)
- `GET /dev_admin` - Developer admin panel
- `POST /dev_admin/toggle_user/<user_id>` - Developer user management
- `DELETE /dev_admin/delete_user/<user_id>` - Developer user deletion
- `POST /dev_admin/reset_password/<user_id>` - Developer password reset
- `GET /dev_admin/export_users` - Export user data

## 🔒 Security Features

### Authentication & Authorization
- Secure password hashing with bcrypt
- Session management with Flask-Login
- Role-based access control (user/admin/developer)
- CSRF protection on all forms

### Input Validation & Sanitization
- Comprehensive input sanitization
- File type and content validation
- SQL injection prevention
- XSS protection

### Rate Limiting & Monitoring
- Configurable rate limits per endpoint
- Security event logging
- Failed attempt tracking
- Account lockout protection

### Data Protection
- Secure file upload handling
- Error message sanitization
- Sensitive data masking
- Audit trail logging

## 📈 Performance & Scalability

### Current Capabilities
- **Concurrent Users**: Supports multiple simultaneous users
- **File Processing**: Handles large CSV/Excel files efficiently
- **Real-time Predictions**: Sub-second response times
- **Memory Efficient**: Optimized data processing pipelines

### Extensibility
- Modular architecture for easy feature addition
- Database abstraction for scaling to SQL databases
- API-ready for integration with other systems
- Container-ready for deployment

## 🧪 Testing

### Sample Data
The system includes sample datasets for testing:
- `Sample_datasets/Fraud_Fraudulent_sample_20.csv` - Fraudulent transactions
- `Sample_datasets/Non_Fraudulent_sample_20.csv` - Legitimate transactions
- `Sample_datasets/sample_10random.csv` - Mixed sample data

### Test Files
- `static/test_fraud_data.pdf` - PDF test file
- `comprehensive_test.csv` - Comprehensive test dataset



### Development Guidelines
- Follow PEP 8 style guidelines
- Add tests for new features
- Update documentation
- Ensure security best practices

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with Flask web framework
- Machine learning models trained on synthetic financial data
- Security features inspired by industry best practices
- UI/UX designed for usability and security

## 📞 Support

For support and questions:
- Check the [Developer Documentation](DEVELOPER_ADMIN_DOCUMENTATION.md)
- Review the security logs for troubleshooting
- Contact system administrators for access issues

---

**⚠️ Security Notice**: This system handles sensitive financial data. Ensure proper security measures are in place before deployment in production environments.

