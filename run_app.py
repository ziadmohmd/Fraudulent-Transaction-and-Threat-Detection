#!/usr/bin/env python3
"""
Simple launcher for the Flask fraud detection app
"""

import os
import sys

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    print("Loading Flask fraud detection app...")
    
    # Import and run the app
    from app import app
    
    print("Models loaded successfully!")
    print("Starting Flask development server...")
    print("=" * 50)
    print("🚀 FRAUD DETECTION SYSTEM")
    print("=" * 50)
    print("📊 Dashboard: http://127.0.0.1:5000/")
    print("🔍 Single Prediction: http://127.0.0.1:5000/predict")
    print("📁 Batch Upload: http://127.0.0.1:5000/upload")
    print("📈 Visualizations: http://127.0.0.1:5000/visualizations")
    print("=" * 50)
    print("Press Ctrl+C to stop the server")
    print("=" * 50)
    
    # Run the Flask app
    app.run(
        debug=True,
        host='127.0.0.1',
        port=5000,
        use_reloader=False  # Disable reloader to avoid issues
    )
    
except ImportError as e:
    print(f"❌ Import Error: {e}")
    print("Make sure all required packages are installed:")
    print("pip install flask pandas numpy scikit-learn xgboost plotly werkzeug openpyxl")
    
except Exception as e:
    print(f"❌ Error starting app: {e}")
    import traceback
    traceback.print_exc()
