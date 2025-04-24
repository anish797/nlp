from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import os
import pickle
import pandas as pd
import numpy as np
from datetime import datetime
import json
import tempfile
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
from io import BytesIO
import base64

# Import custom modules
from packet_analyser import analyze_packet_file
from report_analyser import analyze_report_file
from log_analyser import analyze_ssh_logs, analyze_linux_logs, analyze_bgl_logs
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Add this to your app.py file
import json
import numpy as np

class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, pd.Timestamp):
            return str(obj)
        return super(NumpyEncoder, self).default(obj)

app.json_encoder = NumpyEncoder

# Ensure upload directory exists
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    
    file = request.files['file']
    analysis_type = request.form.get('analysis_type')
    log_type = request.form.get('log_type')
    
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    
    if file:
        # Create a secure filename
        filename = secure_filename(file.filename)
        
        # Create a directory for uploads if it doesn't exist
        upload_dir = os.path.join(app.config['UPLOAD_FOLDER'])
        os.makedirs(upload_dir, exist_ok=True)
        
        # Save the file
        file_path = os.path.join(upload_dir, filename)
        file.save(file_path)
        
        try:
            result = None
            plot_data = None
            if analysis_type == 'packet':
                result = analyze_packet_file(file_path)
            elif analysis_type == 'report':
                result = analyze_report_file(file_path)
            elif analysis_type == 'log':
                if log_type == 'ssh':
                    result, plot_data = analyze_ssh_logs(file_path)
                elif log_type == 'linux':
                    result, plot_data = analyze_linux_logs(file_path)
                elif log_type == 'bgl':
                    result, plot_data = analyze_bgl_logs(file_path)
                else:
                    flash('Invalid log type')
                    return redirect(url_for('index'))
            else:
                flash('Invalid analysis type')
                return redirect(url_for('index'))
            
            # Clean up - remove the file after analysis
            os.remove(file_path)
            
            # Return results
            if result:
                return render_template('results.html', 
                                       result=result, 
                                       plot_data=plot_data,
                                       analysis_type=analysis_type,
                                       log_type=log_type if analysis_type == 'log' else None)
            else:
                flash('Analysis failed. No results returned.')
                return redirect(url_for('index'))
        
        except Exception as e:
            # Clean up in case of error
            if os.path.exists(file_path):
                os.remove(file_path)
            
            flash(f'Error during analysis: {str(e)}')
            return redirect(url_for('index'))
    
    return redirect(url_for('index'))

@app.template_filter('tojson_safe')
def tojson_safe_filter(obj):
    return json.dumps(obj, cls=NumpyEncoder)

if __name__ == '__main__':
    app.run(debug=True)