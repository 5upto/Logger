import matplotlib
matplotlib.use('Agg')  # Use non-GUI backend for server

from flask import Flask, request, render_template, redirect, url_for, send_file
from werkzeug.utils import secure_filename
import os
import re
from datetime import datetime
import io
import matplotlib.pyplot as plt
import base64
import json

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit

# In-memory storage for parsed logs
parsed_logs = []

LOG_LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']

LOG_PATTERNS = [
    re.compile(r'^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - (?P<level>\w+) - (?P<message>.*)$'),
    re.compile(r'^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}), (?P<level>\w+)\s+(?P<source>\S+)\s+(?P<message>.*)$'),
    re.compile(r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z) (?P<level>\w+) (?P<message>.*)$'),
]

def parse_log_line(line):
    for pattern in LOG_PATTERNS:
        match = pattern.match(line)
        if match:
            timestamp_str = match.group('timestamp')
            level = match.group('level').upper() if 'level' in match.groupdict() else 'INFO'
            message = match.group('message')
            try:
                # Try multiple datetime formats
                for fmt in ['%Y-%m-%d %H:%M:%S,%f', '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%d %H:%M:%S']:
                    try:
                        timestamp = datetime.strptime(timestamp_str, fmt)
                        break
                    except ValueError:
                        timestamp = None
                else:
                    timestamp = None
            except Exception:
                timestamp = None
            return {'timestamp': timestamp, 'level': level, 'message': message}
    # Fallback if no pattern matched
    return {'timestamp': None, 'level': 'INFO', 'message': line}

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    global parsed_logs
    if request.method == 'POST':
        if 'logfile' not in request.files:
            return redirect(request.url)
        file = request.files['logfile']
        if file.filename == '':
            return redirect(request.url)
        if file and file.filename.endswith('.log'):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file.save(filepath)
            # Parse the log file
            parsed_logs = []
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    parsed = parse_log_line(line.strip())
                    if parsed:
                        parsed_logs.append(parsed)
            # Save parsed logs to JSON file
            json_path = os.path.join(app.config['UPLOAD_FOLDER'], filename + '.json')
            with open(json_path, 'w', encoding='utf-8') as jf:
                json.dump(parsed_logs, jf, default=str)
            return redirect(url_for('view_logs'))
    return render_template('upload.html')

@app.route('/logs')
def view_logs():
    global parsed_logs

    # Filters
    level_filter = request.args.get('level', '')
    start_time_str = request.args.get('start_time', '')
    end_time_str = request.args.get('end_time', '')

    filtered_logs = parsed_logs

    if level_filter and level_filter in LOG_LEVELS:
        filtered_logs = [log for log in filtered_logs if log['level'] == level_filter]

    try:
        if start_time_str:
            start_time = datetime.strptime(start_time_str, '%Y-%m-%dT%H:%M')
            filtered_logs = [log for log in filtered_logs if log['timestamp'] and log['timestamp'] >= start_time]
        if end_time_str:
            end_time = datetime.strptime(end_time_str, '%Y-%m-%dT%H:%M')
            filtered_logs = [log for log in filtered_logs if log['timestamp'] and log['timestamp'] <= end_time]
    except ValueError:
        pass

    # Metrics
    level_counts = {level: 0 for level in LOG_LEVELS}
    for log in filtered_logs:
        if log['level'] in level_counts:
            level_counts[log['level']] += 1

    # Graph: log counts by level
    fig, ax = plt.subplots()
    ax.bar(level_counts.keys(), level_counts.values(), color='skyblue')
    ax.set_title('Log Counts by Level')
    ax.set_xlabel('Log Level')
    ax.set_ylabel('Count')

    img = io.BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    graph_url = base64.b64encode(img.getvalue()).decode('utf8')
    plt.close(fig)

    return render_template('logs.html', logs=filtered_logs, levels=LOG_LEVELS, level_filter=level_filter,
                           start_time=start_time_str, end_time=end_time_str, level_counts=level_counts, graph_url=graph_url)

@app.route('/download_report')
def download_report():
    global parsed_logs
    if not parsed_logs:
        return "No parsed logs available to download.", 404
    # Convert datetime objects to string for JSON serialization
    logs_to_download = []
    for log in parsed_logs:
        log_copy = log.copy()
        if log_copy['timestamp']:
            log_copy['timestamp'] = log_copy['timestamp'].strftime('%Y-%m-%d %H:%M:%S.%f')
        logs_to_download.append(log_copy)
    json_data = json.dumps(logs_to_download, indent=2)
    buffer = io.BytesIO(json_data.encode('utf-8'))
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name='parsed_logs.json', mimetype='application/json')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
