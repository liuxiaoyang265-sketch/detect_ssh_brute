import os
import uuid
import threading
from flask import Flask, request, jsonify, send_file, render_template, abort
from werkzeug.utils import secure_filename
from auth_analyzer import analyze_file

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), 'uploads')
RESULT_DIR = os.path.join(os.path.dirname(__file__), 'results')
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(RESULT_DIR, exist_ok=True)
APP_TOKEN = os.environ.get('APP_TOKEN')

TASKS = {}

def require_token():
    if not APP_TOKEN:
        return True
    t = request.form.get('token') or request.args.get('token') or request.headers.get('X-Token')
    if t != APP_TOKEN:
        abort(403)
    return True

def worker(task_id, file_path, params):
    def on_progress(p):
        TASKS[task_id]['progress'] = p
    TASKS[task_id]['status'] = 'running'
    res = analyze_file(file_path, on_progress, params)
    TASKS[task_id]['result'] = res
    TASKS[task_id]['status'] = 'done'

@app.route('/')
def index():
    return render_template('index.html', has_token=bool(APP_TOKEN))

@app.route('/analyze', methods=['POST'])
def analyze():
    require_token()
    if 'file' not in request.files:
        return jsonify({'error': 'no_file'}), 400
    f = request.files['file']
    if f.filename == '':
        return jsonify({'error': 'empty_filename'}), 400
    filename = secure_filename(f.filename)
    if not filename.lower().endswith(('.log', '.txt')):
        return jsonify({'error': 'invalid_type'}), 400
    task_id = uuid.uuid4().hex
    save_path = os.path.join(UPLOAD_DIR, task_id + '_' + filename)
    f.save(save_path)
    params = {
        'count': 5,
        'minutes': 5,
        'limit': 100,
    }
    TASKS[task_id] = {'status': 'queued', 'progress': 0, 'file': save_path, 'result': None}
    th = threading.Thread(target=worker, args=(task_id, save_path, params), daemon=True)
    th.start()
    return jsonify({'task_id': task_id})

@app.route('/progress/<task_id>')
def progress(task_id):
    t = TASKS.get(task_id)
    if not t:
        return jsonify({'error': 'not_found'}), 404
    return jsonify({'status': t['status'], 'progress': t['progress']})

@app.route('/result/<task_id>')
def result(task_id):
    require_token()
    t = TASKS.get(task_id)
    if not t:
        return jsonify({'error': 'not_found'}), 404
    if t['status'] != 'done':
        return jsonify({'error': 'not_ready'}), 409
    return jsonify(t['result'])

@app.route('/download/log/<task_id>')
def download_log(task_id):
    require_token()
    t = TASKS.get(task_id)
    if not t:
        return jsonify({'error': 'not_found'}), 404
    return send_file(t['file'], as_attachment=True)

@app.route('/download/json/<task_id>')
def download_json(task_id):
    require_token()
    t = TASKS.get(task_id)
    if not t or t['status'] != 'done':
        return jsonify({'error': 'not_ready'}), 409
    out = os.path.join(RESULT_DIR, task_id + '.json')
    import json
    with open(out, 'w', encoding='utf-8') as wf:
        json.dump(t['result'], wf, ensure_ascii=False, indent=2)
    return send_file(out, as_attachment=True)

@app.route('/download/csv/<task_id>')
def download_csv(task_id):
    require_token()
    t = TASKS.get(task_id)
    if not t or t['status'] != 'done':
        return jsonify({'error': 'not_ready'}), 409
    out = os.path.join(RESULT_DIR, task_id + '.csv')
    import csv
    with open(out, 'w', newline='', encoding='utf-8') as wf:
        w = csv.writer(wf)
        w.writerow(['time', 'ip', 'user', 'port'])
        for e in t['result'].get('accepted_events', []):
            w.writerow([e['timestamp'], e['ip'], e['user'], e['port']])
    return send_file(out, as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', '5000')), debug=False)
