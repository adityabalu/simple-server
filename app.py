import os
import sys
import logging
from flask import Flask, request, render_template, send_file, abort, jsonify, session, redirect, url_for
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit
import time
import eventlet
import uuid
import traceback

eventlet.monkey_patch()

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For session management
socketio = SocketIO(app, async_mode='eventlet', logger=True, engineio_logger=True)
app.config['UPLOAD_FOLDER'] = '/app/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 * 1024  # 16 GB max file size

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

def process_upload(file_path, content_length, task_id):
    try:
        bytes_received = 0
        start_time = time.time()

        with open(file_path, 'wb') as f:
            while bytes_received < content_length:
                chunk = yield
                if not chunk:
                    break
                f.write(chunk)
                bytes_received += len(chunk)
                progress = min(int((bytes_received / content_length) * 100), 100)
                elapsed_time = time.time() - start_time
                upload_speed = bytes_received / elapsed_time / 1024 / 1024 if elapsed_time > 0 else 0
                socketio.emit('upload_progress', {
                    'task_id': task_id,
                    'progress': progress,
                    'speed': f"{upload_speed:.2f} MB/s"
                })

        logging.info(f"File upload completed: {file_path}, task_id: {task_id}")
        socketio.emit('upload_complete', {
            'task_id': task_id,
            'message': 'File uploaded successfully',
            'download_link': f'/download/{os.path.basename(file_path)}'
        })
        yield True  # Indicate successful completion
    except Exception as e:
        logging.error(f"Error during file processing: {str(e)}")
        logging.error(traceback.format_exc())
        socketio.emit('upload_error', {
            'task_id': task_id,
            'error': str(e)
        })
        yield False  # Indicate failure

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        try:
            filename = secure_filename(request.headers.get('X-Filename', ''))
            if not filename:
                logging.error("No filename provided in headers")
                return jsonify({'error': 'No filename provided'}), 400

            password = request.headers.get('X-Password', '')
            if not password:
                logging.error("No password provided in headers")
                return jsonify({'error': 'No password provided'}), 400

            content_length = request.headers.get('Content-Length')
            if not content_length:
                logging.error("No Content-Length header provided")
                return jsonify({'error': 'No Content-Length header'}), 400

            content_length = int(content_length)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            task_id = str(uuid.uuid4())

            logging.info(f"Starting file upload: {filename}, task_id: {task_id}")

            processor = process_upload(file_path, content_length, task_id)
            next(processor)  # Prime the coroutine

            chunk_size = 1024 * 1024  # 1MB chunks
            for chunk in iter(lambda: request.stream.read(chunk_size), b''):
                processor.send(chunk)

            try:
                success = next(processor)
            except StopIteration:
                success = True  # Assume success if StopIteration is raised

            if success:
                hashed_password = generate_password_hash(password)
                with open(f"{file_path}.pwd", 'w') as pwd_file:
                    pwd_file.write(hashed_password)
                return jsonify({'message': 'Upload processed successfully', 'task_id': task_id})
            else:
                return jsonify({'error': 'Upload failed during processing'}), 500

        except Exception as e:
            logging.error(f"Error during file upload: {str(e)}")
            logging.error(traceback.format_exc())
            return jsonify({'error': str(e)}), 500

    return render_template('upload.html')

@app.route('/download/<filename>')
def download_file(filename):
    if 'authenticated_' + filename not in session or not session['authenticated_' + filename]:
        return redirect(url_for('password_prompt', filename=filename))
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(file_path):
        abort(404)
    
    # Clear the authentication flag after successful download
    session.pop('authenticated_' + filename, None)
    
    return send_file(file_path, as_attachment=True)

@app.route('/password_prompt/<filename>')
def password_prompt(filename):
    return render_template('password_prompt.html', filename=filename)

@app.route('/check_password/<filename>', methods=['POST'])
def check_password(filename):
    password = request.form['password']
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    pwd_file_path = f"{file_path}.pwd"
    
    if not os.path.exists(pwd_file_path):
        abort(404)
    
    with open(pwd_file_path, 'r') as pwd_file:
        hashed_password = pwd_file.read().strip()
    
    if check_password_hash(hashed_password, password):
        session['authenticated_' + filename] = True
        return redirect(url_for('download_file', filename=filename))
    else:
        return render_template('password_prompt.html', filename=filename, error="Incorrect password. Please try again.")

@socketio.on('connect')
def handle_connect():
    logging.info('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    logging.info('Client disconnected')

if __name__ == '__main__':
    logging.info("Starting the application")
    socketio.run(app, host='0.0.0.0', port=80, debug=True)