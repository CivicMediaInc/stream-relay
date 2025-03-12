#!/usr/bin/env python3

import json
import os
import threading
from flask import Flask, render_template, request, jsonify, Response, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import time
from logger import StreamLogger

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Global configuration
CONFIG_FILE = 'config/config.json'
USERS_FILE = 'config/users.json'
active_streams = {}
logger = StreamLogger()

def create_initial_admin():
    if not os.path.exists(USERS_FILE):
        users = {
            'users': {
                'admin': {
                    'password': generate_password_hash('admin123'),
                    'role': 'admin'
                }
            }
        }
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=4)

# Create initial admin user if users.json doesn't exist
create_initial_admin()

class User(UserMixin):
    def __init__(self, username, role):
        self.id = username
        self.role = role

class StreamRelay:
    def __init__(self, source_url, name):
        self.source_url = source_url
        self.name = name
        self.active = True
        self.clients = []
        self.buffer = b''
        self.lock = threading.Lock()
        self.bytes_received = 0
        self.status = "Initializing"
        self.last_data_time = time.time()
        self.stall_check_thread = None
        self.start_stall_check()
        
    def start(self):
        self.active = True
        self.status = "Starting"
        self.bytes_received = 0
        self.last_data_time = time.time()
        self.relay_thread = threading.Thread(target=self._fetch_stream)
        self.relay_thread.daemon = True
        self.relay_thread.start()
        logger.log_stream_start(self.name, self.source_url)
    
    def stop(self):
        self.active = False
        self.status = "Stopped"
        logger.log_stream_stop(self.name)
        
    def start_stall_check(self):
        def check_stall():
            while self.active:
                if time.time() - self.last_data_time > 10 and self.status != "Stopped":
                    if self.status != "Stalled":
                        self.status = "Stalled"
                        logger.log_stream_stall(self.name)
                        self.restart()
                time.sleep(5)
        
        self.stall_check_thread = threading.Thread(target=check_stall)
        self.stall_check_thread.daemon = True
        self.stall_check_thread.start()
    
    def restart(self):
        logger.log_stream_restart(self.name)
        self.stop()
        time.sleep(1)  # Brief pause before restart
        self.start()
        
    def get_status(self):
        # Check if stream is stalled (no data for more than 10 seconds)
        if self.active and time.time() - self.last_data_time > 10:
            self.status = "Stalled"
        
        return {
            "status": self.status,
            "bytes_received": self.bytes_received,
            "active": self.active,
            "last_data_time": self.last_data_time
        }
        
    def _fetch_stream(self):
        try:
            self.status = "Connecting"
            response = requests.get(self.source_url, stream=True)
            self.status = "Connected"
            
            for chunk in response.iter_content(chunk_size=8192):
                if not self.active:
                    break
                if chunk:
                    with self.lock:
                        self.buffer = chunk
                        self.bytes_received += len(chunk)
                        self.last_data_time = time.time()
                        self.status = "Receiving"
                        for client in self.clients[:]:
                            try:
                                client.put(chunk)
                            except:
                                self.clients.remove(client)
        except Exception as e:
            error_msg = str(e)
            print(f"Error in stream {self.name}: {error_msg}")
            self.status = f"Error: {error_msg}"
            logger.log_stream_error(self.name, error_msg)
            self.active = False

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return {'streams': {}}

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {'users': {}}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

@login_manager.user_loader
def load_user(username):
    users = load_users()
    if username in users['users']:
        return User(username, users['users'][username]['role'])
    return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        users = load_users()
        
        if username in users['users'] and check_password_hash(users['users'][username]['password'], password):
            user = User(username, users['users'][username]['role'])
            login_user(user)
            logger.log_login(username)
            return redirect(url_for('index'))
        
        flash('Invalid username or password')
    config = load_config()
    system_name = config.get('system', {}).get('name', 'Stream Relay Admin')
    return render_template('login.html', system_name=system_name)

@app.route('/logout')
@login_required
def logout():
    logger.log_logout(current_user.id)
    logout_user()
    return redirect(url_for('login'))

@app.route('/config')
@login_required
def config():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    config_data = load_config()
    system_name = config_data.get('system', {}).get('name', 'Stream Relay Admin')
    return render_template('config.html', config=config_data.get('system', {'name': 'Stream Relay Admin', 'port': 5000}), system_name=system_name)

@app.route('/api/config', methods=['POST'])
@login_required
def update_config():
    if current_user.role != 'admin':
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    data = request.json
    system_name = data.get('system_name')
    port = data.get('port')
    
    if not system_name or not port:
        return jsonify({'status': 'error', 'message': 'Missing required fields'})
    
    try:
        port = int(port)
        if port < 1 or port > 65535:
            raise ValueError('Invalid port number')
    except ValueError:
        return jsonify({'status': 'error', 'message': 'Invalid port number'})
    
    config = load_config()
    if 'system' not in config:
        config['system'] = {}
    
    config['system']['name'] = system_name
    config['system']['port'] = port
    save_config(config)
    logger.log_config_update(current_user.id, {'system_name': system_name, 'port': port})
    
    return jsonify({'status': 'success'})

@app.route('/')
@login_required
def index():
    config = load_config()
    system_name = config.get('system', {}).get('name', 'Stream Relay Admin')
    if current_user.role == 'admin':
        return render_template('admin.html', streams=config['streams'], system_name=system_name)
    else:
        return render_template('monitor.html', streams=config['streams'], system_name=system_name)

@app.route('/users')
@login_required
def users():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    users_data = load_users()
    config = load_config()
    system_name = config.get('system', {}).get('name', 'Stream Relay Admin')
    return render_template('users.html', users=users_data['users'], system_name=system_name)

@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')
    
    if not all([username, password, role]) or role not in ['admin', 'monitor']:
        return jsonify({'status': 'error', 'message': 'Invalid data'})
    
    users = load_users()
    if username in users['users']:
        return jsonify({'status': 'error', 'message': 'User already exists'})
    
    users['users'][username] = {
        'password': generate_password_hash(password),
        'role': role
    }
    save_users(users)
    return jsonify({'status': 'success'})

@app.route('/remove_user/<username>')
@login_required
def remove_user(username):
    if current_user.role != 'admin':
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    if username == 'admin' or username == current_user.id:
        return jsonify({'status': 'error', 'message': 'Cannot remove this user'})
    
    users = load_users()
    if username in users['users']:
        del users['users'][username]
        save_users(users)
    
    return jsonify({'status': 'success'})

@app.route('/add_stream', methods=['POST'])
@login_required
def add_stream():
    if current_user.role != 'admin':
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    data = request.json
    source_url = data.get('source_url')
    name = data.get('name')
    frequency = data.get('frequency')
    location = data.get('location')
    
    if not all([name, source_url, frequency, location]):
        return jsonify({'status': 'error', 'message': 'Missing required fields'})
    
    config = load_config()
    config['streams'][name] = {
        'source_url': source_url,
        'name': name,
        'frequency': frequency,
        'location': location
    }
    save_config(config)
    
    if name not in active_streams:
        relay = StreamRelay(source_url, name)
        active_streams[name] = relay
        relay.start()
    
    logger.log_stream_add(name, source_url, frequency, location)
    return jsonify({'status': 'success'})

@app.route('/remove_stream/<stream_name>')
@login_required
def remove_stream(stream_name):
    if current_user.role != 'admin':
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    # Convert hyphens back to spaces for looking up the stream
    name = stream_name.replace('-', ' ')
    
    config = load_config()
    if name in config['streams']:
        del config['streams'][name]
        save_config(config)
        
    if name in active_streams:
        active_streams[name].stop()
        del active_streams[name]
    
    return jsonify({'status': 'success'})

@app.route('/stream/<stream_name>')
def stream(stream_name):
    print(f"Accessing stream: {stream_name}")  # Debug output
    print(f"Available streams: {list(active_streams.keys())}")  # Debug output
    
    if stream_name not in active_streams:
        config = load_config()
        print(f"Stream not in active_streams, checking config: {list(config['streams'].keys())}")  # Debug output
        if stream_name in config['streams']:
            stream_config = config['streams'][stream_name]
            relay = StreamRelay(
                stream_config['source_url'],
                stream_config['name']
            )
            active_streams[stream_name] = relay
            relay.start()
            print(f"Started new stream: {stream_name}")  # Debug output
        else:
            print(f"Stream not found in config: {stream_name}")  # Debug output
            return "Stream not found", 404

    def generate():
        from queue import Queue
        client_queue = Queue()
        active_streams[stream_name].clients.append(client_queue)
        try:
            while active_streams[stream_name].active:
                chunk = client_queue.get()
                if chunk:
                    yield chunk
        finally:
            if client_queue in active_streams[stream_name].clients:
                active_streams[stream_name].clients.remove(client_queue)

    return Response(
        generate(),
        mimetype='audio/mpeg',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Transfer-Encoding': 'chunked'
        }
    )

@app.route('/edit_user/<username>', methods=['POST'])
@login_required
def edit_user(username):
    if current_user.role != 'admin':
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    if username == 'admin' and current_user.id != 'admin':
        return jsonify({'status': 'error', 'message': 'Cannot edit admin user'})
    
    data = request.json
    new_password = data.get('password')
    new_role = data.get('role')
    
    if not new_role or new_role not in ['admin', 'monitor']:
        return jsonify({'status': 'error', 'message': 'Invalid role'})
    
    users = load_users()
    if username not in users['users']:
        return jsonify({'status': 'error', 'message': 'User not found'})
    
    users['users'][username]['role'] = new_role
    if new_password:
        users['users'][username]['password'] = generate_password_hash(new_password)
    
    save_users(users)
    return jsonify({'status': 'success'})

@app.route('/delete_user/<username>')
@login_required
def delete_user(username):
    if current_user.role != 'admin':
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    if username == 'admin' or username == current_user.id:
        return jsonify({'status': 'error', 'message': 'Cannot delete this user'})
    
    users = load_users()
    if username in users['users']:
        del users['users'][username]
        save_users(users)
    
    return jsonify({'status': 'success'})

@app.route('/edit_stream/<stream_name>', methods=['POST'])
@login_required
def edit_stream(stream_name):
    if current_user.role != 'admin':
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    data = request.json
    new_name = data.get('name')
    source_url = data.get('source_url')
    frequency = data.get('frequency')
    location = data.get('location')
    
    if not all([new_name, source_url, frequency, location]):
        return jsonify({'status': 'error', 'message': 'Missing required fields'})
    
    config = load_config()
    
    # Debug output to help diagnose issues
    print(f"Editing stream. Original name from URL: {stream_name}")
    print(f"Available streams in config: {list(config['streams'].keys())}")
    
    # Try both with and without hyphen replacement
    stream_key = stream_name
    if stream_key not in config['streams']:
        stream_key = stream_name.replace('-', ' ')
        if stream_key not in config['streams']:
            return jsonify({'status': 'error', 'message': 'Stream not found'})
    
    print(f"Found stream with key: {stream_key}")
    
    # Stop the existing stream if it's active
    if stream_key in active_streams:
        active_streams[stream_key].stop()
        del active_streams[stream_key]
    
    # Remove old stream config
    del config['streams'][stream_key]
    
    # Add new stream config
    new_key = new_name  # Use the name as provided
    config['streams'][new_key] = {
        'source_url': source_url,
        'name': new_name,
        'frequency': frequency,
        'location': location
    }
    save_config(config)
    
    # Start new stream
    relay = StreamRelay(source_url, new_key)
    active_streams[new_key] = relay
    relay.start()
    
    print(f"Stream updated. New name: {new_key}")
    return jsonify({'status': 'success'})

@app.route('/logs')
@login_required
def logs():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    config = load_config()
    system_name = config.get('system', {}).get('name', 'Stream Relay Admin')
    return render_template('logs.html', system_name=system_name)

@app.route('/api/logs')
@login_required
def get_logs():
    if current_user.role != 'admin':
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    logs = logger.get_recent_logs()
    return jsonify(logs)

@app.route('/api/log', methods=['POST'])
@login_required
def log_event():
    data = request.json
    level = data.get('level', 'info')
    message = data.get('message')
    details = data.get('details', {})
    
    if not message:
        return jsonify({'status': 'error', 'message': 'Missing required message field'}), 400
    
    if level == 'error':
        logger.logger.error(f"Frontend: {message}", extra={'details': details})
    elif level == 'warning':
        logger.logger.warning(f"Frontend: {message}", extra={'details': details})
    else:
        logger.logger.info(f"Frontend: {message}", extra={'details': details})
    
    return jsonify({'status': 'success'})

@app.route('/api/streams/status')
@login_required
def get_streams_status():
    statuses = {}
    for name, stream in active_streams.items():
        statuses[name] = stream.get_status()
    
    return jsonify(statuses)

@app.route('/api/streams/stop/<stream_name>')
@login_required
def stop_stream(stream_name):
    if stream_name in active_streams:
        active_streams[stream_name].stop()
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': 'Stream not found'}), 404

@app.route('/api/streams/start/<stream_name>')
@login_required
def start_stream(stream_name):
    config = load_config()
    if stream_name in config['streams']:
        if stream_name in active_streams:
            active_streams[stream_name].stop()
        relay = StreamRelay(config['streams'][stream_name]['source_url'], stream_name)
        active_streams[stream_name] = relay
        relay.start()
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': 'Stream not found'}), 404

@app.route('/api/streams/stop_all')
@login_required
def stop_all_streams():
    if current_user.role != 'admin':
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    for stream in active_streams.values():
        stream.stop()
    
    logger.log_all_streams_stop(current_user.id)
    return jsonify({'status': 'success'})

@app.route('/api/streams/start_all')
@login_required
def start_all_streams():
    if current_user.role != 'admin':
        return jsonify({'status': 'error', 'message': 'Unauthorized'})
    
    config = load_config()
    for name, stream_config in config['streams'].items():
        if name in active_streams:
            active_streams[name].stop()
        relay = StreamRelay(stream_config['source_url'], name)
        active_streams[name] = relay
        relay.start()
    
    logger.log_all_streams_start(current_user.id)
    return jsonify({'status': 'success'})

if __name__ == '__main__':
    # Load existing streams and configuration on startup
    config = load_config()
    logger.log_startup()
    
    # Get configured port or use default
    port = config.get('system', {}).get('port', 5000)
    system_name = config.get('system', {}).get('name', 'Stream Relay Admin')
    
    print("\n=== Stream Configuration at Startup ===")
    print(f"System Name: {system_name}")
    print(f"Port: {port}")
    print("\nConfigured streams in config.json:")
    for name, stream_config in config['streams'].items():
        print(f"\nStream: {name}")
        print(f"  Source URL: {stream_config['source_url']}")
        print(f"  Name in config: {stream_config['name']}")
        print(f"  Mount point will be: /stream/{name}")
        
        stream_name = name
        relay = StreamRelay(
            stream_config['source_url'],
            stream_name
        )
        active_streams[stream_name] = relay
        relay.start()
        print(f"  → Started stream: {stream_name}")
    
    print("\nActive stream mount points:")
    for stream_name in active_streams.keys():
        print(f"  /stream/{stream_name}")
    
    print("\nTo access streams, use these URLs:")
    for stream_name in active_streams.keys():
        print(f"  http://localhost:{port}/stream/{stream_name}")
    
    print("\n=====================================")
    app.run(host='0.0.0.0', port=port, threaded=True) 
