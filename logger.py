import os
import logging
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler

class StreamLogger:
    def __init__(self, log_dir='logs'):
        self.log_dir = log_dir
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        self.log_file = os.path.join(log_dir, 'relaymanager.log')
        
        # Create logger
        self.logger = logging.getLogger('StreamRelay')
        self.logger.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        
        # Create TimedRotatingFileHandler
        file_handler = TimedRotatingFileHandler(
            self.log_file,
            when='midnight',
            interval=1,
            backupCount=30  # Keep last 30 days of logs
        )
        file_handler.suffix = "%Y-%m-%d.log"
        file_handler.setFormatter(formatter)
        
        # Add handlers
        self.logger.addHandler(file_handler)
    
    def log_startup(self):
        self.logger.info("Stream Relay Manager Started")
    
    def log_login(self, username):
        self.logger.info(f"User Login: {username}")
    
    def log_logout(self, username):
        self.logger.info(f"User Logout: {username}")
    
    def log_stream_add(self, name, source_url, frequency, location):
        self.logger.info(f"Stream Added - Name: {name}, URL: {source_url}, Frequency: {frequency}, Location: {location}")
    
    def log_stream_edit(self, old_name, new_name, source_url, frequency, location):
        self.logger.info(f"Stream Edited - Old Name: {old_name}, New Name: {new_name}, URL: {source_url}, Frequency: {frequency}, Location: {location}")
    
    def log_stream_remove(self, name):
        self.logger.info(f"Stream Removed - Name: {name}")
    
    def log_stream_start(self, name, source_url):
        self.logger.info(f"Stream Started - Name: {name}, URL: {source_url}")
    
    def log_stream_stop(self, name):
        self.logger.info(f"Stream Stopped - Name: {name}")
    
    def log_stream_error(self, name, error):
        self.logger.error(f"Stream Error - Name: {name}, Error: {error}")
    
    def log_stream_stall(self, name):
        self.logger.warning(f"Stream Stalled - Name: {name}")
    
    def log_stream_restart(self, name):
        self.logger.info(f"Stream Restarted - Name: {name}")
    
    def log_listener_connect(self, stream_name, client_ip):
        self.logger.info(f"Listener Connected - Stream: {stream_name}, IP: {client_ip}")
    
    def log_listener_disconnect(self, stream_name, client_ip):
        self.logger.info(f"Listener Disconnected - Stream: {stream_name}, IP: {client_ip}")
    
    def log_all_streams_start(self, username):
        self.logger.info(f"All Streams Started by {username}")
    
    def log_all_streams_stop(self, username):
        self.logger.info(f"All Streams Stopped by {username}")
    
    def get_recent_logs(self, lines=100):
        """Return the most recent log entries"""
        if not os.path.exists(self.log_file):
            return []
        
        with open(self.log_file, 'r') as f:
            logs = f.readlines()
        
        return list(reversed(logs[-lines:]))  # Return most recent logs first

    def log_config_update(self, username, changes):
        self.logger.info(f"User '{username}' updated system configuration: {changes}") 