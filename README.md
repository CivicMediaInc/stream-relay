# Stream Relay
- Created by Drew Smith
- Updated: 3/11/2025 10:45pm

A Python application that allows you to relay Icecast streams to multiple listeners while only maintaining a single connection to the source stream.

## Features

- Web interface for managing streams
- User authentication with admin and regular user roles
- System configuration management
- Stream monitoring with real-time status updates
- Volume control for each stream
- Add, edit, and remove stream sources
- View detailed stream statistics and logs
- Alphabetically sorted stream display
- Persistent configuration using JSON
- Efficient stream relay with single source connection

## Requirements

- Python 3.7+
- Dependencies listed in `requirements.txt`

## Installation

1. Clone this repository
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Start the application:
   ```bash
   python app.py
   ```

2. Open your web browser and navigate to the configured port (default: `http://localhost:5000`)

3. Log in with your credentials:
   - Default admin credentials are configured during first run
   - Regular users can be added through the admin interface

4. Admin Features:
   - System Configuration
     - Set system name
     - Configure server port
   - User Management
     - Add/remove users
     - Set user roles
   - Stream Management
     - Add, edit, and remove streams
     - View stream statistics
   - Log Viewer
     - Monitor system events and errors

5. Regular User Features:
   - Monitor streams
   - Start/stop individual streams
   - Control stream volume
   - View stream status

6. Adding a new stream:
   - Enter a name for the stream
   - Provide the source URL
   - Set the frequency
   - Add location information
   - Click "Add Stream"

7. Access the relayed stream:
   - Use the URL provided in the stream list
   - Format: `http://<your-server>:<port>/stream/<stream_name>`

## Configuration

The application uses two main configuration files:

1. `config.json`: Stores system and stream configuration
   - System name
   - Server port
   - Stream definitions
   - User credentials (hashed)

2. `logger.py`: Handles logging configuration
   - System events
   - Stream status
   - User actions
   - Error logging

## Security

- Password hashing for user accounts
- Role-based access control
- Session management
- Secure configuration storage

## Notes

- Each stream source maintains only one connection to the original stream
- Multiple listeners can connect to the relay without increasing load on the source server
- Stream status is updated every 5 seconds
- All stream cards are sorted alphabetically for easy navigation
- The server port can be configured through the web interface