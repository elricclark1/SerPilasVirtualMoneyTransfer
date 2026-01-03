import os
import sys
from time import sleep

# Add current directory to path
sys.path.append(os.path.dirname(__file__))

from app import app, init_db

if __name__ == '__main__':
    # Initialize the database
    init_db()
    
    # Run the Flask app
    # On Android, we don't need debug mode.
    # We bind to 0.0.0.0 to be accessible from other devices.
    app.run(host='0.0.0.0', port=5000, debug=False)
