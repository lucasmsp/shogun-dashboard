import os
from project.home import start_dash

if __name__ == '__main__':
    host = os.getenv('APP_HOST', '127.0.0.1')
    port = int(os.getenv('APP_PORT', 8080))
    scan = os.getenv('APP_SCAN', 'false').lower() == 'true'

    start_dash(host=host, port=port, scan_enabled=scan)
