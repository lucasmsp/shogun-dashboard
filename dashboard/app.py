import argparse
from project.home import start_dash 

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument( '--host', default='127.0.0.1', help="Hostname or IP address to start the application. (default, 127.0.0.1).", type=str)
    parser.add_argument( '--port', default=8080,  help="Port to start the application (default, 8080).", type=int)
    parser.add_argument( '--scan',  help="When true, the application will try to scan for new Shodan dumps (default, True).", default=False, type=lambda x: (str(x).lower() == 'true'))
    args = parser.parse_args()

    start_dash(host=args.host, port=args.port, scan_enabled=args.scan) 
