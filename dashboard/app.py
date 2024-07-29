import argparse

from project.dash_server import app

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog="tlhop-dashboard",
        description="This application provides a dashboard with various panels for analyzing cybersecurity vulnerabilities using data from the Shodan search engine.",
        epilog="Thread-Limiting Holistic Open Platform (TLHOP) Project - DCC/UFMG - CERT.br"
    )
    parser.add_argument('--host', required=False, default='127.0.0.1', help="Hostname or IP address to start the application. (default, 127.0.0.1).", type=str)
    parser.add_argument('--port', required=False, default=8080, help="Port to start the application (default, 8080).", type=int)
    parser.add_argument('--scan', required=False, default=False, help="When true, the application will try to scan for new Shodan dumps (default, True).", type=lambda x: (str(x).lower() == 'true'))
    args, _ = parser.parse_known_args()

    app.scan_enabled = args.scan 
    app.run(debug=False, host=args.host, port=args.port, use_reloader=False)
