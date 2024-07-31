
import os
from project.dash_server import app

scan_enabled = str(os.environ.get("TLHOP_DASHBOARD_SCAN", "True")).lower() == 'true'
app.scan_enabled = scan_enabled

server = app.server
