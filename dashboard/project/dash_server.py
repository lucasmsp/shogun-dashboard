from dash import Dash, html
import dash_bootstrap_components as dbc

from project.callbacks import register_callbacks
from project.storage import DatasetManager
from project.flask_routes import start_flask, set_routes

external_stylesheets = [
    {
        "href": (
            "https://fonts.googleapis.com/css2?"
            "family=Lato:wght@400;700&display=swap"
        ),
        "rel": "stylesheet",
    },
    dbc.themes.BOOTSTRAP,
    "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css"
]


dm = DatasetManager()
dm.check_available_datasets()

server, db, login_manager = start_flask(dm)
app = Dash("TLHOP/SAM Cybersecurity Dashboards", server=server, external_stylesheets=external_stylesheets)
app.title = "TLHOP/SAM Cybersecurity Dashboards"
app.scan_enabled = True 
app.dm = dm
app.layout = html.Div()
app = set_routes(server, db, login_manager, app)
register_callbacks(dm, app)

