from dash import Dash, dash_table, dcc, html, callback, Output, Input
import dash_bootstrap_components as dbc

import pandas as pd
import plotly.express as px

from project.layout import register_layout
from project.callbacks import register_callbacks

external_stylesheets = [
    {
        "href": (
            "https://fonts.googleapis.com/css2?"
            "family=Lato:wght@400;700&display=swap"
        ),
        "rel": "stylesheet",
    },
    dbc.themes.BOOTSTRAP
]
app = Dash(__name__, external_stylesheets=external_stylesheets)
app.title = "TLHOP/SAM Analytics on EPSS"
app.layout = register_layout()
register_callbacks(app)


if __name__ == "__main__":
    app.run_server(debug=True)    
