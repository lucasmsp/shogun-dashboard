from dash import Dash, dash_table, dcc, html, callback, Output, Input
import dash_bootstrap_components as dbc

import pandas as pd
import plotly.express as px

from project.layout import register_layout
from project.callbacks import register_callbacks

dfs = {
    'v1': pd.read_parquet('df_v1.parquet'),
    'v2a': pd.read_parquet('df_v2a.parquet'),
    'v2b': pd.read_parquet('df_v2b.parquet'),
    'v3': pd.read_parquet('df_v3.parquet')
}

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
app.layout = register_layout(dfs)
register_callbacks(app, dfs)


if __name__ == "__main__":
    app.run_server(debug=True)    