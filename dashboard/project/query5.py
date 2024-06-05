from urllib.request import urlopen
import json
import pandas as pd
import plotly.express as px
from dash import html, dcc, dash_table
import dash_bootstrap_components as dbc
from dash import Dash, dcc, html, Input, Output, callback


def register_layout_query(dm):
    q5 = [
        dbc.Row(
            children=[
                html.H1(
                    children="View 5 - Representation of data through maps",
                    style={'text-align': 'center'}
                ),
                html.H2(
                    children="This visualization allows the analysis of the data through the maps",
                    style={'font-size': '20px'}
                ),

                html.Div(style={'height': '50px'}),

                html.H4(children="Choose the type of chart", style={'text-align': 'Left'}),
                dbc.Row(
                    dcc.Dropdown(
                        id='dropdown-query',
                        options=[
                            {'label': 'Brazil states', 'value': 'creation'},
                            {'label': 'idIBGE', 'value': 'idIBGE'},
                        ],
                        value='creation'
                    ),
                    style={'marginTop': '32px'}
                ),

                dcc.Graph(
                    id="query-5-graph",
                    config={
                        'displayModeBar': False,
                        'scrollZoom': True
                    }
                ),
            ]
        ),
    ]
    return q5


def register_callback_query(dm, app):
    with urlopen("https://raw.githubusercontent.com/codeforamerica/click_that_hood/"
                 "master/public/data/brazil-states.geojson") as response:
        Brazil = json.load(response)
        state_id_map = {}
        for feature in Brazil['features']:
            feature['id'] = feature['properties']['name']
            state_id_map[feature['properties']['sigla']] = feature['id']

        brazil_date = pd.read_csv("/home/izzy/Documentos/tlhop-epss-app/output_data/br-state-codes.csv")

    @app.callback(
        Output('query-5-graph', 'figure'),
        # Input('query-5-graph', 'layoutData'),
        Input("dropdown-query", 'value'),
    )
    def update_choropleth_map(value):
        if value == "idIBGE":
            fig = px.choropleth_mapbox(
                brazil_date,
                locations="name",  # define the limits on the map/geography
                geojson=Brazil,  # shape information
                color="idIBGE",  # defining the color of the scale through the database
                hover_name="name",  # the information in the box
                hover_data=["idIBGE"],
                title="Distribuição por idIBGE",  # title of the map
                mapbox_style="carto-positron",  # defining a new map style
                center={"lat": -14, "lon": -55},  # define the limits that will be plotted
                zoom=2,  # map view size
                opacity=0.5,  # opacity of the map color, to appear the background
            )
            return fig

        elif value == "creation":
            fig = px.choropleth_mapbox(
                brazil_date,
                locations="name",  # define the limits on the map/geography
                geojson=Brazil,  # shape information
                color="creation",  # defining the color of the scale through the database
                hover_name="name",  # the information in the box
                hover_data=["creation"],
                title="Criação dos estados brasileiros",  # title of the map
                mapbox_style="carto-positron",  # defining a new map style
                center={"lat": -14, "lon": -55},  # define the limits that will be plotted
                zoom=2,  # map view size
                opacity=0.5,  # opacity of the map color, to appear the background
            )
            return fig




