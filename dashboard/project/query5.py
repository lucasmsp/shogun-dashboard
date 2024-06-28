from urllib.request import urlopen
import json
import plotly.express as px
import dash_bootstrap_components as dbc
from dash import Dash, dcc, html, Input, Output, callback
import plotly.figure_factory as ff
import numpy as np


def register_layout_query(dm):
    q5 = [
        dbc.Row(
            children=[
                html.H1(
                    children="View 5 - Representation of data through maps",
                    style={'text-align': 'center'}
                ),

                html.Div(style={'height': '40px'}),

                html.H2(
                    children="This visualization allows the analysis of the data through the maps",
                    style={'font-size': '20px'}
                ),

                html.Div(style={'height': '40px'}),

                html.H4(children="Choose the type of chart", style={'text-align': 'Left'}),
                dbc.Row(
                    dcc.Dropdown(
                        id='dropdown-query',
                        options=[
                            {'label': 'Choropleth Map - # IPs per vulnerability', 'value': 'ip_str'},
                            {'label': 'Choropleth Map - Average of CVSS by state', 'value': 'cvss_score'},
                            {'label': 'Choropleth Map - Average of EPSS by state', 'value': 'epss_score'},
                            {'label': 'Choropleth Map - Number of different CVEs per state', 'value': 'cve_id'},
                            {'label': 'Choropleth Map - CVSS values by states', 'value': 'ip_cvss'}
                        ],
                        clearable=False,
                        value='ip_str'
                    ),
                    style={'marginTop': '32px'}
                ),

                html.Div(id='cvss-range-slider'),

                dcc.Store(id='range-slider-values'),

                html.Div(style={'height': '40px'}),

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
        brazil = json.load(response)

    state_id_map = {}
    for feature in brazil['features']:
        feature['id'] = feature['properties']['name']
        state_id_map[feature['properties']['sigla']] = feature['id']

    @app.callback(
        Output('cvss-range-slider', 'children'),
        Input('dropdown-query', 'value')
    )
    def update_range_slider(value):
        if value == 'ip_cvss':
            return [
                html.Div(style={'height': '40px'}),
                html.Label(
                    children='Choose the CVSS range',
                    style={
                        "marginLeft": "30px",
                        "marginBottom": "10px",
                    }
                ), dcc.RangeSlider(
                    id='cvss-range',
                    min=0,
                    max=10,
                    count=1,
                    value=[0, 10],
                    tooltip={
                        'placement': 'top',
                        'always_visible': True,
                    },
                    allowCross=False,
                ),
            ]
        else:
            return None

    @app.callback(
        Output('range-slider-values', 'data'),
        Input('cvss-range', 'value')
    )
    def store_range_slider_cvss(cvss_range):
        return cvss_range

    @app.callback(
        Output('query-5-graph', 'figure'),
        Input('date-picker-single', 'date'),
        Input("dropdown-query", 'value'),
        Input('range-slider-values', 'data')
    )
    def update_choropleth_map(date_value, value, cvss_range_query):

        print("[INFO] update_table4: ", date_value, flush=True)

        if value == 'ip_str':

            df = dm.get_report_dataset(date_value,
                                       columns=["ip_str", "region_code"])

            df['name'] = df['region_code'].map(state_id_map)

            df['n_ips'] = df.groupby('region_code')['ip_str'].transform(lambda x: x.nunique(dropna=True))

            df = df[['n_ips', 'region_code', 'name']].drop_duplicates()

            fig = px.choropleth_mapbox(
                df,
                locations="name",
                geojson=brazil,
                color="n_ips",
                color_continuous_scale="Rainbow",
                hover_name="region_code",
                hover_data=["n_ips"],
                mapbox_style="carto-positron",
                labels={'n_ips': '# IPs'},
                center={"lat": -14, "lon": -55},
                zoom=2,
                opacity=0.5,
            )
            fig.update_layout(
                title="# IPs per vulnerability",
                margin={'r': 1, 'l': 1, 'b': 1, 't': 40},
                font=dict(size=12),
            )

            return fig

        elif value == 'cvss_score':

            df = dm.get_report_dataset(date_value,
                                       columns=["ip_str", "region_code", "vulns_scores"])

            df['name'] = df['region_code'].map(state_id_map)

            df['cvss_new'] = df['vulns_scores'].apply(lambda x: x['cvss_score'])

            df = df.drop('vulns_scores', axis=1)

            df = df.explode('cvss_new')

            # Transformando cada item em float
            df['cvss_new'] = df['cvss_new'].apply(lambda x: float(x))

            # Criando uma coluna 'cvss_mean' que armazena a média dos cvss por estado
            df['cvss_mean'] = df.groupby('region_code')['cvss_new'].transform('mean')

            #Criando um df somente com as 3 colunas necessárias para criar o mapa
            df = df[['cvss_mean', 'region_code', 'name']].drop_duplicates()

            fig = px.choropleth_mapbox(
                df,
                locations="name",
                geojson=brazil,
                color="cvss_mean",
                color_continuous_scale="Rainbow",
                hover_name="region_code",
                hover_data=["cvss_mean"],
                mapbox_style="carto-positron",
                labels={'cvss_mean': 'Avg CVSS'},
                center={"lat": -14, "lon": -55},
                zoom=2,
                opacity=0.5,
            )
            fig.update_layout(
                title="Average CVSS by state",
                margin={'r': 1, 'l': 1, 'b': 1, 't': 40},
                font=dict(size=12),
            )

            return fig

        elif value == 'epss_score':

            df = dm.get_report_dataset(date_value,
                                       columns=["region_code", "vulns_scores"])

            df['name'] = df['region_code'].map(state_id_map)

            df['epss_new'] = df['vulns_scores'].apply(lambda x: x['epss'])

            df = df.drop('vulns_scores', axis=1)

            df = df.explode('epss_new')

            # Transformando cada item em float
            df['epss_new'] = df['epss_new'].apply(lambda x: float(x))

            # Criando uma coluna 'epss_sum' que armazena a média dos epss por estado
            df['epss_mean'] = df.groupby('region_code')['epss_new'].transform('mean')

            # Criando um df somente com as 3 colunas necessárias para criar o mapa
            df = df[['epss_mean', 'region_code', 'name']].drop_duplicates()

            fig = px.choropleth_mapbox(
                df,
                locations="name",
                geojson=brazil,
                color="epss_mean",
                color_continuous_scale="Rainbow",
                hover_name="region_code",
                hover_data=["epss_mean"],
                mapbox_style="carto-positron",
                labels={'epss_mean': 'Avg EPSS'},
                center={"lat": -14, "lon": -55},
                zoom=2,
                opacity=0.5,
            )
            fig.update_layout(
                title="Average EPSS by state",
                margin={'r': 1, 'l': 1, 'b': 1, 't': 40},
                font=dict(size=12),
            )

            return fig

        elif value == 'cve_id':

            df = dm.get_report_dataset(date_value,
                                       columns=["region_code", "vulns_scores"])

            df['name'] = df['region_code'].map(state_id_map)

            df['cve_new'] = df['vulns_scores'].apply(lambda x: x['cve_id'])

            df = df.drop('vulns_scores', axis=1)

            df = df.explode('cve_new')

            df['n_cves'] = df.groupby('region_code')['cve_new'].transform(lambda x: x.nunique(dropna=True))

            df = df[['n_cves', 'region_code', 'name']].drop_duplicates()

            fig = px.choropleth_mapbox(
                df,
                locations="name",
                geojson=brazil,
                color="n_cves",
                color_continuous_scale="Rainbow",
                hover_name="region_code",
                hover_data=["n_cves"],
                mapbox_style="carto-positron",
                labels={'n_cves': '# CVEs'},
                center={"lat": -14, "lon": -55},
                zoom=2,
                opacity=0.5,
            )
            fig.update_layout(
                title="Number of different CVEs per state",
                margin={'r': 1, 'l': 1, 'b': 1, 't': 40},
                font=dict(size=12),
            )

            return fig

        elif value == 'ip_cvss':

            df = dm.get_report_dataset(date_value,
                                       columns=["ip_str", "region_code", "vulns_scores"])

            df['name'] = df['region_code'].map(state_id_map)

            df['cvss_new'] = df['vulns_scores'].apply(lambda x: x['cvss_score'])

            df = df.explode('cvss_new')

            df['cvss_new'] = df['cvss_new'].apply(lambda x: float(x))

            df = df.drop('vulns_scores', axis=1)

            # df = df[(df['cvss_new'] >= 5)]

            df = df[(df['cvss_new'] >= cvss_range_query[0]) & (df['cvss_new'] <= cvss_range_query[1])]

            fig = px.choropleth_mapbox(
                df,
                locations="name",
                geojson=brazil,
                color="cvss_new",
                color_continuous_scale="Rainbow",
                hover_name="region_code",
                hover_data=["cvss_new", "ip_str"],
                mapbox_style="carto-positron",
                labels={'cvss_new': 'CVSS range'},
                center={"lat": -14, "lon": -55},
                zoom=2,
                opacity=0.5,
            )
            fig.update_layout(
                title="CVSS values by states",
                margin={'r': 1, 'l': 1, 'b': 1, 't': 40},
                font=dict(size=12),
            )
            return fig


