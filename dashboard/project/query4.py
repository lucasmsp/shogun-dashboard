from urllib.request import urlopen
import json
import plotly.express as px
import dash_bootstrap_components as dbc
from dash import Dash, dcc, html, Input, Output, callback
import plotly.figure_factory as ff
import numpy as np
import pandas as pd

TAB_VIEW = "tab-3"

def register_layout_query(dm):
    q5 = [
        dbc.Row(
            children=[
                html.H1(
                    children="View 4 - Representation of data through maps",
                    style={'textAlign': 'center'}
                ),

                html.Div(style={'height': '100px'}),

                html.H2(
                    children="This visualization allows the analysis of the data through the maps",
                    style={'fontSize': '20px'}
                ),

                html.Div(style={'height': '100px'}),

                html.H4(children="Choose the type of chart", style={'textAlign': 'Left'}),
                dbc.Row(
                    dcc.Dropdown(
                        id='query4-dropdown-query',
                        options=[
                            {'label': 'Choropleth Map of brazilian states - # IPs with vulnerabilities', 'value': 'ip_str'},
                            {'label': 'Choropleth Map of brazilian states - Average of CVSS by state', 'value': 'cvss_score'},
                            {'label': 'Choropleth Map of brazilian states - Average of EPSS by state', 'value': 'epss_score'},
                            {'label': 'Choropleth Map of brazilian states - Number of different CVEs per state', 'value': 'cve_id'},
                            {'label': 'Choropleth Map of brazilian states - CVSS values by states', 'value': 'ip_cvss'}
                        ],
                        clearable=False,
                        value='ip_str'
                    ),
                    style={'marginTop': '32px'}
                ),
                dbc.Row(
                    html.Div([
                        html.Div(style={'height': '40px'}),
                        html.Label(
                            children='Choose the CVSS range',
                            style={
                                "marginLeft": "30px",
                                "marginBottom": "10px",
                            }
                        ), 
                        dcc.RangeSlider(
                            id='query4-cvss-range-slider',
                            min=0,
                            max=10,
                            count=1,
                            value=[0, 10],
                            tooltip={
                                'placement': 'top',
                            },
                            allowCross=False,
                        )
                        ], 
                        id="query4-div-to-hide",
                        style={ 'display': 'none'})
                ),

                html.Div(style={'height': '40px'}),

                dcc.Graph(
                    id="query-4-graph",
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
        Output(component_id="query4-div-to-hide", component_property='style'),
        Input('query4-dropdown-query', 'value')
    )
    def update_range_slider(value):
        if value == 'ip_cvss':
            return {'display': 'block'}
        else:
            return {'display': 'none'}

    @app.callback(
        Output('query-4-graph', 'figure'),
        Input('date-picker-single', 'value'),
        Input("query4-dropdown-query", 'value'),
        Input('query4-cvss-range-slider', 'value'), 
        Input("general-tabs", "active_tab"), prevent_initial_call=True
    )
    def update_choropleth_map(date_value, value, cvss_range_query=[0,10], active_tab=None):
        fig = {}
        if TAB_VIEW != active_tab:
            return fig

        print("[INFO][query4][update_choropleth_map] ", date_value, flush=True)
        
        if value == 'ip_str':

            df = dm.get_report_dataset(date_value, columns=["ip_str", "region_code"])
            if df.empty:
                return fig

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
            if df.empty:
                return fig

            df['name'] = df['region_code'].map(state_id_map)
            df['cvss_new'] = df['vulns_scores'].apply(lambda x: x['cvss_score'])
            df = df.drop('vulns_scores', axis=1)\
                .explode('cvss_new')

            # Transformando cada item em float
            df['cvss_new'] = pd.to_numeric(df['cvss_new'], downcast='float', errors='coerce')
            # filtrando apenas o maior CVSS_NEW de cada IP
            df = df.groupby(['region_code', "name", 'ip_str']).max('cvss_new').reset_index()
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
                title="Average CVSS by state (only the major CVE per IP)",
                margin={'r': 1, 'l': 1, 'b': 1, 't': 40},
                font=dict(size=12),
            )

            return fig

        elif value == 'epss_score':

            df = dm.get_report_dataset(date_value,
                                       columns=['ip_str', "region_code", "vulns_scores"])
            if df.empty:
                return fig

            df['name'] = df['region_code'].map(state_id_map)
            df['epss_new'] = df['vulns_scores'].apply(lambda x: x['epss'])            
            df = df.drop('vulns_scores', axis=1)\
                .explode('epss_new')
            # Transformando cada item em float
            df['epss_new'] = pd.to_numeric(df['epss_new'], downcast='float', errors='coerce')
            # filtrando apenas o maior epss_new de cada IP
            df = df.groupby(['region_code', "name", 'ip_str']).max('epss_new').reset_index()
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
                title="Average EPSS by state (only the major CVE per IP)",
                margin={'r': 1, 'l': 1, 'b': 1, 't': 40},
                font=dict(size=12),
            )

            return fig

        elif value == 'cve_id':

            df = dm.get_report_dataset(date_value,
                                       columns=["region_code", "vulns_scores"])
            if df.empty:
                return fig

            df['name'] = df['region_code'].map(state_id_map)
            df['cve_new'] = df['vulns_scores'].apply(lambda x: x['cve_id'])
            df = df.drop('vulns_scores', axis=1)\
                .explode('cve_new')

            df = df[['region_code', 'name', 'cve_new']].drop_duplicates()
            df['n_cves'] = df.groupby(['region_code', 'name'])['cve_new'].transform(lambda x: x.nunique(dropna=True))
            
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
            print("[INFO][query4][update_choropleth_map] ip_cvss: ", cvss_range_query)
            df = dm.get_report_dataset(date_value,
                                       columns=["ip_str", "region_code", "vulns_scores"])
            if df.empty:
                return fig
            df['name'] = df['region_code'].map(state_id_map)
            df['cvss_new'] = df['vulns_scores'].apply(lambda x: x['cvss_score'])

            df = df.explode('cvss_new')

            df['cvss_new'] = df['cvss_new'].apply(lambda x: float(x))
            df = df.groupby(['region_code', "name", 'ip_str']).max('cvss_new').reset_index()
            df = df[(df['cvss_new'] >= cvss_range_query[0]) & (df['cvss_new'] <= cvss_range_query[1])]

            df = df.groupby(by=['region_code', "name"]).agg(n_ips=('ip_str', pd.Series.nunique)).reset_index()
            fig = px.choropleth_mapbox(
                df,
                locations="name",
                geojson=brazil,
                color="n_ips",
                color_continuous_scale="Rainbow",
                hover_name="region_code",
                hover_data=["n_ips"],
                mapbox_style="carto-positron",
                labels={'cvss_new': 'CVSS range'},
                center={"lat": -14, "lon": -55},
                zoom=2,
                opacity=0.5,
            )
            fig.update_layout(
                title="Number of IPs with CVEs within CVSS range by states",
                margin={'r': 1, 'l': 1, 'b': 1, 't': 40},
                font=dict(size=12),
            )
            return fig


