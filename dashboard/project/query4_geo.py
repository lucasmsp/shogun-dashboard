import json
import plotly.express as px
import dash_bootstrap_components as dbc

from dash import Dash, dcc, html, Input, Output, callback, no_update

import pandas as pd

from project.auxiliar import logging


def build_state_choropleth(df, color_column, title, hover_label, color_label, geojson):
    """
    Build a choropleth map of Brazilian states.

    Args:
        df (pd.DataFrame): DataFrame containing the data.
        color_column (str): Column to use for coloring the states.
        title (str): Title of the choropleth map.
        hover_label (str): Label to use for the hover text.
        color_label (str): Label to use for the color scale.
        geojson (dict): GeoJSON file containing the state boundaries.

    Returns:
        plotly.graph_objs._figure.Figure: Choropleth map of Brazilian states.
    """

    if df.empty or color_column not in df.columns:
        fig = px.choropleth()
        fig.add_annotation(
            text="No data available for the selected filters",
            x=0.5,
            y=0.5,
            xref="paper",
            yref="paper",
            showarrow=False,
        )
        fig.update_layout(
            title=title,
            margin={'r': 1, 'l': 1, 'b': 1, 't': 40},
            font=dict(size=12),
            height=900,
        )
        return fig

    fig = px.choropleth(
        df,
        geojson=geojson,
        locations="name",
        color=color_column,
        color_continuous_scale="Rainbow",
        hover_name=hover_label,
        hover_data=[color_column],
        labels={color_column: color_label},
        locationmode="geojson-id",
    )
    fig.update_traces(marker_line_color="white", marker_line_width=0.5)
    fig.update_geos(fitbounds="locations", visible=False)
    fig.update_layout(
        title=title,
        margin={'r': 1, 'l': 1, 'b': 1, 't': 40},
        font=dict(size=12),
        height=900,
    )
    return fig


def register_layout_query(filter_modal={}):
    """
    Register the layout for the fourth query (choropleth map of Brazilian states).

    Args:
        filter_modal (dict): Filter modal configuration.

    Returns:
        dbc.Card: Layout for the fourth query.
    """

    elements = [
        dbc.Row(
            children=[
                html.H1(
                    children="View 4 - Representation of data through maps",
                    style={'textAlign': 'center', 'bottom-padding': '40px'}
                ),
                html.H2(
                    children="This visualization allows the analysis of the data through the maps",
                    style={'fontSize': '20px', 'bottom-padding': '40px'}
                ),
                html.H4(children="Choose the type of chart", style={'textAlign': 'Left'}),
                dbc.Row(
                    dcc.Dropdown(
                        id='query4-dropdown-query',
                        options=[
                            {'label': 'Choropleth Map of brazilian states - # IPs with vulnerabilities', 'value': 'ip'},
                            {'label': 'Choropleth Map of brazilian states - Average CVSS by state (only the major CVE '
                                      'per IP)', 'value': 'cvss_score'},
                            {'label': 'Choropleth Map of brazilian states - Average EPSS by state (only the major CVE '
                                      'per IP)', 'value': 'epss_score'},
                            {'label': 'Choropleth Map of brazilian states - Number of different CVEs per state', 'value': 'cve_id'},
                            {'label': 'Choropleth Map of brazilian states - Number of IPs with CVEs within CVSS range by states', 'value': 'ip_cvss'}
                        ],
                        clearable=False,
                        value='ip'
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
                dbc.Row(
                    html.Small(
                        [
                            html.I(className="fas fa-info-circle me-1", style={"color": "#17a2b8"}),
                            " Tip: Click on a region or state on the map to redirect to the General analysis per record view, filtered by that region."
                        ],
                        className="text-muted mt-2",
                        style={"textAlign": "left", "paddingLeft": "15px"}
                    )
                )
            ]
        )
    ]

    tab4_content = dbc.Card(
        dbc.CardBody(
            html.Div(children=[dbc.Row(children=elements)], className="wrapper_table",
                     style={"width": "100%", "height": "100%"}),
        ),
        className="mt-3",
        id="tab4_content"
    )

    return tab4_content


def register_callback_query(dm, app):
    """
    Register the callbacks for the fourth query (choropleth map of Brazilian states).

    Args:
        dm (DataManager): Data manager instance.
        app (dash.Dash): Dash application instance.
    """

    brazil_states_geojson =  "./assets/brazil-states-simplified.geojson"
    with open(brazil_states_geojson) as f:
        brazil = json.load(f)

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
        Input('query4-cvss-range-slider', 'value')
    )
    def update_choropleth_map(date_value, value, cvss_range_query=[0, 10]):
        fig = {}
        height = 900
        zoom = 4

        if not date_value:
            return fig

        logging.info(date_value)
        
        if value == 'ip':

            df = dm.get_report_dataset(date_value, columns=["ip", "city"])
            df['region_code'] = df['city'].str.split(', ').str[1]
            if df.empty:
                return fig

            df['name'] = df['region_code'].map(state_id_map)
            df['n_ips'] = df.groupby('region_code')['ip'].transform(lambda x: x.nunique(dropna=True))
            df = df[['n_ips', 'region_code', 'name']].drop_duplicates()

            fig = build_state_choropleth(
                df,
                color_column="n_ips",
                title="# IPs per vulnerability",
                hover_label="region_code",
                color_label="# IPs",
                geojson=brazil,
            )

        elif value == 'cvss_score':

            df = dm.get_report_dataset(date_value, columns=["ip", "city", "vulns_cvss_score"])
            df['region_code'] = df['city'].str.split(', ').str[1]

            if df.empty:
                return fig

            df['name'] = df['region_code'].map(state_id_map)
            df['cvss_new'] = df['vulns_cvss_score']

            df = df.drop('vulns_cvss_score', axis=1)\
                .explode('cvss_new')

            # Transformando cada item em float
            df['cvss_new'] = pd.to_numeric(df['cvss_new'], downcast='float', errors='coerce')
            # filtrando apenas o maior CVSS_NEW de cada IP
            df = df.groupby(['region_code', "name", 'ip'], as_index=False)['cvss_new'].max()
            # Criando uma coluna 'cvss_mean' que armazena a média dos cvss por estado
            df['cvss_mean'] = df.groupby('region_code')['cvss_new'].transform('mean')
            #Criando um df somente com as 3 colunas necessárias para criar o mapa
            df = df[['cvss_mean', 'region_code', 'name']].drop_duplicates()

            fig = build_state_choropleth(
                df,
                color_column="cvss_mean",
                title="Average CVSS by state (only the major CVE per IP)",
                hover_label="region_code",
                color_label="Avg CVSS",
                geojson=brazil,
            )

        elif value == 'epss_score':

            df = dm.get_report_dataset(date_value, columns=['ip', "city", "vulns_epss"])
            df['region_code'] = df['city'].str.split(', ').str[1]
            if df.empty:
                return fig

            df['name'] = df['region_code'].map(state_id_map)
            df['epss_new'] = df['vulns_epss']
            df = df.drop('vulns_epss', axis=1)\
                .explode('epss_new')
            # Transformando cada item em float
            df['epss_new'] = pd.to_numeric(df['epss_new'], downcast='float', errors='coerce')
            # filtrando apenas o maior epss_new de cada IP
            df = df.groupby(['region_code', "name", 'ip'], as_index=False)['epss_new'].max()
            # Criando uma coluna 'epss_sum' que armazena a média dos epss por estado
            df['epss_mean'] = df.groupby('region_code')['epss_new'].transform('mean')

            # Criando um df somente com as 3 colunas necessárias para criar o mapa
            df = df[['epss_mean', 'region_code', 'name']].drop_duplicates()

            fig = build_state_choropleth(
                df,
                color_column="epss_mean",
                title="Average EPSS by state (only the major CVE per IP)",
                hover_label="region_code",
                color_label="Avg EPSS",
                geojson=brazil,
            )

        elif value == 'cve_id':

            df = dm.get_report_dataset(date_value, columns=["city", "vulns_cve_id"])
            df['region_code'] = df['city'].str.split(', ').str[1]
            if df.empty:
                return fig

            df['name'] = df['region_code'].map(state_id_map)
            df['cve_new'] = df['vulns_cve_id']
            df = df.drop('vulns_cve_id', axis=1)\
                .explode('cve_new')

            df = df[['region_code', 'name', 'cve_new']].drop_duplicates()
            df['n_cves'] = df.groupby(['region_code', 'name'])['cve_new'].transform(lambda x: x.nunique(dropna=True))
            
            fig = build_state_choropleth(
                df,
                color_column="n_cves",
                title="Number of different CVEs per state",
                hover_label="region_code",
                color_label="# CVEs",
                geojson=brazil,
            )

        elif value == 'ip_cvss':
            logging.debug(f"ip_cvss: {cvss_range_query}")

            df = dm.get_report_dataset(date_value, columns=['ip', "city", "vulns_cvss_score"])
            df['region_code'] = df['city'].str.split(', ').str[1]
            if df.empty:
                return fig
            df['name'] = df['region_code'].map(state_id_map)
            df['cvss_new'] = df['vulns_cvss_score']

            df = df.drop('vulns_cvss_score', axis=1) \
                .explode('cvss_new')

            df['cvss_new'] = df['cvss_new'].apply(lambda x: float(x))
            df = df.groupby(['region_code', "name", 'ip'], as_index=False)['cvss_new'].max()
            df = df[(df['cvss_new'] >= cvss_range_query[0]) & (df['cvss_new'] <= cvss_range_query[1])]
            df = df.groupby(by=['region_code', "name"]).agg(n_ips=('ip', pd.Series.nunique)).reset_index()

            fig = build_state_choropleth(
                df,
                color_column="n_ips",
                title="Number of IPs with CVEs within CVSS range by states",
                hover_label="region_code",
                color_label="Number of IPs",
                geojson=brazil,
            )

        return fig

    @app.callback(
        Output("url-redirect", "pathname", allow_duplicate=True),
        Output('store-filters', 'data', allow_duplicate=True),
        Input("query-4-graph", "clickData"),
        prevent_initial_call=True
    )
    def select_region_view4_to_report(data):
        """
        Callback to select a region on the choropleth map and redirect to the general analysis per record view.

        Args:
            data (dict): Click data from the choropleth map.

        Returns:
            tuple: Tuple containing the pathname and filter options.
        """

        logging.info(data)

        if not data:
            return no_update
            #, no_update

        region = ", " + data['points'][0]['hovertext']
        filter_opt = {"query-5-ag": {"city": {"filterType": "text", "type": "contains", 'filter': region}}}
        
        return "/dashboard/report", filter_opt

