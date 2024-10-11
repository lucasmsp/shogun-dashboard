import itertools
from dash import html, dcc, dash_table
import dash_bootstrap_components as dbc
from dash import Dash, dcc, html, Input, Output
import dash_ag_grid as dag
import plotly.express as px
import plotly.figure_factory as ff

import pandas as pd

INPUT_DATA = '3'
TAB_VIEW = "tab-2"

# constructs the layout for View 3
def register_layout_query():
    layout = [
        dbc.Row(
            dcc.Loading([
                dag.AgGrid(
                    id="query-3-ag",
                    rowData = [{"cve_id": "Processing...", "cvss_score": 0, "epss": 0, "n_ips": 0, 'n_orgs': 0}],
                    columnDefs=[
                        {"field": 'cve_id', "headerName": 'CVE', "cellRenderer": "GoToMitre",
                         "tooltipValueGetter": {"function": "'Click on the cell for more details'"},
                         "filterParams": {"filterOptions": ["equals", "notEqual", 'contains']}
                        },
                        {"field": 'cvss_score', "headerName": 'CVSS',
                        'tooltipValueGetter': {"function": "'CVSS Version: ' + params.data.cvss_version"},
                         "filter": "agNumberColumnFilter", "filterParams": {"filterOptions": ["equals","notEqual",'lessThan', 'greaterThan', 'inRange']}
                         },
                        {"field": 'epss', "headerName": 'EPSS',
                         'tooltipValueGetter': {"function": "'EPSS: ' + params.data.epss_rank"},
                         "filter": "agNumberColumnFilter",
                         "filterParams": {"filterOptions": ["equals", "notEqual", 'lessThan', 'greaterThan', 'inRange']}
                         },
                        {"field": 'n_ips', "headerName": "# IPs",
                         "filter": "agNumberColumnFilter", "filterParams": {"filterOptions": ["equals","notEqual",'lessThan', 'greaterThan', 'inRange']}
                         },
                        {"field": 'n_orgs', "headerName": "# Organizations",
                         "filter": "agNumberColumnFilter", "filterParams": {"filterOptions": ["equals","notEqual",'lessThan', 'greaterThan', 'inRange']}
                         },
                    ],
                    defaultColDef={"flex": 1, "filter": True},
                    columnSize="sizeToFit",
                    columnSizeOptions={"skipHeader": False},
                    dashGridOptions={
                        'tooltipInteraction': True,
                        'tooltipShowDelay': 10,
                        'tooltipHideDelay': 1000
                    }
                )
            ])
        ),

        html.Div(style={'height': '40px'}),

        html.H4(children="Choose the type of chart", style={'textAlign': 'Left'}),

        dbc.Row(
            dcc.Dropdown(
                id='dropdown-query3',
                options=[
                    {'label': 'Scatter plot - EPSS by CVSS Score', 'value': 'epss_cvss'},
                    {'label': 'Confusion Matrix - EPSS Rank by CVSS Rank', 'value': 'epss_rank_cvss_rank'},
                    {'label': 'Line plot - # IPs by CVSS', 'value': 'ips_cvss'},
                    {'label': 'Line plot - # IPs by EPSS', 'value': 'ips_epss'},
                    {'label': 'Line plot - # Organizations by CVSS', 'value': 'orgs_cvss'},
                    {'label': "Line plot - # Organizations by EPSS", 'value': 'orgs_epss'},
                ],
                clearable=False,
                value='epss_cvss'
            ),
            style={'marginTop': '32px'}
        ),

        dcc.Graph(
            id="query3-graph",
            config={
                'displayModeBar': False,
                'scrollZoom': False
            }
        )
    ]

    q3 = [
        html.H1(children="View 3 - Report of Common Vulnerabilities and Exposures (CVE)", className='wrapper'),

        html.Div(style={'height': '40px'}),

        html.H2(
            children="This visualization allows the analysis of the distribution of CVEs "
                     "in relation to IPs and organizations accessible on the Internet",
            style={'fontSize': '20px'}
        ),

        dbc.Tab(layout, label="Table")
    ]

    return q3


def find_expression(string):
    list_expressions = ['>=', '<=', '!=']
    for i in list_expressions:
        index = string.find(i)

        if index != -1:
            return i


# register all the callbacks in one place
def register_callback_query(dm, app):
    @app.callback(
        Output('query-3-ag', "rowData"),
        [
            Input('date-picker-single', 'value')
        ]
    )
    def update_table3(date_value):
        # if TAB_VIEW != active_tab:
        #     return [{}]
        print("[INFO][query3] - update_table3: ", date_value)

        df = dm.get_view_dataset(date_value, INPUT_DATA)
        if df.empty:
            return [{}]

        return df.to_dict('records')

    # TODO: Atualizar gráficos para usar o filtermodal
    @app.callback(
        Output('query3-graph', "figure"),
        Input('dropdown-query3', 'value'), 
        Input('date-picker-single', 'value')
    )
    def update_graphs(value, date_value):
        # if TAB_VIEW != active_tab:
        #     return {}
        print("[INFO][query3] update_graphs: ")

        df = dm.get_view_dataset(date_value, INPUT_DATA)

        if df.empty:
            return {}

        if value == 'epss_cvss':
            fig = px.scatter(df, x=df["cvss_score"], y=df['epss'], title="Scatter plot - EPSS by CVSS score",
                             color='epss_rank')
            fig.update_layout(
                xaxis_title="CVSS Score",
                yaxis_title="EPSS",
                # xaxis=dict(showticklabels=False),
                xaxis=dict(
                    tickmode='array',
                    tickvals=[0, 2, 4, 6, 8, 10],
                    range=[0, 10]
                )
            )
            return fig

        elif value == 'epss_rank_cvss_rank':
            z = df.groupby(["cvss_rank", "epss_rank"]).count() \
                .reset_index() \
                .pivot(index="cvss_rank", columns="epss_rank", values=["cve_id"]) \
                .fillna(0) \
                .reset_index()
            z.columns = ['epss_rank', '< 0.2', '< 0.4', '< 0.6', '< 0.8', '>= 0.8']

            severity_mapping = {
                "low": 1,
                "medium": 2,
                "high": 3,
                "critical": 4
            }
            z['severity'] = z['epss_rank'].map(severity_mapping)
            z = z.sort_values(by='severity', ascending=True)

            x = ["low", "medium", "high", "critical"]
            y = ['< 0.2', '< 0.4', '< 0.6', '< 0.8', '>= 0.8']
            z = z[y].T.values.tolist()
            z_text = [[str(y) for y in x] for x in z]

            fig = ff.create_annotated_heatmap(z, x=x, y=y, annotation_text=z_text, colorscale='Viridis')
            fig['data'][0]['showscale'] = True

            fig.update_layout(
                height=450,
                width=1250,
                title_text='Confusion Matrix - EPSS Rank by CVSS Rank',
                xaxis_title="CVSS Rank",
                yaxis_title="EPSS Rank",
                xaxis={'side': 'bottom'},
            )
            return fig

        elif value == "ips_cvss":
            df = df.groupby("cvss_score").sum("n_ips").reset_index()
            fig = px.line(df, x=df['cvss_score'], y=df['n_ips'], title="Line plot - # IPs by CVSS")
            fig.update_layout(
                xaxis_title="CVSS Score",
                yaxis_title="# IPs",
                xaxis=dict(
                    tickmode='array',
                    tickvals=[0, 2, 4, 6, 8, 10],
                    range=[0, 10]
                )
            )
            return fig

        elif value == "orgs_cvss":
            df = df.groupby("cvss_score").sum("n_orgs").reset_index()
            fig = px.line(df, x=df['cvss_score'], y=df['n_orgs'], title="Line plot - # Organizations by CVSS")
            fig.update_layout(
                xaxis_title="CVSS Score",
                yaxis_title="# Organizations",
                xaxis=dict(
                    tickmode='array',
                    tickvals=[0, 2, 4, 6, 8, 10],
                    range=[0, 10]
                )
            )
            return fig

        elif value == "orgs_epss":
            df = df.groupby("epss").sum("n_orgs").reset_index()
            fig = px.line(df, x=df['epss'], y=df['n_orgs'], title="Line plot - # Organizations by EPSS")
            fig.update_layout(
                xaxis_title="EPSS Score",
                yaxis_title="# Organizations",
                xaxis=dict(
                    tickmode='array',
                    tickvals=[0, 0.2, 0.4, 0.6, 0.8, 1.0],
                    range=[0, 1.0]
                )
            )
            return fig

        elif value == "ips_epss":
            df = df.groupby("epss").sum("n_ips").reset_index()
            fig = px.line(df, x=df['epss'], y=df['n_ips'], title="Line plot - # IPs by EPSS")
            fig.update_layout(
                xaxis_title="# EPSS Score",
                yaxis_title="# IPs",
                xaxis=dict(
                    tickmode='array',
                    tickvals=[0, 0.2, 0.4, 0.6, 0.8, 1.0],
                    range=[0, 1.0]
                )
            )

            return fig
