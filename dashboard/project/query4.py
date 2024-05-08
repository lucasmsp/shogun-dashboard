from dash import html, dcc, dash_table
import dash_bootstrap_components as dbc
from dash import Dash, dcc, html, Input, Output, State

import plotly.express as px
import plotly.graph_objs as go
import plotly.figure_factory as ff

import pandas as pd
import json

from deltalake import DeltaTable

import pyarrow.dataset as ds

import project.base as base

dt = DeltaTable("/opt/output_data/tlhop-epss-dashboard.delta")
dataset = dt.to_pyarrow_dataset()

def register_layout_query(dm):
    q4 = html.Div([
        html.H1("View 4 - IP Table", className='wrapper'),
        dash_table.DataTable(
            id='query-4-table',
            columns=[
                {"name": 'meta', "id": "meta_id"},
                {"name": 'IP', "id": "ip_str"},
                {"name": 'OS', "id": 'os'},
                {"name": 'Organization', "id": 'org'},
                {"name": 'Hostnames', "id": 'hostnames'},
                {"name": 'Domains', "id": 'domains'}
            ],
            sort_action='custom',
            sort_mode='multi',
            sort_by=[],
            page_size=10,
            style_data={
                'whiteSpace': 'normal',
                'height': 'auto',
                'max-height': '15px', 'min-height': '15px', 'height': '15px'
            }
        ),
        html.Div(id="output")
    ], style={'margin-top': '32px'})

    return q4


def register_callback_query(dm, app):
    @app.callback(
        Output('query-4-table', 'data'),
        Input('date-picker-single', 'date')
    )
    def update_table4(date_value):
        print("[INFO] update_table4: ", date_value)
        df = dataset.to_table(columns=["meta_id", "ip_str", "os", "org", "hostnames", "domains"]).to_pandas()
        df = df.head(1000)

        return df.to_dict('records')
        
    @app.callback(
        Output("output", "children"),
        Input("query-4-table", "active_cell"),
        State('query-4-table', 'data'),
        State('date-picker-single', 'date')
    )
    def update_graph(active_cell, table_data, date_value):
        if active_cell:

            row = active_cell['row']
            meta_id = table_data[row]['meta_id']
            ip_str = table_data[row]['ip_str']

            condition = (ds.field("meta_id") == meta_id)
            filtered_data = dataset.filter(condition).head(1).to_pydict()

            vulns = filtered_data.get('vulns') if filtered_data else None

            cvss_scores = []
            cve_ids = []
            description = []
            if vulns:
                for cve_list in vulns:
                    for cve in cve_list:
                        if 'cvss_score' in cve:
                            cvss_scores.append(cve['cvss_score'])
                            cve_ids.append(cve['cve_id'])
                            description.append(cve['description'])

            df = pd.DataFrame({'CVSS Score': cvss_scores})

            fig = px.bar(df,
                x='CVSS Score',
                title=f"Vulnerabilities of IP {ip_str}",
                labels={'CVSS Score': 'CVSS Score', 'count': 'Count'}
            )

            vulns = filtered_data.get('vulns') if filtered_data else None

            cve_summary_list = [
                html.Div([
                    html.H3(f"CVE ID: {cve_id}"),
                    html.H2(f"Summary: {description}")
                ]) for cve_id, description in zip(cve_ids, description)
            ]

            return html.Div([
                dcc.Graph(figure=fig),
                html.Div(cve_summary_list)
            ])

        return html.Div([
            html.H2("No row selected"),
        ])

