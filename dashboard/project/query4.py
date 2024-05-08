from dash import html, dcc, dash_table
import dash_bootstrap_components as dbc
from dash import Dash, dcc, html, Input, Output, State

import plotly.express as px
import plotly.graph_objs as go
import plotly.figure_factory as ff

import pyarrow.dataset as ds
import pandas as pd
import json

import project.base as base

def register_layout_query(dm):
    q4 = html.Div([
        html.H1("View 4 - IP Table", className='wrapper'),
        dash_table.DataTable(
            id='query-4-table',
            columns=[
                # {"name": 'ID', "id": "meta_id"},
                {"name": 'IP', "id": "ip_str"},
                {"name": 'OS', "id": 'os'},
                {"name": 'Organization', "id": 'org'},
                {"name": 'Hostnames', "id": 'hostnames'},
                {"name": 'Domains', "id": 'domains'}
            ],
            sort_action='custom',
            sort_mode='multi',
            sort_by=[],
            page_size=20,
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
        print("[INFO] update_table4: ", date_value, flush=True)

        df = dm.get_report_dataset(date_value, columns=["meta_id", "ip_str", "os", "org", "hostnames", "domains"])
        df['hostnames'] = df["hostnames"].str.join(", ") 
        df['domains'] = df["domains"].str.join(", ") 
        df['os'] = df["os"].fillna("-")
        # df = df.head(1000)

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
            filtered_data = dm.get_report_dataset(date_value, condition=condition, single_output=True)
            vulns = filtered_data.get('vulns', [])

            cvss_scores = []
            cve_ids = []
            description = []
            for cve_list in vulns:
                for cve in cve_list:
                    if 'cvss_score' in cve:
                        cvss_scores.append(cve['cvss_score'])
                        cve_ids.append(cve['cve_id'])
                        description.append(cve['description'])

            df = pd.DataFrame({'CVSS Score': cvss_scores, "CVE": cve_ids})

            fig = px.bar(df,
                x = 'CVE',
                y = 'CVSS Score',
                title = f"Vulnerabilities of IP {ip_str}",
                #labels= {'CVSS Score': 'CVSS Score', 'count': 'Count'}
            )

            vulns = filtered_data.get('vulns') if filtered_data else None

            cve_summary_card = [dbc.CardHeader("CVE summary")] + [
                html.P(children=[
                        html.Strong('CVE ID: '), html.Span(cve_id+ "\t"),
                        html.Strong('- Summary: '), html.Span(description+"\n")
                    ], className="card-text")
                for cve_id, description in zip(cve_ids, description)
            ]

            return html.Div([
                dcc.Graph(figure=fig),
                html.Div(cve_summary_card)
                ])

        return html.Div([
            html.H2("No row selected"),
        ])

