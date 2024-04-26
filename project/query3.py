import re

import numpy as np
import pandas as pd
from dash import html, dcc, dash_table
import plotly.express as px
import dash_bootstrap_components as dbc
from dash import Dash, dcc, html, Input, Output
import plotly.graph_objs as go

INPUT_DATA = 'v3'

# Precisamos ocultar o "org_list" e de alguma forma, disponibilizar ao usuário, se necessário. P.ex: apenas ao clicar ? por houver (pop-up), exportar como um arquivo csv ?
# quais gráficos fazer ?

#constructs the layout for View 3
def register_layout_query(dfs):
    # visualização 3
    q3 = [
        dbc.Row(
            children=[
                html.H1(children="View 3 - More details by CVE", className='wrapper'),
                # contém uma tabela iterativa Dash
                dbc.Row(
                    # Renders an interactive table component
                    dash_table.DataTable(

                        id='query-3-table',
                        columns=[
                            {"name": i, "id": i, "selectable": True, "deletable": True} for i in
                            sorted(dfs[INPUT_DATA].columns)
                        ],
                        # permite que a tabela seja editável
                        editable=True,
                        # permite filtragem da tabela
                        filter_action="native",
                        hidden_columns=['org_list'],
                        sort_action='custom',
                        sort_mode='multi',
                        sort_by=[],
                        row_selectable='multi',
                        row_deletable=True,
                        page_current=0,
                        page_size=5,
                        style_data={
                            'whiteSpace': 'normal',
                            'height': 'auto',
                            'max-height': '15px', 'min-height': '15px', 'height': '15px'
                        }
                    ),
                    style={'margin-top': '32px'}

                ),
                html.Div(id='datable-interactivity-container')
            ]
        )
    ]

    return q3


# register all the callbacks in one place
def register_callback_query(app, dfs):
    @app.callback(
        Output('query-3-table', "data"),
        Input('query-3-table', "sort_by")
    )


    def update_table3(sort_by):
        df = dfs[INPUT_DATA]
        df['org_list'] = df['org_list'].str.join(', ')

        df["cvss_rank"] = [float(str(i).replace("<", "").replace(">", "").replace("=", ""))
                           for i in df["cvss_rank"]]
        df["epss_rank"] = [float(str(i).replace("<", "").replace(">", "").replace("=", ""))
                           for i in df["epss_rank"]]

        if len(sort_by):
            df = df.sort_values(
                [col['column_id'] for col in sort_by],
                ascending=[
                    col['direction'] == 'asc'
                    for col in sort_by
                ],
                inplace=False
            )

        return df.to_dict('records')

    @app.callback(
        Output('query-3-table', "style_data_conditional"),
        Input('query-3-table', "sort_by")
    )
    def update_styles(sort_by):
        return [{
            'if': {'column_id': i['column_id']},
            'background_color': 'white'
        } for i in sort_by]

    @app.callback(
        Output('datable-interactivity-container', "children"),
        Input('query-3-table', "derived_virtual_data"),
        Input('query-3-table', "derived_virtual_selected_rows")
    )
    def update_graphs(rows, derived_virtual_selected_rows):
        if derived_virtual_selected_rows is None:
            derived_virtual_selected_rows = []

        dff = dfs[INPUT_DATA] if rows is None else pd.DataFrame(rows)

        # limita o dataframe às primeiras 10 linhas
        dff = dff.head(15)

        colors = ['red' if i in derived_virtual_selected_rows else '#0074D9'
                  for i in range(len(dff))]

        return [
            dcc.Graph(
                id=column,
                figure={
                    "data": [
                        {
                            "x": dff["cve_id"],
                            "y": dff[column],
                            # "type": "barh",
                            "mode": "markers",
                            "marker": {
                                "color": colors,
                                "size": 10,
                                "opacity": 0.8,
                                "line": {"width": 0.5, "color": "white"}
                            },
                        }
                    ],
                    "layout": {
                        "xaxis": {"automargin": True},
                        "yaxis": {
                            "automargin": True,
                            "title": {"text": column}
                        },
                        "height": 200,
                        "margin": {"t": 10, "l": 10, "r": 10},
                    },
                },
            )
            for column in ["cvss", "cvss_rank", "cvss_version", "epss_rank", "n_ips", "n_orgs"] if column in dff
        ]
