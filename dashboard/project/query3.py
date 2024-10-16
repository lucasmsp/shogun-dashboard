import itertools

import dash_bootstrap_components as dbc
from dash import Dash, dcc, html, Input, Output, no_update
import dash_ag_grid as dag
import plotly.express as px
import plotly.figure_factory as ff

from project.auxiliar import gen_subgraphs

import pandas as pd

INPUT_DATA = '3'

# constructs the layout for View 3
def register_layout_query(filter_modal={}):
    elements = [
        dbc.Row(
            html.Div([
                html.H1(children="View 3 - Report of Common Vulnerabilities and Exposures (CVE)",
                        className='wrapper', style={'textAlign': 'center'}),
                html.H2(
                    children="This visualization allows the analysis of the distribution of CVEs "
                             "in relation to IPs and organizations accessible on the Internet",
                    style={'fontSize': '20px', 'top-padding': '40px', 'bottom-padding': '40px'}
                )
            ])
        ),

        dcc.Loading([
            dag.AgGrid(
                id="query-3-ag",
                rowData = [{"vulns_cve_id": "Processing...", "vulns_cvss_score": 0, "vulns_epss": 0, "n_ips": 0, 'n_orgs': 0}],
                columnDefs=[
                    {"field": 'vulns_cve_id', "headerName": 'CVE', "cellRenderer": "GoToMitre",
                     "tooltipValueGetter": {"function": "'Click on the cell for more details'"},
                     "filterParams": {"filterOptions": ["equals", "notEqual", 'contains']},
                         # "cellStyle": {
                         #     "styleConditions": [
                         #         {
                         #             "condition": "params.data.verified === true",
                         #             "style": {"backgroundColor": "lightgreen"},
                         #         },
                         #         {
                         #             "condition": "params.data.verified === false",
                         #             "style": {"backgroundColor": "lightcoral"},
                         #         },
                         #         {
                         #             "condition": "params.data.verified === null",
                         #             "style": {"backgroundColor": "lightgrey"},
                         #         },
                         #
                         #     ],
                         # }
                    },
                    {"field": 'vulns_cvss_score', "headerName": 'CVSS',
                    'tooltipValueGetter': {"function": "'CVSS Version: ' + params.data.vulns_cvss_version"},
                     "filter": "agNumberColumnFilter", "filterParams": {"filterOptions": ["equals","notEqual",'lessThan', 'greaterThan', 'inRange']},
                         "cellStyle": {
                             "styleConditions": [
                                 {
                                     "condition": "params.data.vulns_cvss_score >= 0 && params.data.vulns_cvss_score <= 2",
                                     "style": {"backgroundColor": "#FFD700"},
                                 },
                                 {
                                     "condition": "params.data.vulns_cvss_score > 2 && params.data.vulns_cvss_score <= 4",
                                     "style": {"backgroundColor": "#FFA500"},
                                 },
                                 {
                                     "condition": "params.data.vulns_cvss_score > 4 && params.data.vulns_cvss_score <= 6",
                                     "style": {"backgroundColor": "#FF8C00"},
                                 },
                                 {
                                     "condition": "params.data.vulns_cvss_score > 6 && params.data.vulns_cvss_score <= 8",
                                     "style": {"backgroundColor": "#FF6347"},
                                 },
                                 {
                                     "condition": "params.data.vulns_cvss_score > 8 && params.data.vulns_cvss_score <= 10",
                                     "style": {"backgroundColor": "#FF4500"},
                                 },
                             ],
                         },
                     },
                    {"field": 'vulns_epss', "headerName": 'EPSS',
                     'tooltipValueGetter': {"function": "'EPSS: ' + params.data.vulns_epss_rank"},
                     "filter": "agNumberColumnFilter",
                     "filterParams": {"filterOptions": ["equals", "notEqual", 'lessThan', 'greaterThan', 'inRange']},
                         "cellStyle": {
                             "styleConditions": [
                                 {
                                     "condition": "params.data.vulns_epss >= 0 && params.data.vulns_epss <= 0.2",
                                     "style": {"backgroundColor": "#FFD700"},
                                 },
                                 {
                                     "condition": "params.data.vulns_epss > 0.2 && params.data.vulns_epss <= 0.4",
                                     "style": {"backgroundColor": "#FFA500"},
                                 },
                                 {
                                     "condition": "params.data.vulns_epss > 0.4 && params.data.vulns_epss <= 0.6",
                                     "style": {"backgroundColor": "#FF8C00"},
                                 },
                                 {
                                     "condition": "params.data.vulns_epss > 0.6 && params.data.vulns_epss <= 0.8",
                                     "style": {"backgroundColor": "#FF6347"},
                                 },
                                 {
                                     "condition": "params.data.vulns_epss > 0.8 && params.data.vulns_epss <= 1",
                                     "style": {"backgroundColor": "#FF4500"},
                                 },
                             ],
                         },
                     },
                    {"field": 'vulns_cwe', "headerName": "CWE"},
                    {"field": 'n_as', "headerName": "# AS"},
                    {"field": 'n_ips', "headerName": "# IPs",
                     "filter": "agNumberColumnFilter", "filterParams": {"filterOptions": ["equals","notEqual",'lessThan', 'greaterThan', 'inRange']}
                     },
                    {"field": 'n_orgs', "headerName": "# Organizations",
                     "filter": "agNumberColumnFilter", "filterParams": {"filterOptions": ["equals","notEqual",'lessThan', 'greaterThan', 'inRange']}
                     },
                    {"headerName": "Cisa's KEV",
                            "suppressStickyLabel": True,
                            "children": [
                                {"field": "vulns_cisa_date_added", "headerName": "Date Added", "width": 140, "columnGroupShow": "closed"},
                                {"field": "vulns_cisa_knownRansomwareCampaignUse", "headerName": "Ransomware Use", "width": 140,
                                 'tooltipValueGetter': {"function":
                                                            "params.data.vulns_cisa_description"
                                                        },
                                 "columnGroupShow": "closed"
                                 }
                            ],
                        },
                ],
                defaultColDef={"flex": 1, "filter": True},
                columnSize="sizeToFit",
                columnSizeOptions={"skipHeader": False},
                dashGridOptions={
                    "rowSelection": "single",
                    'tooltipInteraction': True,
                    'tooltipShowDelay': 10,
                    'tooltipHideDelay': 1000,
                    "animateRows": False
                }
            )
        ]),
        dbc.Row(dbc.Col(html.Hr(style={"width": "100%", 'top-padding': '10px'}), width={'size': 10, 'offset': 1})),
        dbc.Row([html.Div(id='query-3-graph', children=[])])

    ]

    tab3_content = dbc.Card(
        dbc.CardBody(
            html.Div(children=[dbc.Row(children=elements)], className="wrapper"),
        ),
        className="mt-3",
        id="tab3_content"
    )

    return tab3_content


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
        Input('date-picker-single', 'value')
    )
    def update_table3(date_value):
        print("[INFO][query3] - update_table3: ", date_value)
        df = dm.get_view_dataset(date_value, INPUT_DATA)
        if df.empty:
            return [{}]

        df['vulns_cwe'] = df['vulns_cwe'].apply(lambda x: ','.join(map(str, x)))
        #
        # df['cisa_info'] = df['cisa_info'].apply(lambda x: {} if pd.isna(x) else x)
        # tmp = pd.json_normalize(df.pop("cisa_info"))[['date_added', 'description', 'knownRansomwareCampaignUse']]
        # df = pd.concat([df, tmp], axis=1)

        return df.to_dict('records')

    # TODO: Atualizar gráficos para usar o filtermodal
    @app.callback(
        Output('query-3-graph', "children"),
        Input('date-picker-single', 'value')
    )
    def update_graphs(date_value):

        print("[INFO][query3] update_graphs: ")

        df = dm.get_view_dataset(date_value, INPUT_DATA)

        if df.empty:
            return {}

        graphs = []

        # fig 1
        fig = px.scatter(df, x=df["vulns_cvss_score"], y=df['vulns_epss'],
                         title="Scatter plot - EPSS by CVSS score",
                         color='vulns_epss_rank')
        fig.update_layout(
            xaxis_title="CVSS Score",
            yaxis_title="EPSS",
            xaxis=dict(
                tickmode='array',
                tickvals=[0, 2, 4, 6, 8, 10],
                range=[0, 10]
            )
        )
        graph = dcc.Graph(figure=fig, config={'displayModeBar': False, 'scrollZoom': False})
        graphs.append(graph)

        # fig 2
        tmp1 = df.groupby(["vulns_cvss_rank", "vulns_epss_rank"]).count() \
            .reset_index() \
            .pivot(index="vulns_cvss_rank", columns="vulns_epss_rank", values=["vulns_cve_id"]) \
            .fillna(0) \
            .reset_index()
        tmp1.columns = ['vulns_epss_rank', '< 0.2', '< 0.4', '< 0.6', '< 0.8', '>= 0.8']

        severity_mapping = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4
        }
        tmp1['severity'] = tmp1['vulns_epss_rank'].map(severity_mapping)
        tmp1 = tmp1.sort_values(by='severity', ascending=True)

        x = ["low", "medium", "high", "critical"]
        y = ['< 0.2', '< 0.4', '< 0.6', '< 0.8', '>= 0.8']
        tmp1 = tmp1[y].T.values.tolist()
        z_text = [[str(y) for y in x] for x in tmp1]

        fig = ff.create_annotated_heatmap(tmp1, x=x, y=y, annotation_text=z_text, colorscale='Viridis')
        fig['data'][0]['showscale'] = True

        fig.update_layout(
            title_text='Confusion Matrix - EPSS Rank by CVSS Rank',
            xaxis_title="CVSS Rank",
            yaxis_title="EPSS Rank",
            xaxis={'side': 'bottom'},
        )
        graph = dcc.Graph(figure=fig, config={'displayModeBar': False, 'scrollZoom': False})
        graphs.append(graph)

        # fig 3
        tmp2 = df.groupby("vulns_cvss_score").sum("n_ips").reset_index()
        fig = px.line(tmp2, x=tmp2['vulns_cvss_score'], y=tmp2['n_ips'], title="Line plot - # IPs by CVSS")
        fig.update_layout(
            xaxis_title="CVSS Score",
            yaxis_title="# IPs",
            xaxis=dict(
                tickmode='array',
                tickvals=[0, 2, 4, 6, 8, 10],
                range=[0, 10]
            )
        )
        graph = dcc.Graph(figure=fig, config={'displayModeBar': False, 'scrollZoom': False})
        graphs.append(graph)

        # fig 4
        tmp3 = df.groupby("vulns_cvss_score").sum("n_orgs").reset_index()
        fig = px.line(tmp3, x=tmp3['vulns_cvss_score'], y=tmp3['n_orgs'], title="Line plot - # Organizations by CVSS")
        fig.update_layout(
            xaxis_title="CVSS Score",
            yaxis_title="# Organizations",
            xaxis=dict(
                tickmode='array',
                tickvals=[0, 2, 4, 6, 8, 10],
                range=[0, 10]
            )
        )
        graph = dcc.Graph(figure=fig, config={'displayModeBar': False, 'scrollZoom': False})
        graphs.append(graph)

        # fig 5
        tmp4 = df.groupby("vulns_epss").sum("n_orgs").reset_index()
        fig = px.line(tmp4, x=tmp4['vulns_epss'], y=tmp4['n_orgs'], title="Line plot - # Organizations by EPSS")
        fig.update_layout(
            xaxis_title="EPSS Score",
            yaxis_title="# Organizations",
            xaxis=dict(
                tickmode='array',
                tickvals=[0, 0.2, 0.4, 0.6, 0.8, 1.0],
                range=[0, 1.0]
            )
        )
        graph = dcc.Graph(figure=fig, config={'displayModeBar': False, 'scrollZoom': False})
        graphs.append(graph)

        # fig 6
        tmp5 = df.groupby("vulns_epss").sum("n_ips").reset_index()
        fig = px.line(tmp5, x=tmp5['vulns_epss'], y=tmp5['n_ips'], title="Line plot - # IPs by EPSS")
        fig.update_layout(
            xaxis_title="EPSS Score",
            yaxis_title="# IPs",
            xaxis=dict(
                tickmode='array',
                tickvals=[0, 0.2, 0.4, 0.6, 0.8, 1.0],
                range=[0, 1.0]
            )
        )
        graph = dcc.Graph(figure=fig, config={'displayModeBar': False, 'scrollZoom': False})
        graphs.append(graph)

        children = gen_subgraphs(n_cols=3, graphs=graphs)
        return children

    @app.callback(
        Output("url-redirect", "pathname", allow_duplicate=True),
        Output('store-filters', 'data', allow_duplicate=True),
        Input("query-3-ag", "cellClicked"),
        Input("query-3-ag", "selectedRows"),
        prevent_initial_call=True
    )
    def select_orgs_ips(cell, row):
        print(f"[INFO] select_orgs_ips: Cell {cell} and row {row}")
        if cell and row:
            if cell.get("colId", "") == "n_orgs":
                cve_value = row[0].get('vulns_cve_id')
                filter_opt = {
                    "query-2a-grid": {'vulns_cve_id': {'filterType': 'text', 'type': 'contains', 'filter': cve_value}}}
                return "/dashboard/view2a", filter_opt

        return no_update, no_update
