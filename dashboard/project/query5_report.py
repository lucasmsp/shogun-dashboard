from dash import html, dcc, Input, Output
import dash_ag_grid as dag
from dash.exceptions import PreventUpdate

import dash_bootstrap_components as dbc

import re

from flask_login import current_user
from project.auxiliar import logging
from project.filters import *


def register_layout_query(filter_modal={}):
    """
    Register the layout for the fifth query (general analysis per record).

    Args:
        filter_modal (dict): Filter modal configuration.

    Returns:
        dbc.Card: Layout for the fifth query.
    """

    aggrid = dag.AgGrid(
                id="query-5-ag",
                rowData = [{"data": "Processing...", "ip": "0", "port": 0, "city": "", "os": "", "asn": "",
                            "org_clean": "", "hostnames": "", "domains": "", "score": 0, "meta_id": ""
                            }],
                filterModel=filter_modal,
                columnDefs=[
                    {"field": 'servers', "headerName": 'SERVICE', "cellRenderer": "markdown",
                      'width': 300, 'maxWidth': 500, "resizable": True,  "filter": "agTextColumnFilter",
                        "filterParams": {
                            "buttons": ["reset", "apply"],
                            "closeOnApply": True
                        }},
                    {"field": 'ip', "headerName": 'IP',  "cellRenderer": "IPLink", 
                     "tooltipValueGetter": {"function": "'Click on the cell for more details'"}, 
                     'width': 150, 'maxWidth': 200, "resizable": True, "filter": "agTextColumnFilter",
                        "filterParams": {
                            "buttons": ["reset", "apply"],
                            "closeOnApply": True
                        }
                     },
                    {"field": 'port', "headerName": 'PORT', "resizable": False, 'width': 100, 'maxWidth': 100,
                        "filter": "agNumberColumnFilter",
                        "filterParams": {
                            "buttons": ["apply", "reset"],
                            "closeOnApply": True
                        },
                    },
                    {"field": 'city', "headerName": "CITY", 'width': 150, "wrapText": True, 
                     "filter": "agTextColumnFilter",
                        "filterParams": {
                            "buttons": ["reset", "apply"],
                            "closeOnApply": True
                        }
                    },
                    {"field": 'os', "headerName": "OS", 'width': 80, "wrapText": True, 
                     "filter": "agTextColumnFilter",
                        "filterParams": {
                            "buttons": ["reset", "apply"],
                            "closeOnApply": True
                        }},
                    {"field": 'asn', "headerName": "ASN",  'maxWidth': 120, "wrapText": True, 
                     "filter": "agTextColumnFilter",
                        "filterParams": {
                            "buttons": ["reset", "apply"],
                            "closeOnApply": True
                        }},
                    {"field": 'org_clean', "headerName": "ORGANIZATION", "wrapText": True, 
                     "filter": "agTextColumnFilter",
                        "filterParams": {
                            "buttons": ["reset", "apply"],
                            "closeOnApply": True
                        }},
                    {"field": 'hostnames', "headerName": "HOSTNAMES", "wrapText": True, 
                     "filter": "agTextColumnFilter",
                        "filterParams": {
                            "buttons": ["reset", "apply"],
                            "closeOnApply": True
                        }, "cellRenderer": "markdown"},
                    {"field": 'domains', "headerName": "DOMAINS", "wrapText": True, "cellRenderer": "markdown", 
                     "filter": "agTextColumnFilter",
                        "filterParams": {
                            "buttons": ["reset", "apply"],
                            "closeOnApply": True
                        }},
                    {"field": 'score', "headerName": "SCORE", "resizable": False, 'width': 100, 'maxWidth': 100,
                        "filter": "agNumberColumnFilter",
                        "filterParams": {
                            "buttons": ["apply", "reset"],
                            "closeOnApply": True
                        },},
                    {"field": 'meta_id', "headerName": 'VOTE', "resizable": False, "cellRenderer": "launchBtn",
                     'width': 170, 'maxWidth': 170, "filter": False, 'sortable': False},
                ],
                defaultColDef={"flex": 1, "filter": True,
                               "valueFormatter": {"function": "typeof params.value === 'number' ? d3.format('.2f')(params.value) : params.value"}
                               },
                columnSize="sizeToFit",
                columnSizeOptions={"skipHeader": False},
                dashGridOptions={
                    'tooltipInteraction': True,
                    'tooltipShowDelay': 10,
                    'tooltipHideDelay': 1000,
                    "rowHeight": 120,
                    'animateRows': False,
                    "suppressColumnMoveAnimation": True,

                    # The number of rows rendered outside the viewable area the grid renders.
                    "rowBuffer": 0,
                    # How many blocks to keep in the store. Default is no limit, so every requested block is kept.
                    "maxBlocksInCache": 2,
                    "cacheBlockSize": 5000, # complete data has +- 35k records
                    "cacheOverflowSize": 2,
                    "maxConcurrentDatasourceRequests": 2,
                    "infiniteInitialRowCount": 1,
                },
                rowModelType="infinite",
                getRowId="params.data.index",
                style={"height": "1000px"},
                className="ag-theme-alpine compact"
            )

    elements = [
        html.H2(
            children=("Shodan's banners about IPs with vulnerabilities in Brazil. "
                      "Using this interface, users can filter banners by each column, "
                      "ranking its vulnerabilities and clicking on IP column to check details."
                      ),
            style={'fontSize': '20px', 'padding': 20}
        ),
        dbc.Row(dcc.Loading([aggrid]))
    ]

    tab5_content = dbc.Card(
        dbc.CardBody(
            html.Div(children=[dbc.Row(children=elements)], className="wrapper_table",
                     style={"width": "100%", "height": "100%"}),
        ),
        className="mt-3",
        id="tab5_content"
    )

    return tab5_content

def register_callback_query(dm, app):
    """
    Register the callbacks for the fifth query (general analysis per record).

    Args:
        dm (DataManager): Data manager instance.
        app (dash.Dash): Dash application instance.
    """
    @app.callback(
        Output('query-5-ag', "getRowsResponse"),
        [
            Input('date-picker-single', 'value'),
            Input("query-5-ag", "getRowsRequest"),
            Input('store-filters', 'data')]
    )
    def update_table5(date_value, request, stored_filters):
        """
        Callback to update the table data based on the selected date and filters.

        Args:
            date_value (str): Date selected from the date picker.
            request (dict): Request parameters from the AG Grid.
            stored_filters (dict): Stored filters.

        Returns:
            dict: Dictionary containing the row data and row count.
        """

        if not date_value:
            return {"rowData": [], "rowCount": 0}

        logging.info(f"[INFO][query5] - update_table5: {date_value}")

        df = dm.get_report_dataset(
            date_value,
            columns=["data", "ip", "port", "city", "os", "org_clean", "hostnames", "domains",
                     "meta_id", "vulns_epss", "asn", 'servers'],
            sort_by='score',
            ascending=False,
            compute_score=True,
            user_id=current_user.id,
            for_each=False
        )

        if stored_filters and 'query-5-ag' in stored_filters:
            map_filters = stored_filters['query-5-ag']
            for col, filter_conf in map_filters.items():
                try:
                    df = filter_by_model(filter_conf, df, col)
                except Exception as e:
                    logging.error(f"[ERROR] query 5 - error applying map filter")

        lines = len(df.index)
        logging.info(f"[INFO] query 5 - original dataset has {lines} lines")

        if request:
            if request["filterModel"]:
                filters = request["filterModel"]
                for col, filter_conf in filters.items():
                    try:
                        df = filter_by_model(filter_conf, df, col)
                        lines = len(df.index)
                    except:
                        logging.error("[ERROR] query 5 - error filter grid5")

            if request["sortModel"]:
                sorting = []
                asc = []
                for sort in request["sortModel"]:
                    sorting.append(sort["colId"])
                    if sort["sort"] == "asc":
                        asc.append(True)
                    else:
                        asc.append(False)
                df = df.sort_values(by=sorting, ascending=asc)

            start_row = request["startRow"]
            end_row = request["endRow"]

            partial = df.iloc[start_row:end_row]
            logging.info("[INFO] query 5 - finishing output")

            if lines == 0:
                lines = 1

            return {"rowData": partial.to_dict("records"), "rowCount": lines}

        raise PreventUpdate

