from dash import html, dcc
import dash_bootstrap_components as dbc


def gen_subgraphs(n_cols, graphs):
    children = []
    row = []
    size = int(12 / n_cols)
    for i, graph in enumerate(graphs):
        mod_ = i % n_cols
        if (mod_ == 0) and (i != 0):
            children.append(dbc.Row(row, align="start", justify="center"))
            row = []
        row.append(dbc.Col(graph, width={'size': size, 'order': mod_ + 1}))

    if len(row) > 0:
        children.append(dbc.Row(row, align="start", justify="center"))

    return children


header_mapping = {
    'vulns_epss_rank': {
        'name': 'EPSS rank',
        "description": "EPSS rank vary from 0 (0%) to 1 (100%)",
        'type': 'string'
    },
    'vulns_epss': {
        'name': 'EPSS',
        "description": "EPSS Score vary from 0 (0%) to 1 (100%)",
        'type': 'float'
    },
    'n_cves': {
        'name': '# CVEs',
        "description": "Number of distinct vulnerabilities",
        "type": 'integer'
    },
    'n_ips': {
        'name': '# IPs',
        "description": "Number of IP addresses",
        "type": 'integer'
    },
    'n_orgs': {
        'name': '# Organizations',
        "description": "Number of organizations",
        "type": 'integer'
    },
    "n_as": {
        'name': "# AS",
        "description": "Number of Autonomous Systems",
        "type": 'integer'
    },
    'org_clean': {
        'name': "Organization",
        'description': "Organization registered as being responsible for the IP",
        'type': 'string'
    },
    'ip': {
        "name": 'IP',
        'description': "",
        'type': 'string',
    },
    'cpe_product': {
        'name': "Product name",
        'description': "",
        'type': 'string'
    },
    'vulns_cve_id': {
        'name': 'CVE',
        'description': "",
        'type': 'string'
    },
    'vulns_cvss_score': {
        "name": 'CVSS',
        "description": "CVSS stands for Common Vulnerability Scoring System, a standardized framework "
                       "for measuring the severity of security flaws in information systems. "
                       "The score vary from 0 to 10.",
        'type': 'float'
    }

}

def gen_columns_def(columns_names):
    columns = []
    raw_data = {}
    for i, c in enumerate(columns_names):
        new_column = {
            "field": c, "flex": 1,
            "headerName": header_mapping[c]['name'],
            'headerTooltip': header_mapping[c]['description']
        }
        if header_mapping[c]['type'] in ['integer', 'float']:
            new_column["filter"] = "agNumberColumnFilter"
            new_column['filterParams'] = {"filterOptions": ["equals", "notEqual", 'lessThan', 'greaterThan', 'inRange']}
        else:
            new_column['filterParams'] = {"filterOptions": ["equals", "notEqual", 'contains']}

        if i == 0:
            raw_data[c] = "Loading ..."
        elif header_mapping[c]['type'] == 'integer':
            raw_data[c] = 0
        elif header_mapping[c]['type'] == 'float':
            raw_data[c] = 0.0
        else:
            raw_data[c] = "-"

        columns.append(new_column)
    return columns, [raw_data]