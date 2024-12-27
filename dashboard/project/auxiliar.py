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


color_style = {
    '<CVSS>': [
        {
            "condition": "params.data.<CVSS> >= 0 && params.data.<CVSS> <= 2",
            "style": {"backgroundColor": "#FFD700"},
        },
        {
            "condition": "params.data.<CVSS> > 2 && params.data.<CVSS> <= 4",
            "style": {"backgroundColor": "#FFA500"},
        },
        {
            "condition": "params.data.<CVSS> > 4 && params.data.<CVSS> <= 6",
            "style": {"backgroundColor": "#FF8C00"},
        },
        {
            "condition": "params.data.<CVSS> > 6 && params.data.<CVSS> <= 8",
            "style": {"backgroundColor": "#FF6347"},
        },
        {
            "condition": "params.data.<CVSS> > 8 && params.data.<CVSS> <= 10",
            "style": {"backgroundColor": "#FF4500"},
        },
    ],
    '<EPSS>': [
        {
            "condition": "params.data.<EPSS> >= 0 && params.data.<EPSS> <= 20",
            "style": {"backgroundColor": "#FFD700"},
        },
        {
            "condition": "params.data.<EPSS> > 20 && params.data.<EPSS> <= 40",
            "style": {"backgroundColor": "#FFA500"},
        },
        {
            "condition": "params.data.<EPSS> > 40 && params.data.<EPSS> <= 60",
            "style": {"backgroundColor": "#FF8C00"},
        },
        {
            "condition": "params.data.<EPSS> > 60 && params.data.<EPSS> <= 80",
            "style": {"backgroundColor": "#FF6347"},
        },
        {
            "condition": "params.data.<EPSS> > 80 && params.data.<EPSS> <= 100",
            "style": {"backgroundColor": "#FF4500"},
        },
    ],
    "asn": [
        {
            "condition": "params.data.as_seen == 'True'",
            "style": {"backgroundColor": "lightgreen"},
        },
        {
            "condition": "params.data.as_seen == 'False'",
            "style": {"backgroundColor": "lightcoral"},
        },
    ]
}

header_mapping = {

    # Information related to a vulnerability
    "vulns_cisa_date_added": {
        'name': "Date Added",
        "description": "Cisa's date added",
        'type': 'date'
    },
    "vulns_cisa_knownRansomwareCampaignUse": {
        'name': "Ransomware Use",
        "description": "Association with known ransomware campaigns",
        'type': "???"  # TODO
    },
    "vulns_cisa_product_vendor": {
        'name': "Product",
        'description': "Cisa Vendor-Product Info",
        'type': 'string'
    },
    "vulns_cvss_score_max": {
        'name': "CVSS (max)",
        'description': "Max value of CVSS",
        'type': 'float',
        'color_style': '<CVSS>'
    },
    "vulns_cvss_score_min": {
        'name': "CVSS (min)",
        'description': "Min value of CVSS",
        'type': 'float',
        'color_style': '<CVSS>'
    },
    "vulns_cvss_score_avg": {
        'name': "CVSS (avg)",
        'description': "Avg of CVSS",
        'type': 'float',
        'color_style': '<CVSS>'
    },
    'vulns_cve_id': {
        'name': 'CVE',
        'description': "CVE Identifier",
        'type': 'string'
    },
    'vulns_cvss_score': {
        "name": 'CVSS',
        "description": "CVSS stands for Common Vulnerability Scoring System, a standardized framework "
                       "for measuring the severity of security flaws in information systems. "
                       "The score vary from 0 to 10.",
        'type': 'float',
        'color_style': '<CVSS>'
    },
    "vulns_cwe": {
        'name': "CWE",
        "description": "CWE Identifier",
        'type': 'list-string'
    },
    'vulns_epss': {
        'name': 'EPSS',
        "description": "EPSS Score vary from 0 (0%) to 1 (100%)",
        'type': 'float',
        'color_style': '<EPSS>'
    },
    "vulns_epss_max": {  # rename vulns_epss
        'name': "EPSS (max)",
        'description': "Max value of EPSS",
        'type': 'float',
        'color_style': '<EPSS>'
    },
    "vulns_epss_avg": {
        'name': "EPSS (avg)",
        'description': "Avg of EPSS",
        'type': 'float',
        'color_style': '<EPSS>'
    },
    'vulns_epss_rank': {
        'name': 'EPSS rank',
        "description": "EPSS rank vary from 0 (0%) to 1 (100%)",
        'type': 'string'
    },
    'vulns_epss_min': {
        'name': 'EPSS (min)',
        "description": "EPSS vary from 0 (0%) to 1 (100%)",
        'type': 'string',
        'color_style': '<EPSS>'
    },
    'vulns_cvss_version': {
        'name': 'CVSS version',
        'description': 'Version of CVSS',
        'type': 'float'
    },
    'vulns_cisa_description': {
        'name': "Cisa's information",
        'description': "Cisa's vulnerability description",
        'type': 'string'
    },
    'cpe_product': {
        'name': "Product name",
        'description': "",
        'type': 'string'
    },
    "cisa_info": {
        'name': "Cisa's KEV",
        "description": "CISA Vulnerability Information",
        'type': '????'
    },
    "epss_info": {
        'name': "EPSS scores",
        "description": "EPSS scores information",
        'type': '????'
    },
    "cvss_info": {
        'name': "CVSS scores",
        "description": "CVSS scores information",
        'type': '????'
    },
    "epss_major": {  # rename  vulns_epss
        'name': "EPSS (major)",
        'description': "EPSS vary from 0 (0%) to 1 (100%)",
        'type': 'float',
        'color_style': '<EPSS>'
    },
    "avg_cvss": {
        "name": 'Avg CVSS',
        "description": '',
        "type": 'float',
        'color_style': '<CVSS>'
    },
    "avg_epss": {
        "name": 'Avg EPSS',
        "description": '',
        "type": 'float',
        'color_style': '<EPSS>'
    },

    # Quantifications
    "n_as": {
        'name': "# AS",
        "description": "Number of Autonomous Systems",
        "type": 'integer'
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
        'name': '# Orgs',
        "description": "Number of organizations",
        "type": 'integer'
    },
    "n_port": {
        'name': "# Ports",
        'description': "Number of ports",
        "type": 'integer'
    },
    "n_products": {
        'name': "# Products",
        'description': "Number of products with different vulnerabilities",
        "type": 'integer'
    },
    "n_vulns_in_cisa": {
        'name': "# CVEs in CISA",
        'description': "Number of vulnerabilities by CISA",
        'type': 'integer'
    },
    "n_vulns": {
        'name': "# CVEs",
        'description': "Number of vulnerabilities",
        'type': 'integer'
    },
    'n_vulns_cisa_knownRansomwareCampaignUse': {
        'name': '# Ransomware Use',
        'description': 'Number of known CVEs as being used in ransomware campaigns',
        'type': 'integer'
    },

    'ip': {
        "name": 'IP',
        'description': "",
        'type': 'string',
    },
    'org_clean': {
        'name': "Organization",
        'description': "Organization registered as being responsible for the IP",
        'type': 'string'
    },
    "port": {
        'name': "Port",
        'description': "Port identification",
        'type': 'integer'
    },
    'asn': {
        "name": 'ASN',
        "description": "ASNs seen in BGS are GREEN, not seen are RED",
        "type": 'string'
    },

    # About ASes
    'as_rank': {
        "name": 'Rank',
        "description": '',
        "type": 'float'
    },
    "as_announcing_addresses": {
        "name": 'Addresses',
        "description": '',
        "type": 'integer'
    },
    "as_country_name": {
        "name": 'Country',
        "description": '',
        "type": 'string'
    },
    "as_org_name": {
        "name": 'Name',
        "description": '',
        "type": 'string'
    },
    "as_org_country_name": {
        "name": 'Country',
        "description": '',
        "type": 'string'
    },

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

        if "color_style" in header_mapping[c]:
            key = header_mapping[c]["color_style"]
            styles = color_style[key].copy()
            for s in styles:
                s['condition'] = s['condition'].replace(key, c)

            new_column["cellStyle"] = { "styleConditions": styles }

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
