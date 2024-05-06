from dash.dependencies import Output, Input
import plotly.express as px

import project.base as base
import project.query1 as query1
import project.query2 as query2
import project.query3 as query3

from datetime import date

def register_callbacks(dm, app):
  
    query1.register_callback_query(dm, app)
    query2.register_callback_query(dm, app)
    query3.register_callback_query(dm, app)