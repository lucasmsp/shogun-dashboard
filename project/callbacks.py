from dash.dependencies import Output, Input
import pandas as pd
import plotly.express as px

import project.query1 as query1
import project.query2 as query2
import project.query3 as query3

def register_callbacks(app, dfs):
    
    query1.register_callback_query(app, dfs)
    query2.register_callback_query(app, dfs)
    query3.register_callback_query(app, dfs)
