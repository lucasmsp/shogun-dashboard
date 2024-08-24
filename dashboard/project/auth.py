from dash import Input, Output, callback_context, State
import pandas as pd
import os

def register_callback_query(dm, app):

    @app.callback(
        Output('url-redirect', 'href'),
        [Input('logout-menu-item', 'n_clicks'), 
        Input('admin-menu-item', 'n_clicks'),
        Input('profile-menu-item', 'n_clicks')],
        prevent_initial_call=True
    )
    def handle_redirect(logout_clicks, admin_clicks, profile_clicks):
        ctx = callback_context

        if not ctx.triggered:
            return None

        triggered_id = ctx.triggered[0]['prop_id'].split('.')[0]

        if triggered_id == 'logout-menu-item' and logout_clicks:
            return "/logout"
        elif triggered_id == 'admin-menu-item' and admin_clicks:
            return "/admin"
        elif triggered_id == 'profile-menu-item' and profile_clicks:
            return "/profile"
        
        return None
    
    @app.callback(
        Output('store-date', 'data'),
        Input('date-picker-single', 'value')
    )
    def global_date(date_value):
        if date_value:
            file_path = os.path.join('date', 'selected_date.csv')
            if not os.path.exists('date'):
                os.makedirs('date')
            
            df = pd.DataFrame({'date': [date_value]})
            
            df.to_csv(file_path, index=False, mode='w')
            
            if os.path.exists(file_path):
                print(f"File found: {file_path}")
                content = pd.read_csv(file_path)
                # print(f"File content:\n{content}")
            else:
                print("File not found.")
            
            return date_value
        
    # @app.callback(
    #     Output('details-iframe', 'src'),
    #     Input('date-picker-single', 'value')
    # )
    # def update_iframe_src(selected_date):
    #     if selected_date is not None:
    #         return f"/details_ip?date={selected_date}"
    #     return "/details_ip"