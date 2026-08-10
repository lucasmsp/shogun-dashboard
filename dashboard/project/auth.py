from dash import Input, Output, callback_context, State
import pandas as pd
import os

def register_callback_query(dm, app):
    """
    Register the callback query for the authentication page.

    Args:
        dm (DataModule): Data module.
        app (dash.Dash): Dash application.
    
    Returns:
        None
    """

    @app.callback(
        Output('url-redirect', 'href'),
        Output('url-redirect', 'refresh'),

        [Input('logout-menu-item', 'n_clicks'),
        Input('admin-menu-item', 'n_clicks'),
        Input('profile-menu-item', 'n_clicks')],
        prevent_initial_call=True
    )
    def handle_redirect(logout_clicks, admin_clicks, profile_clicks):
        ctx = callback_context

        if not ctx.triggered:
            return None, False

        triggered_id = ctx.triggered[0]['prop_id'].split('.')[0]

        if triggered_id == 'logout-menu-item' and logout_clicks:
            return "/logout", True
        elif triggered_id == 'admin-menu-item' and admin_clicks:
            return "/admin", True
        elif triggered_id == 'profile-menu-item' and profile_clicks:
            return "/profile", True

        return None, False
    
    @app.callback(
        Output('store-date', 'data'),
        Input('date-picker-single', 'value')
    )
    def global_date(date_value):
        """
        Global date callback.

        Args:
            date_value (str): Date value.
        
        Returns:
            str: Date value.
        """
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
