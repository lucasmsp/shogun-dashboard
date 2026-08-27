import pandas as pd


def filter_by_model(filter_modal, df, col):
    """
    Filter the DataFrame by a model.

    Args:
        filter_modal (dict): Filter model.
        df (pd.DataFrame): DataFrame to filter.
        col (str): Column to filter.
    
    Returns:
        pd.DataFrame: Filtered DataFrame.
    """

    if "operator" in filter_modal:
        # is a filter with multiple conditions
        if filter_modal['operator'] == "AND":
            # we support up to 2 conditions
            df = filter_generic(filter_modal["condition1"], df, col)
            df = filter_generic(filter_modal["condition2"], df, col)
        elif filter_modal['operator'] == "OR":
            # TODO
            pass
        else:
            print("[ERROR] Filter operator type not supported yet.")
        return df
    else:
        # is a single filter
        return filter_generic(filter_modal, df, col)

def filter_generic(filter_modal, df, col):
    """
    Filter the DataFrame by a generic filter.

    Args:
        filter_modal (dict): Filter model.
        df (pd.DataFrame): DataFrame to filter.
        col (str): Column to filter.
    
    Returns:
        pd.DataFrame: Filtered DataFrame.
    """
    return filter_df(df, filter_modal, col)

# TODO !
def filter_text(filter_modal, df, col):
    """
    Filter the DataFrame by a text filter.

    Args:
        filter_modal (dict): Filter model.
        df (pd.DataFrame): DataFrame to filter.
        col (str): Column to filter.
    
    Returns:
        pd.DataFrame: Filtered DataFrame.
    """
    col_query = filter_modal.get(col, None)
    if col_query:

        type_ = col_query.get("type", 'contains')
        value = col_query.get("filter", '')
        if type_ == "contains":
            df = df[df[col].astype(str).str.contains(str(value), case=False, na=False)]
        elif type_ == "notContains":
            df = df[~df[col].astype(str).str.contains(str(value), case=False, na=False)]
        elif type_ == "startsWith":
            df = df[df[col].astype(str).str.lower().str.startswith(str(value).lower(), na=False)]
        elif type_ == "notStartsWith":
            df = df[~df[col].astype(str).str.lower().str.startswith(str(value).lower(), na=False)]
        elif type_ == "endsWith":
            df = df[df[col].astype(str).str.lower().str.endswith(str(value).lower(), na=False)]
        elif type_ == "notEndsWith":
            df = df[~df[col].astype(str).str.lower().str.endswith(str(value).lower(), na=False)]
        elif type_ == "equals":
            df = df[df[col].astype(str).str.lower() == str(value).lower()]
        elif type_ == "notEqual":
            df = df[df[col].astype(str).str.lower() != str(value).lower()]

    return df

def filter_number(filter_modal, df, col):
    """
    Filter the DataFrame by a number filter.

    Args:
        filter_modal (dict): Filter model.
        df (pd.DataFrame): DataFrame to filter.
        col (str): Column to filter.
    
    Returns:
        pd.DataFrame: Filtered DataFrame.
    """
    opt =  filter_modal.get(col, None)
    if opt:
        type_ = opt.get("type", 'equals')
        value = opt.get("filter", '')
        if type_ == "equals":
            df = df[df[col] == value]
        elif type_ == "lessThan":
            df = df[df[col] <= value]
        elif type_ == "greaterThan":
            df = df[df[col] >= value]
        elif type_ == "notEqual":
            df = df[df[col] != value]
    return df


operators = {
        "greaterThanOrEqual": "ge",
        "lessThanOrEqual": "le",
        "lessThan": "lt",
        "greaterThan": "gt",
        "notEqual": "ne",
        "equals": "eq",
    }

def filter_df(dff, filter_model, col):
    """
    Filter the DataFrame by a filter model.

    Args:
        dff (pd.DataFrame): DataFrame to filter.
        filter_model (dict): Filter model.
        col (str): Column to filter.
    
    Returns:
        pd.DataFrame: Filtered DataFrame.
    """

    if "filter" in filter_model:
        if filter_model["filterType"] == "date":
            crit1 = filter_model["dateFrom"]
            crit1 = pd.Series(crit1).astype(dff[col].dtype)[0]
            if "dateTo" in filter_model:
                crit2 = filter_model["dateTo"]
                crit2 = pd.Series(crit2).astype(dff[col].dtype)[0]
        else:
            crit1 = filter_model["filter"]
            if filter_model.get("filterType") != "text":
                try:
                    crit1 = pd.Series(crit1).astype(dff[col].dtype)[0]
                except Exception:
                    pass
            if "filterTo" in filter_model:
                crit2 = filter_model["filterTo"]
                if filter_model.get("filterType") != "text":
                    try:
                        crit2 = pd.Series(crit2).astype(dff[col].dtype)[0]
                    except Exception:
                        pass
    if "type" in filter_model:
        if filter_model["type"] == "contains":
            dff = dff.loc[dff[col].astype(str).str.contains(str(crit1), case=False, na=False)]
        elif filter_model["type"] == "notContains":
            dff = dff.loc[~dff[col].astype(str).str.contains(str(crit1), case=False, na=False)]
        elif filter_model["type"] == "startsWith":
            dff = dff.loc[dff[col].astype(str).str.lower().str.startswith(str(crit1).lower(), na=False)]
        elif filter_model["type"] == "notStartsWith":
            dff = dff.loc[~dff[col].astype(str).str.lower().str.startswith(str(crit1).lower(), na=False)]
        elif filter_model["type"] == "endsWith":
            dff = dff.loc[dff[col].astype(str).str.lower().str.endswith(str(crit1).lower(), na=False)]
        elif filter_model["type"] == "notEndsWith":
            dff = dff.loc[~dff[col].astype(str).str.lower().str.endswith(str(crit1).lower(), na=False)]
        elif filter_model["type"] == "equals" and (filter_model.get("filterType") == "text" or isinstance(crit1, str) or dff[col].dtype == "object"):
            dff = dff.loc[dff[col].astype(str).str.lower() == str(crit1).lower()]
        elif filter_model["type"] == "notEqual" and (filter_model.get("filterType") == "text" or isinstance(crit1, str) or dff[col].dtype == "object"):
            dff = dff.loc[dff[col].astype(str).str.lower() != str(crit1).lower()]
        elif filter_model["type"] == "inRange":
            if filter_model["filterType"] == "date":
                dff = dff.loc[  dff[col].astype("datetime64[ns]").between_time(crit1, crit2) ]
            else:
                dff = dff.loc[dff[col].between(crit1, crit2)]
        elif filter_model["type"] == "blank":
            dff = dff.loc[dff[col].isnull()]
        elif filter_model["type"] == "notBlank":
            dff = dff.loc[~dff[col].isnull()]
        else:
            dff = dff.loc[getattr(dff[col], operators[filter_model["type"]])(crit1)]
    elif filter_model["filterType"] == "set":
        values_lower = [str(v).lower() for v in filter_model["values"]]
        dff = dff.loc[dff[col].astype(str).str.lower().isin(values_lower)]
    return dff