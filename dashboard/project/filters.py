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
    org_query = filter_modal.get(col, None)
    if org_query:

        type_ = org_query.get("type", 'contains')
        value = org_query.get("filter", '')
        if type_ == "contains":
            df = df[df[col].str.contains(value, case=False)]
        elif type_ == "equals":
            df = df[df[col] == value]
        elif type_ == "notEqual":
            df = df[df[col] != value]

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
            crit1 = pd.Series(crit1).astype(dff[col].dtype)[0]
            if "filterTo" in filter_model:
                crit2 = filter_model["filterTo"]
                crit2 = pd.Series(crit2).astype(dff[col].dtype)[0]
    if "type" in filter_model:
        if filter_model["type"] == "contains":
            dff = dff.loc[dff[col].str.contains(crit1)]
        elif filter_model["type"] == "notContains":
            dff = dff.loc[~dff[col].str.contains(crit1)]
        elif filter_model["type"] == "startsWith":
            dff = dff.loc[dff[col].str.startswith(crit1)]
        elif filter_model["type"] == "notStartsWith":
            dff = dff.loc[~dff[col].str.startswith(crit1)]
        elif filter_model["type"] == "endsWith":
            dff = dff.loc[dff[col].str.endswith(crit1)]
        elif filter_model["type"] == "notEndsWith":
            dff = dff.loc[~dff[col].str.endswith(crit1)]
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
        dff = dff.loc[dff[col].astype("string").isin(filter_model["values"])]
    return dff