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
    if not isinstance(filter_modal, dict):
        return df

    if "operator" in filter_modal:
        # is a filter with multiple conditions
        conditions = filter_modal.get("conditions", [])
        if not conditions:
            c1 = filter_modal.get("condition1")
            c2 = filter_modal.get("condition2")
            if c1: conditions.append(c1)
            if c2: conditions.append(c2)

        if filter_modal['operator'] == "AND":
            for cond in conditions:
                df = filter_generic(cond, df, col)
        elif filter_modal['operator'] == "OR":
            df_list = [filter_generic(cond, df, col) for cond in conditions]
            if df_list:
                df = pd.concat(df_list).drop_duplicates()
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
        return filter_by_model(opt, df, col)
    return df


operators = {
        "greaterThanOrEqual": "ge",
        "lessThanOrEqual": "le",
        "lessThan": "lt",
        "greaterThan": "gt",
        "notEqual": "ne",
        "equals": "eq",
    }

def normalize_epss_crit(crit, series):
    if not isinstance(crit, (int, float)) or series.empty:
        return crit
    try:
        s_valid = pd.to_numeric(series, errors='coerce').dropna()
        if s_valid.empty:
            return crit
        max_val = float(s_valid.max())
        if max_val <= 1.0 and crit > 1.0:
            return float(crit) / 100.0
        elif max_val > 1.0 and 0 < crit <= 1.0:
            return float(crit) * 100.0
    except Exception:
        pass
    return crit


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
        if filter_model.get("filterType") == "date":
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
                if "epss" in col.lower() and col in dff.columns:
                    crit1 = normalize_epss_crit(crit1, dff[col])

            if "filterTo" in filter_model:
                crit2 = filter_model["filterTo"]
                if filter_model.get("filterType") != "text":
                    try:
                        crit2 = pd.Series(crit2).astype(dff[col].dtype)[0]
                    except Exception:
                        pass
                    if "epss" in col.lower() and col in dff.columns:
                        crit2 = normalize_epss_crit(crit2, dff[col])
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
            if dff[col].apply(lambda x: isinstance(x, (list, tuple, set))).any():
                crit1_str = str(crit1).lower()
                dff = dff.loc[dff[col].apply(lambda lst: any(crit1_str == str(item).lower() for item in lst) if isinstance(lst, (list, tuple, set)) else str(lst).lower() == crit1_str)]
            else:
                dff = dff.loc[dff[col].astype(str).str.lower() == str(crit1).lower()]
        elif filter_model["type"] == "notEqual" and (filter_model.get("filterType") == "text" or isinstance(crit1, str) or dff[col].dtype == "object"):
            if dff[col].apply(lambda x: isinstance(x, (list, tuple, set))).any():
                crit1_str = str(crit1).lower()
                dff = dff.loc[~dff[col].apply(lambda lst: any(crit1_str == str(item).lower() for item in lst) if isinstance(lst, (list, tuple, set)) else str(lst).lower() == crit1_str)]
            else:
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