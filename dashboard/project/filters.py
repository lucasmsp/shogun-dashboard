



def filter_text(filter_modal, df, col):

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