var dagcomponentfuncs = (window.dashAgGridComponentFunctions = window.dashAgGridComponentFunctions || {});

dagcomponentfuncs.StockLink = function (props) {
    return React.createElement(
        'a',
        {href: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name='+props.value, target: '_blank', rel: 'noopener noreferrer'},
        props.value
    );
};