var dagcomponentfuncs = (window.dashAgGridComponentFunctions = window.dashAgGridComponentFunctions || {});

dagcomponentfuncs.GoToMitre = function (props) {
    return React.createElement(
        'a',
        {
            href: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name='+props.value,
            target: '_blank', 
            rel: 'noopener noreferrer'},
        props.value
    );
};


dagcomponentfuncs.IPLink = function (props) {

    // console.log('launchBtn', props.data)
    return React.createElement(
        'a',
        {
            target: "_self",
            href: '/details/' + props.data['meta_id']
        },
            props.value
    );
};

dagcomponentfuncs.Button = function (props) {
    const {setData, data} = props;

    function onClick() {
        setData();
    }
    return React.createElement(
        'button',
        {
            onClick: onClick,
            className: props.className,
        },
        props.value
    );
};

dagcomponentfuncs.launchBtn = function (props) {
    const { meta_id } = props.data;

    // Hold vote stuff
    const [vote, setVote] = React.useState(null);

    // Fetch vote dict flask_routes.py
    React.useEffect(() => {
        async function fetchUserVotes() {
            try {
                const response = await fetch('/api/user_votes');
                if (response.ok) {
                    const result = await response.json();
                    if (meta_id in result) {
                        setVote(result[meta_id]);
                    }
                } else {
                    console.error('Failed to fetch user votes:', response.statusText);
                }
            } catch (error) {
                console.error('There was a problem with the fetch operation:', error);
            }
        }

        fetchUserVotes();
    }, [meta_id]);

    // Save vote to db flask_routes.py/models.py
    async function saveVote(voteValue) {
        try {
            const response = await fetch('/save_vote', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    meta_id: meta_id,
                    vote: voteValue
                })
            });

            if (!response.ok) {
                throw new Error('Network response was not ok');
            }

            const result = await response.json();
            if (result.status === 'success') {
                console.log('Vote saved successfully');

                // Update
                setVote(voteValue);
            } else {
                console.error('Failed to save vote:', result.message);
            }
        } catch (error) {
            console.error('There was a problem with the fetch operation:', error);
        }
    }

    // Handle dropdown change
    function handleDropdownChange(event) {
        const voteValue = parseInt(event.target.value, 10);
        saveVote(voteValue);
    }

    // Dropdown options
    const options = [];
    for (let i = 0; i <= 10; i++) {
        options.push(
            React.createElement(
                'option',
                { key: i, value: i },
                i
            )
        );
    }

    return React.createElement(
        'select',
        {
            value: vote !== null ? vote : '',  // Set the current vote or default to empty
            className: 'form-select',
            onChange: handleDropdownChange,
        },
        options
    );
};


dagcomponentfuncs.CustomTooltipCvssV6 = function (props) {
    return React.createElement(
        'div',
        {
            style: {
                border: '5px double',
                backgroundColor: props.color || '#f0e5c7',
                padding: 10,
            },
        },
        [
            React.createElement('b', {}, 'Min:'),
            React.createElement('div', {}, props.data.min_cvss),
            React.createElement('b', {}, 'Max:'),
            React.createElement('div', {}, props.data.max_cvss),
        ]
    );
};

dagcomponentfuncs.CustomTooltipEpssV6 = function (props) {
    return React.createElement(
        'div',
        {
            style: {
                border: '5px double',
                backgroundColor: props.color || '#f0e5c7',
                padding: 10,
            },
        },
        [
            React.createElement('b', {}, 'Min:'),
            React.createElement('div', {}, props.data.min_epss),
            React.createElement('b', {}, 'Max:'),
            React.createElement('div', {}, props.data.max_epss),
        ]
    );
};

dagcomponentfuncs.CustomTooltipAsnV6 = function (props) {
    return React.createElement(
        'div',
        {
            style: {
                border: '5px double',
                backgroundColor: props.color || '#f0e5c7',
                padding: 10,
            },
        },
        [
            React.createElement('b', {}, 'AS Name:'),
            React.createElement('div', {}, props.data.as_name),
            React.createElement('b', {}, 'AS Rank'),
            React.createElement('div', {}, props.data.as_rank),
        ]
    );
};

dagcomponentfuncs.CustomTooltipOrgNameV6 = function (props) {
    return React.createElement(
        'div',
        {
            style: {
                border: '5px double',
                backgroundColor: props.color || '#f0e5c7',
                padding: 10,
            },
        },
        [
            React.createElement('b', {}, '# Orgs:'),
            React.createElement('div', {}, props.data.n_orgs),
        ]
    );
};

dagcomponentfuncs.CustomTooltipCountryNameV6 = function (props) {
    return React.createElement(
        'div',
        {
            style: {
                border: '5px double',
                backgroundColor: props.color || '#f0e5c7',
                padding: 10,
            },
        },
        [
            React.createElement('b', {}, 'Org Country Name:'),
            React.createElement('div', {}, props.data.as_org_country_name),
        ]
    );
};


dagcomponentfuncs.CustomTooltipPrefixesV6 = function (props) {
    return React.createElement(
        'div',
        {
            style: {
                border: '5px double',
                backgroundColor: props.color || '#f0e5c7',
                padding: 10,
            },
        },
        [
            React.createElement('b', {}, '# Addresses: '),
            React.createElement('div', {}, props.data.as_announcing_addresses),
        ]
    );
};