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

dagcomponentfuncs.GoToCWE = function (props) {
    const cweNumber = props.value.replace('CWE-', '');
    return React.createElement(
        'a',
        {
            href: `https://cwe.mitre.org/data/definitions/${cweNumber}.html`,
            target: '_blank',
            rel: 'noopener noreferrer'
        },
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

    // Hold vote state
    const [vote, setVote] = React.useState(null);

    // Fetch user votes from Flask API
    React.useEffect(() => {
        async function fetchUserVotes() {
            try {
                const response = await fetch('/api/user_votes');
                if (response.ok) {
                    const result = await response.json();
                    if (meta_id in result) {
                        setVote(result[meta_id]);
                    } else {
                        setVote('skip');  // Default to "Skip" if no vote
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

    // Save vote to the database
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
                setVote(voteValue);
            } else {
                console.error('Failed to save vote:', result.message);
            }
        } catch (error) {
            console.error('There was a problem with the fetch operation:', error);
        }
    }

    async function removeVote() {
        try {
            const response = await fetch('/remove_vote', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    meta_id: meta_id
                })
            });

            if (!response.ok) {
                throw new Error('Network response was not ok');
            }

            const result = await response.json();
            if (result.status === 'success') {
                setVote('skip');
            } else {
                console.error('Failed to remove vote:', result.message);
            }
        } catch (error) {
            console.error('There was a problem with the fetch operation:', error);
        }
    }

    function handleDropdownChange(event) {
        const voteValue = event.target.value;
        if (voteValue === 'skip') {
            removeVote();  // Call remove if skip
        } else {
            saveVote(parseInt(voteValue, 10));
        }
    }

    const options = [
        React.createElement('option', { key: 'skip', value: 'skip' }, 'Skip'),  // Skip option
    ];

    for (let i = 0; i <= 10; i++) {
        options.push(
            React.createElement('option', { key: i, value: i }, i)
        );
    }

    return React.createElement(
        'select',
        {
            value: vote !== null ? vote : 'skip',  // Default to "Skip" if no vote is present
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
            React.createElement('b', {}, 'Number of Cities:'),
            React.createElement('div', {}, props.data.n_cities),
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