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