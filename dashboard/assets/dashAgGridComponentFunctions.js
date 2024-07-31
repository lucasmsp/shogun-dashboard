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

    // Click handler
    function handleVoteClick(voteValue) {
        if (vote === voteValue) {
            // Remove vote if already selected
            saveVote(null);
        } else {
            saveVote(voteValue);
        }
    }

    // CSS
    function getButtonClass(voteValue) {
        return `btn ${vote === voteValue ? 'btn-primary' : 'btn-success'}`;
    }

    const button1 = React.createElement("button", { className: getButtonClass(1), onClick: () => handleVoteClick(1) }, "⬆");
    const button2 = React.createElement("button", { className: getButtonClass(0), onClick: () => handleVoteClick(0) }, "✓");
    const button3 = React.createElement("button", { className: getButtonClass(-1), onClick: () => handleVoteClick(-1) }, "⬇");

    const div = React.createElement(
        'div',
        { className: 'btn-group' },
        [button1, button2, button3]
      );

    return div
};