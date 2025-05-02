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

    if(props.value == null){
        return null;
    }
    else{
        const cweNumber = props.value.replace("CWE-", "");
        return React.createElement(
            'a',
            {
                href: `https://cwe.mitre.org/data/definitions/${cweNumber}.html`,
                target: '_blank',
                rel: 'noopener noreferrer'
            },
            props.value
        );
       }
    };

dagcomponentfuncs.IPLink = function (props) {

    if (!props || !props.data) {
        return React.createElement('a', {}, '#');
    }

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

// 1. Votos em cache e flag de carregamento
let userVotesCache = null;
let isFetchingVotes = false;
let votesListeners = [];

// 2. Função para buscar votos apenas uma vez e notificar listeners
async function fetchUserVotesOnce() {
    if (userVotesCache !== null || isFetchingVotes) return;

    isFetchingVotes = true;

    try {
        const response = await fetch('/api/user_votes');
        if (response.ok) {
            const result = await response.json();
            userVotesCache = result;
            // Notificar todos os listeners aguardando os votos
            votesListeners.forEach(callback => callback());
            votesListeners = [];  // Limpar lista após uso
        } else {
            console.error('Failed to fetch user votes:', response.statusText);
        }
    } catch (error) {
        console.error('There was a problem with the fetch operation:', error);
    } finally {
        isFetchingVotes = false;
    }
}

dagcomponentfuncs.launchBtn = function (props) {
    if (!props || !props.data) {
        return React.createElement('div', {}, 'Loading...');
    }

    const { meta_id } = props.data;
    const [vote, setVote] = React.useState(userVotesCache?.[meta_id] ?? 'skip');

    // 3. Buscar votos uma vez e atualizar o estado depois
    React.useEffect(() => {
        if (userVotesCache !== null) {
            setVote(userVotesCache[meta_id] ?? 'skip');
        } else {
            // Adiciona este componente como "listener" para ser notificado quando o cache estiver pronto
            votesListeners.push(() => {
                setVote(userVotesCache?.[meta_id] ?? 'skip');
            });

            // Inicia a busca se ainda não estiver em andamento
            fetchUserVotesOnce();
        }
    }, [meta_id]);

    async function saveVote(voteValue) {
        try {
            const response = await fetch('/save_vote', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ meta_id: meta_id, vote: voteValue })
            });

            if (!response.ok) throw new Error('Network response was not ok');

            const result = await response.json();
            if (result.status === 'success') {
                setVote(voteValue);
                if (userVotesCache) {
                    userVotesCache[meta_id] = voteValue;
                }
            }
        } catch (error) {
            console.error('Error saving vote:', error);
        }
    }

    async function removeVote() {
        try {
            const response = await fetch('/remove_vote', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ meta_id: meta_id })
            });

            if (!response.ok) throw new Error('Network response was not ok');

            const result = await response.json();
            if (result.status === 'success') {
                setVote('skip');
                if (userVotesCache) {
                    delete userVotesCache[meta_id];
                }
            }
        } catch (error) {
            console.error('Error removing vote:', error);
        }
    }

    function handleDropdownChange(event) {
        const voteValue = event.target.value;
        if (voteValue === 'skip') {
            removeVote(); // Call remove if skip
        } else {
            saveVote(parseInt(voteValue, 10));
        }
    }

    const options = [
        React.createElement('option', { key: 'skip', value: 'skip' }, 'Skip'),
        ...Array.from({ length: 11 }, (_, i) =>
            React.createElement('option', { key: i, value: i }, i)
        )
    ];

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