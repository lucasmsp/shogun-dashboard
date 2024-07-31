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


// async function saveVote(meta_id, voteValue) {
//     try {
//         const response = await fetch('/save_vote', {
//             method: 'POST',
//             headers: {
//                 'Content-Type': 'application/json'
//             },
//             body: JSON.stringify({
//                 meta_id: meta_id,
//                 vote: voteValue
//             })
//         });

//         if (!response.ok) {
//             throw new Error('Network response was not ok');
//         }

//         const result = await response.json();
//         if (result.status === 'success') {
//             console.log('Vote saved successfully');
//             if (voteValue === null) {
//                 delete userVotes[meta_id];
//             } else {
//                 userVotes[meta_id] = voteValue;
//             }
//         } else {
//             console.error('Failed to save vote:', result.message);
//         }
//     } catch (error) {
//         console.error('There was a problem with the fetch operation:', error);
//     }
// }

dagcomponentfuncs.launchBtn = function (props) {
    console.log('launchBtn', props)
    var meta_id = props.data['meta_id']

    function onClickUp() {
        setData();
    }

    function onClickBase() {
        setData();
    }

    function onClickDown() {
        setData();
    }

    
      const button1 = React.createElement("button", { className: 'btn btn-success', onClick: onClickUp }, "⬆");
      const button2 = React.createElement("button", { className: 'btn btn-success', onClick: onClickBase }, "✓");
      const button3 = React.createElement("button", { className: 'btn btn-success', onClick: onClickDown }, "⬇");

      const div = React.createElement(
        'div',
        { className: 'btn-group' },
        [button1, button2, button3]
      );

    return div
}

    // [button1, button2, button3].forEach(button => {
    //     button.addEventListener('click', async () => {
    //         if (button.classList.contains('selected')) {

    //             voteTd.querySelectorAll('.vote-button').forEach(btn => {
    //                 btn.classList.remove('selected');
    //             });
    //             await saveVote(meta_id, null);
    //         } else {

    //             voteTd.querySelectorAll('.vote-button').forEach(btn => {
    //                 btn.classList.remove('selected');
    //             });
    
    //             button.classList.add('selected');
    
    //             let voteValue = '';
    //             if (button === button1) {
    //                 voteValue = 1;
    //             } else if (button === button2) {
    //                 voteValue = 0;
    //             } else if (button === button3) {
    //                 voteValue = -1;
    //             }
    
    //             await saveVote(meta_id, voteValue);
    //         }
    //     });
    // });

    // if (meta_id in userVotes) {
    //     if (userVotes[row.meta_id] === 1) {
    //         button1.classList.add('selected');
    //     } else if (userVotes[meta_id] === 0) {
    //         button2.classList.add('selected');
    //     } else if (userVotes[meta_id] === -1) {
    //         button3.classList.add('selected');
    //     }
    // }
