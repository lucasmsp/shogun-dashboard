let currentPage = 1;
const rowsPerPage = 10;
let totalPages = 0;
let userVotes = {};
const activeSearches = new Set();
const searchFilters = {};

fetchTotalEntries();
fetchUserVotes();

async function fetchTotalEntries() {
    const response = await fetch('/api/data_count'); 
    const result = await response.json();
    const totalEntries = result.total_entries;
    totalPages = Math.ceil(totalEntries / rowsPerPage); 
}       

async function fetchUserVotes() {
    const response = await fetch('/api/user_votes');
    userVotes = await response.json();
}

async function fetchData(page) {
    const response = await fetch(`/api/data/${page}`);
    const result = await response.json();
    return result;
}

async function renderTable(data) {
    const tableBody = document.querySelector("#dataTable tbody");
    tableBody.innerHTML = "";

    data.forEach(row => {
        const tr = document.createElement("tr");

        Object.keys(row).forEach(key => {
            if (key === 'meta_id') return;

            const td = document.createElement("td");

            if (key === 'data') {
                const spaceIndex = row[key].indexOf(' ');
                const truncatedData = spaceIndex !== -1 ? row[key].slice(0, spaceIndex) : row[key];

                const boldText = document.createElement('span');
                boldText.textContent = truncatedData;
                boldText.style.fontWeight = 'bold';

                const serverMatch = row[key].match(/Server: [^\r\n]+/);
                const serverData = serverMatch ? serverMatch[0] : "N/A";

                const serverText = document.createElement('span');
                serverText.textContent = "\n" + serverData;

                td.appendChild(boldText);
                td.appendChild(document.createElement('br'));
                td.appendChild(serverText);

                const dateMatch = row[key].match(/Date: [^\r\n]+/);
                if (dateMatch) {
                    const dateData = dateMatch[0];

                    const dateText = document.createElement('span');
                    dateText.textContent = "\n" + dateData;

                    td.appendChild(document.createElement('br'));
                    td.appendChild(dateText);
                }
            } else if (key === 'port') {
                const portDiv = document.createElement("div");
                portDiv.classList.add("port-box");
                portDiv.textContent = row[key];

                td.appendChild(portDiv);
            } else if (key === 'ip_str') {
                const ipLink = document.createElement('a');
                ipLink.href = `/details/${row['meta_id']}`;
                ipLink.textContent = row[key];
                ipLink.style.color = '#007bff';

                td.appendChild(ipLink);
            } else {
                td.textContent = row[key];
            }

            tr.appendChild(td);
        });

        const voteTd = document.createElement("td");
        voteTd.classList.add("vote-buttons");

        const button1 = document.createElement("button");
        const button2 = document.createElement("button");
        const button3 = document.createElement("button");

        button1.textContent = "⬆";
        button2.textContent = "✓";
        button3.textContent = "⬇";

        button1.classList.add("vote-button");
        button2.classList.add("vote-button");
        button3.classList.add("vote-button");

        [button1, button2, button3].forEach(button => {
            button.addEventListener('click', async () => {
                if (button.classList.contains('selected')) {
                    // If the button is already selected, remove the vote
                    voteTd.querySelectorAll('.vote-button').forEach(btn => {
                        btn.classList.remove('selected');
                    });
                    await saveVote(row.meta_id, null);
                } else {
                    // If the button is not selected, add/update the vote
                    voteTd.querySelectorAll('.vote-button').forEach(btn => {
                        btn.classList.remove('selected');
                    });
        
                    button.classList.add('selected');
        
                    let voteValue = '';
                    if (button === button1) {
                        voteValue = 1;
                    } else if (button === button2) {
                        voteValue = 0;
                    } else if (button === button3) {
                        voteValue = -1;
                    }
        
                    await saveVote(row.meta_id, voteValue);
                }
            });
        });

        // Verificar e aplicar o voto do usuário
        if (row.meta_id in userVotes) {
            if (userVotes[row.meta_id] === 1) {
                button1.classList.add('selected');
            } else if (userVotes[row.meta_id] === 0) {
                button2.classList.add('selected');
            } else if (userVotes[row.meta_id] === -1) {
                button3.classList.add('selected');
            }
        }

        voteTd.appendChild(button1);
        voteTd.appendChild(button2);
        voteTd.appendChild(button3);

        tr.appendChild(voteTd);

        tableBody.appendChild(tr);
    });
}

async function saveVote(meta_id, voteValue) {
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
            if (voteValue === null) {
                delete userVotes[meta_id];
            } else {
                userVotes[meta_id] = voteValue;
            }
        } else {
            console.error('Failed to save vote:', result.message);
        }
    } catch (error) {
        console.error('There was a problem with the fetch operation:', error);
    }
}

function updatePagination() {
    const pageNumbers = document.getElementById('pageNumbers');
    pageNumbers.innerHTML = '';

    const maxPagesToShow = 5;
    let startPage = currentPage - Math.floor(maxPagesToShow / 2);
    let endPage = currentPage + Math.floor(maxPagesToShow / 2);

    if (startPage < 1) {
        startPage = 1;
        endPage = Math.min(totalPages, maxPagesToShow);
    }
    
    if (endPage > totalPages) {
        endPage = totalPages;
        startPage = Math.max(1, totalPages - maxPagesToShow + 1);
    }

    if (startPage > 1) {
        const firstPage = document.createElement('button');
        firstPage.textContent = '1';
        firstPage.classList.add('page-number');
        if (currentPage === 1) {
            firstPage.classList.add('active');
        }
        firstPage.addEventListener('click', () => {
            currentPage = 1;
            loadPage(currentPage);
        });
        pageNumbers.appendChild(firstPage);

        if (startPage > 2) {
            const dots = document.createElement('span');
            dots.textContent = '...';
            pageNumbers.appendChild(dots);
        }
    }

    for (let i = startPage; i <= endPage; i++) {
        const pageNumber = document.createElement('button');
        pageNumber.textContent = i;
        pageNumber.classList.add('page-number');
        if (i === currentPage) {
            pageNumber.classList.add('active');
        }
        pageNumber.addEventListener('click', () => {
            currentPage = i;
            loadPage(currentPage);
        });
        pageNumbers.appendChild(pageNumber);
    }

    if (endPage < totalPages) {
        if (endPage < totalPages - 1) {
            const dots = document.createElement('span');
            dots.textContent = '...';
            pageNumbers.appendChild(dots);
        }

        const lastPage = document.createElement('button');
        lastPage.textContent = totalPages;
        lastPage.classList.add('page-number');
        if (currentPage === totalPages) {
            lastPage.classList.add('active');
        }
        lastPage.addEventListener('click', () => {
            currentPage = totalPages;
            loadPage(currentPage);
        });
        pageNumbers.appendChild(lastPage);
    }
}

async function loadPage(page) {
    const data = await fetchData(page);
    renderTable(data);
    updatePagination();
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('prevPage').addEventListener('click', () => {
        if (currentPage > 1) {
            currentPage--;
            loadPage(currentPage);
        }
    });

    document.getElementById('nextPage').addEventListener('click', () => {
        if (currentPage < totalPages) {
            currentPage++;
            loadPage(currentPage);
        }
    });

    setupSearchHandlers();
    loadPage(currentPage);
});

function setupSearchHandlers() {
    document.querySelectorAll('.search-input').forEach(input => {
        input.addEventListener('input', (e) => {
            const column = e.target.id.replace('Search', '');
            searchFilters[column] = e.target.value;
            currentPage = 1;
            loadPage(currentPage);
        });
    });
}
