$(document).ready(function() {
    $('#vulnerabilitiesTable').DataTable();
});
document.addEventListener('DOMContentLoaded', async (event) => {
    const meta_id = "{{ meta_id }}";
    let jsonData;

    var mymap = L.map('mapid', {
            center: [51.505, -0.09],
            zoom: 10,
            dragging: false,
            touchZoom: false,
            scrollWheelZoom: false,
            doubleClickZoom: false,
            boxZoom: false,
            keyboard: false,
            zoomControl: false,
        });

          L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
              attribution: '© OpenStreetMap contributors'
          }).addTo(mymap);

    // Retrieve data
    try {
        const response = await fetch(`/api/details/${meta_id}`);
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        jsonData = await response.json();
    } catch (error) {
        console.error('There was a problem with the fetch operation:', error);
    }

    function getEntries(data) {
        const table = document.getElementById('dataTable');
        const thead = table.querySelector('thead tr');
        const tbody = table.querySelector('tbody');
        thead.innerHTML = '';  // Clear existing headers
        tbody.innerHTML = '';  // Clear existing rows

        for (const key in data) {
            if (data.hasOwnProperty(key) && key !== 'vulns') {
                const th = document.createElement('th');
                th.textContent = capitalizeFirstLetter(key);
                thead.appendChild(th);
            }
        }

const rowCount = Math.max(...Object.values(data).map(array => Array.isArray(array) ? array.length : 0));
let latitude = null;
let longitude = null;
for (let i = 0; i < rowCount; i++) {
const tr = document.createElement('tr');
for (const key in data) {
  if (key == 'ip') {
    document.getElementById("ip").textContent = data[key];
  }
  if (key == 'data') {
    document.getElementById("data").textContent = data[key];
  }
  if (key == 'timestamp') {
    document.getElementById("timestamp").textContent = data[key];
  }
  if (key == 'latitude') {
    latitude = data[key];
    }
    if (key == 'longitude') {
        longitude = data[key];
    }
if (Array.isArray(latitude)) {
    latitude = latitude[0];
    }
    if (Array.isArray(longitude)) {
    longitude = longitude[0];
    }

  if (latitude !== null && longitude !== null) {
    console.log(latitude, longitude);
    const marker = L.marker([latitude, longitude]).addTo(mymap);
    mymap.setView([latitude, longitude], 8);
  }


  if (data.hasOwnProperty(key) && key !== 'vulns') {
    const td = document.createElement('td');
    const array = data[key];
    if (Array.isArray(array) && i < array.length) {
      if (typeof array[i] === 'object') {
        td.innerHTML = `<pre>${JSON.stringify(array[i], null, 2)}</pre>`;
      } else {
        td.textContent = array[i];
      }
    } else {
      td.textContent = 'N/A';
    }
    tr.appendChild(td);
  }
}
tbody.appendChild(tr);
}

document.querySelector('.info-content .label-organization').textContent = data.org_clean || 'N/A';
document.querySelector('.info-content .label-operating-system').textContent = data.operating_system || 'N/A';
document.querySelector('.info-content .label-hostnames').textContent = data.hostnames ? data.hostnames.join(', ') : 'N/A';
document.querySelector('.info-content .label-domains').textContent = data.domains ? data.domains.join(', ') : 'N/A';
}

    function capitalizeFirstLetter(string) {
        return string.charAt(0).toUpperCase() + string.slice(1);
    }

    function processJsonData(data) {
        const vulnerabilitiesTable = $('#vulnerabilitiesTable').DataTable();
        let vulnerabilities = [];
        console.log(data);
        const vulnsArray = data.vulns;
        const vulns = vulnsArray[0];
        vulns.forEach(vuln => {
            vulnerabilities.push({
                cve_id: vuln.cve_id,
                description: vuln.description,
                cvss_score: vuln.cvss_score,
                epss: vuln.epss
            });
        });

        vulnerabilitiesTable.clear();

        vulnerabilities.forEach(vuln => {
            const cveLink = `<a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=${vuln.cve_id}" target="_blank">${vuln.cve_id}</a>`;
            vulnerabilitiesTable.row.add([
                cveLink,
                vuln.description,
                vuln.cvss_score,
                vuln.epss
            ]);
        });

        vulnerabilities.sort((a, b) => b.cvss_score - a.cvss_score);
        createCVSSChart(vulnerabilities);

        vulnerabilities.sort((a, b) => b.epss - a.epss);
        createEPSSChart(vulnerabilities);
        vulnerabilitiesTable.draw();

        vulnerabilities.sort((a, b) => b.cvss_score - a.cvss_score);

        // Add CVE tags to the info container
        const cveTagsContainer = document.getElementById('cve-tags-container');
        cveTagsContainer.innerHTML = '';

        const showMoreBtn = document.getElementById('show-more-btn');
        let isExpanded = false;

        const initialVisibleCount = 18;
        let visibleCount = initialVisibleCount;

        function updateCveTags() {
            cveTagsContainer.innerHTML = '';
            vulnerabilities.slice(0, visibleCount).forEach(vuln => {
                const cveTag = document.createElement('a');
                cveTag.href = `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${vuln.cve_id}`;
                cveTag.target = '_blank';
                cveTag.className = 'cve-tag';

                if (vuln.cvss_score < 4.0) {
                    cveTag.classList.add('low-score');
                } else if (vuln.cvss_score < 7.0) {
                    cveTag.classList.add('medium-score');
                } else if (vuln.cvss_score < 9.0) {
                    cveTag.classList.add('high-score');
                } else {
                    cveTag.classList.add('critical-score');
                }

                cveTag.textContent = vuln.cve_id;
                cveTagsContainer.appendChild(cveTag);
            });

            if (visibleCount >= vulnerabilities.length) {
                showMoreBtn.style.display = 'none';
            } else {
                showMoreBtn.style.display = 'block';
                showMoreBtn.textContent = `Show ${vulnerabilities.length - visibleCount} More`;
            }
        }

        showMoreBtn.addEventListener('click', () => {
            visibleCount = vulnerabilities.length;
            isExpanded = true;
            updateCveTags();
        });

        updateCveTags();
    }

    const buttons = document.querySelectorAll('.checkmark-btn');
    const voteMessage = document.getElementById('vote-message');
    const voteContainer = document.querySelector('.vote-container');

    buttons.forEach(button => {
        button.addEventListener('click', () => {
            if (button.classList.contains('active')) {
                button.classList.remove('active');
                voteMessage.textContent = 'Vote removed';
                return;
            }
            buttons.forEach(btn => btn.classList.remove('active'));
            
            button.classList.add('active');

            let voteText = '';
            if (button.id === 'up-btn') {
                voteText = 'Voted as higher';
            } else if (button.id === 'checkmark-btn') {
                voteText = 'Voted as ok';
            } else if (button.id === 'down-btn') {
                voteText = 'Voted as lower';
            }

            voteMessage.textContent = voteText;
        });
    });

    function createCVSSChart(vulnerabilities) {
        const ctx1 = document.getElementById('barCVSS').getContext('2d');
        const barCVSS = new Chart(ctx1, {
            type: 'bar',
            data: {
                labels: vulnerabilities.map(item => item.cve_id),
                datasets: [{
                    label: 'CVSS Score',
                    data: vulnerabilities.map(item => item.cvss_score),
                    backgroundColor: 'rgba(75, 192, 192, 0.2)',
                    borderColor: 'rgba(75, 192, 192, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                plugins: {
                    title: {
                        display: true,
                        text: 'CVSS Scores of Vulnerabilities',
                        font: {
                            size: 18
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true
                    }
                },
                onClick: (event, elements) => {
                    if (elements.length > 0) {
                        const elementIndex = elements[0].index;
                        const vulnerability = vulnerabilities[elementIndex];
                        displayCVEInfo(vulnerability.cve_id, vulnerability.description);
                    }
                }
            }
        });
    }

    function displayCVEInfo(cveId, description) {
        const infoContainer = document.getElementById('infoContainer');
        infoContainer.innerHTML = `<h3>${cveId}</h3><p>${description}</p>`;
    }

    function createEPSSChart(vulnerabilities) {
        const ctx2 = document.getElementById('barEPSS').getContext('2d');
        const barEPSS = new Chart(ctx2, {
            type: 'bar',
            data: {
                labels: vulnerabilities.map(item => item.cve_id),
                datasets: [{
                    label: 'EPSS Score',
                    data: vulnerabilities.map(item => item.epss),
                    backgroundColor: 'rgba(153, 102, 255, 0.2)',
                    borderColor: 'rgba(153, 102, 255, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                plugins: {
                    title: {
                        display: true,
                        text: 'EPSS Scores of Vulnerabilities',
                        font: {
                            size: 18
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true
                    }
                },
                onClick: (event, elements) => {
                    if (elements.length > 0) {
                        const elementIndex = elements[0].index;
                        const vulnerability = vulnerabilities[elementIndex];
                        displayEPSSInfo(vulnerability.cve_id, vulnerability.description);
                    }
                }
            }
        });
    }

    function displayEPSSInfo(cveId, description) {
        const infoContainer = document.getElementById('infoContainer2');
        infoContainer.innerHTML = `<h3>${cveId}</h3><p>${description}</p>`;
    }

    processJsonData(jsonData);
    getEntries(jsonData);
});
document.getElementById('prev-graph-btn').addEventListener('click', function() {
switchGraph('prev');
});

document.getElementById('next-graph-btn').addEventListener('click', function() {
switchGraph('next');
});

function switchGraph(direction) {
var cvssGraphWrapper = document.getElementById('cvss-graph-wrapper');
var epssGraphWrapper = document.getElementById('epss-graph-wrapper');

if (cvssGraphWrapper.classList.contains('active')) {
cvssGraphWrapper.classList.remove('active');
epssGraphWrapper.classList.add('active');
} else {
epssGraphWrapper.classList.remove('active');
cvssGraphWrapper.classList.add('active');
}
}

document.getElementById('cvss-graph-wrapper').classList.add('active');