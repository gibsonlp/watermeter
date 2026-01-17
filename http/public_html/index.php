<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Water Meter Forensic Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .chart-container { min-height: 500px; }
        .table-hover tbody tr:hover { background-color: rgba(255,255,255,0.1); cursor: pointer; }
    </style>
</head>
<body class="bg-body-tertiary">

<nav class="navbar navbar-expand-lg navbar-dark bg-primary mb-4">
    <div class="container">
        <a class="navbar-brand" href="#">💧 Water Monitor</a>
    </div>
</nav>

<div class="container">
    <div class="row mb-4">
        <div class="col-md-6">
            <div class="btn-group" role="group">
                <button type="button" class="btn btn-outline-info active" onclick="updateRange('24h', this)">24h</button>
                <button type="button" class="btn btn-outline-info" onclick="updateRange('7d', this)">7d</button>
                <button type="button" class="btn btn-outline-info" onclick="updateRange('30d', this)">30d</button>
                <button type="button" class="btn btn-outline-warning" onclick="updateRange('1y', this)">1 Year</button>
            </div>
        </div>
        <div class="col-md-6 text-end">
            <span class="text-light opacity-75" id="last-update">Updating...</span>
        </div>
    </div>

    <div class="card mb-4 bg-dark border-secondary">
        <div class="card-body">
            <div id="container" class="chart-container"></div>
            <div class="text-muted small text-center mt-2">
                Tip: Click and drag on the chart to Zoom. Hover over table rows below to highlight events.
            </div>
        </div>
    </div>

    <div class="card bg-dark text-light border-secondary">
        <div class="card-header border-secondary fw-bold">Anomaly & Irrigation Log</div>
        <div class="card-body p-0">
            <div class="table-responsive" style="max-height: 400px; overflow-y: auto;">
                <table class="table table-dark table-hover mb-0 align-middle">
                    <thead class="sticky-top bg-dark">
                        <tr class="text-muted small">
                            <th>Time</th>
                            <th>Line</th>
                            <th>Status</th>
                            <th>Vol (L)</th>
                            <th>Flow (LPM)</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody id="anomaly-table-body"></tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<script src="https://code.highcharts.com/highcharts.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>

<script>
let chart;
let currentRange = '24h';
const LINE_NAMES = { 0: "Front Garden", 1: "Rear Garden", 2: "Trees/Pots", "-1": "System/Meter" };

// COLORS: Pastel Blue (Flow) and Mint Green (Volume)
const C_FLOW = '#66b3ff';
const C_VOL  = '#4ade80';
const C_GRID = '#404040';

document.addEventListener('DOMContentLoaded', function () {
    initChart();
    fetchData();
    setInterval(fetchData, 60000); 
});

function initChart() {
    chart = Highcharts.chart('container', {
        chart: { 
            backgroundColor: 'transparent', 
            zoomType: 'x', 
            style: { fontFamily: 'Segoe UI, sans-serif' } 
        },
        title: { text: 'Water Usage Forensics', style: { color: '#fff' } },
	legend: {
            itemStyle: { color: '#e0e0e0', fontSize: '14px' }, // Bright Grey
            itemHoverStyle: { color: '#ffffff' } // Pure White on hover
        },

        xAxis: { 
            type: 'datetime', 
            lineColor: C_GRID, 
            gridLineColor: C_GRID,
	    labels: {
                style: { color: '#e0e0e0', fontSize: '12px' } // Bright Grey Text
            },
            plotBands: [] 
        },
        yAxis: [{
            title: { text: 'Flow (L/min)', style: { color: C_FLOW } },
            labels: { style: { color: C_FLOW } },
            gridLineColor: C_GRID
        }, {
            title: { text: 'Volume (m³)', style: { color: C_VOL } },
            labels: { style: { color: C_VOL } },
            opposite: true, gridLineWidth: 0
        }],
        tooltip: { shared: true, xDateFormat: '%Y-%m-%d %H:%M:%S', backgroundColor: 'rgba(0,0,0,0.85)', style: { color: '#fff' } },
        series: [
            { 
                name: 'Flow Rate', 
                type: 'column', // VERTICAL LINES
                borderWidth: 0, 
                pointPadding: 0, 
                groupPadding: 0,
                color: C_FLOW, 
                data: [] 
            },
            { 
                name: 'Volume', 
                type: 'line', 
                yAxis: 1, 
                color: C_VOL, 
                data: [] 
            },
            { 
                name: 'Critical Events', 
                type: 'scatter', 
                color: '#ff4d4d', 
                marker: { symbol: 'circle', radius: 6 },
                tooltip: { pointFormat: '<b>{point.title}</b><br>Flow: {point.y} LPM' },
                data: [] 
            }
        ]
    });
}

function updateRange(range, btn) {
    currentRange = range;
    document.querySelectorAll('.btn-group .btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    chart.zoomOut();
    fetchData();
}

function highlightGraph(bandId, isHovering) {
    if(!bandId) return;
    const axis = chart.xAxis[0];
    const bands = axis.plotLinesAndBands;
    const band = bands.find(b => b.id === bandId);
    if (!band) return;

    if (isHovering) {
        band.svgElem.attr({ 'stroke': '#ffffff', 'stroke-width': 2, 'opacity': 0.8 });
    } else {
        band.svgElem.attr({ 'stroke': 'none', 'opacity': band.options.originalOpacity || 1 });
    }
}

function fetchData() {
    const updateLabel = document.getElementById('last-update');
    updateLabel.innerText = 'Fetching...';
    
    Promise.all([
        fetch(`api.php?metric=flow&range=${currentRange}`).then(r => r.json()),
        fetch(`api.php?metric=volume&range=${currentRange}`).then(r => r.json()),
        fetch(`api.php?metric=anomalies&range=${currentRange}`).then(r => r.json())
    ]).then(([flowData, volData, anomalyData]) => {
        
        if (flowData.error) { console.error(flowData.error); return; }

        chart.series[0].setData(flowData);
        chart.series[1].setData(volData);
        chart.series[2].setData(anomalyData.points || []); 

        const bands = anomalyData.plotBands.map(b => ({ ...b, zIndex: 1, originalOpacity: 1 }));
        chart.xAxis[0].update({ plotBands: bands });

        let tableData = [...anomalyData.plotBands];
        if (anomalyData.points) {
            anomalyData.points.forEach(pt => {
                tableData.push({
                    from: pt.x,
                    id: null, 
                    details: { line: -1, status: 'CRITICAL', vol: 0, flow: pt.y, msg: pt.title }
                });
            });
        }
        renderTable(tableData);
        updateLabel.innerText = 'Last updated: ' + new Date().toLocaleTimeString();

    }).catch(err => console.error(err));
}

function renderTable(events) {
    const tbody = document.getElementById('anomaly-table-body');
    tbody.innerHTML = '';

    events.sort((a, b) => b.from - a.from).forEach(evt => {
        const d = evt.details;
        const dateStr = new Date(evt.from).toLocaleString();
        
        let badgeClass = 'bg-success';
        if (d.status === 'LEAK' || d.status === 'BURST') badgeClass = 'bg-warning text-dark';
        if (d.status === 'CRITICAL') badgeClass = 'bg-danger';
        if (d.status === 'CLOG') badgeClass = 'bg-secondary';

        const tr = document.createElement('tr');
        if(evt.id) {
            tr.onmouseenter = () => highlightGraph(evt.id, true);
            tr.onmouseleave = () => highlightGraph(evt.id, false);
        }
        
        tr.innerHTML = `
            <td>${dateStr}</td>
            <td>${LINE_NAMES[d.line] || 'Unknown'}</td>
            <td><span class="badge ${badgeClass} status-badge" style="width:80px">${d.status}</span></td>
            <td>${d.vol.toFixed(1)}</td>
            <td>${d.flow.toFixed(1)}</td>
            <td class="text-light opacity-75 small">${d.msg}</td>
        `;
        tbody.appendChild(tr);
    });
}
</script>

</body>
</html>
