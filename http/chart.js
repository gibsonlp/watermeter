Highcharts.chart('container', {
    chart: {
        zoomType: 'x'
    },
    title: {
        text: 'Water volume and momentary flow'
    },
    subtitle: {
        text: 'Source: My water meter'
    },
    xAxis: [{
        type: 'datetime',
        crosshair: true
    }],
    yAxis: [{ // Primary yAxis
        labels: {
            format: '{value} cbm',
            style: {
                color: Highcharts.getOptions().colors[1]
            }
        },
        title: {
            text: 'Volume',
            style: {
                color: Highcharts.getOptions().colors[1]
            }
        }
    }, { // Secondary yAxis
        title: {
            text: 'l/min',
            style: {
                color: Highcharts.getOptions().colors[0]
            }
        },
        labels: {
            format: '{value} l/min',
            style: {
                color: Highcharts.getOptions().colors[0]
            }
        },
        opposite: true
    }],
    tooltip: {
        shared: true
    },
    legend: {
        layout: 'vertical',
        align: 'left',
        x: 120,
        verticalAlign: 'top',
        y: 100,
        floating: true
    },
    series: [{
        name: 'Flow',
        type: 'column',
        yAxis: 1,
        data: lpm,
        tooltip: {
            valueSuffix: ' l/min'
        }

    }, {
        name: 'Volume',
        type: 'spline',
        data: cbm,
        tooltip: {
            valueSuffix: ' cbm'
        }
    }]
});

Highcharts.setOptions({
    global: {
        /**
        * Use moment-timezone.js to return the timezone offset for individual
        * timestamps, used in the X axis labels and the tooltip header.
        */
        getTimezoneOffset: function (timestamp) {
            d = new Date();
            timezoneOffset =  d.getTimezoneOffset()
            return timezoneOffset;
        }
    }
});
