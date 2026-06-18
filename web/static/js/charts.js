/**
 * NetScope v2 — Chart.js chart builders and updaters.
 *
 * Uses the module pattern to encapsulate all chart instances.
 * Exposes init() and update*() methods consumed by app.js.
 */
const Charts = (() => {
  let rttLine, protoPie, talkerBar, bandwidth, rttHist;

  function init() {
    // Common dark-theme defaults
    Chart.defaults.color = '#8b949e';
    Chart.defaults.borderColor = '#21262d';

    // RTT Line Chart
    rttLine = new Chart(document.getElementById('chart-rtt-line'), {
      type: 'line',
      data: {
        labels: [],
        datasets: [{
          label: 'RTT (ms)',
          data: [],
          borderColor: '#58a6ff',
          backgroundColor: 'rgba(88, 166, 255, 0.08)',
          fill: true,
          tension: 0.3,
          pointRadius: 0,
          pointHoverRadius: 4,
          pointHoverBackgroundColor: '#58a6ff',
          borderWidth: 2,
        }]
      },
      options: {
        animation: false,
        responsive: true,
        maintainAspectRatio: false,
        interaction: {
          mode: 'index',
          intersect: false,
        },
        scales: {
          x: { display: false },
          y: {
            min: 0,
            ticks: { color: '#8b949e', font: { size: 11 } },
            grid: { color: 'rgba(33, 38, 45, 0.8)' },
          }
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#161b22',
            borderColor: '#30363d',
            borderWidth: 1,
            titleColor: '#e6edf3',
            bodyColor: '#8b949e',
            displayColors: false,
            padding: 10,
            callbacks: {
              label: function(ctx) {
                return `RTT: ${ctx.parsed.y.toFixed(1)} ms`;
              }
            }
          },
        }
      }
    });

    // Protocol Doughnut Chart
    protoPie = new Chart(document.getElementById('chart-proto-pie'), {
      type: 'doughnut',
      data: {
        labels: ['TCP', 'UDP', 'ICMP', 'DNS', 'ARP', 'Other'],
        datasets: [{
          data: [0, 0, 0, 0, 0, 0],
          backgroundColor: [
            '#58a6ff', '#3fb950', '#d29922',
            '#f0883e', '#bc8cff', '#8b949e',
          ],
          borderColor: '#161b22',
          borderWidth: 2,
          hoverOffset: 6,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '60%',
        plugins: {
          legend: {
            position: 'right',
            labels: {
              color: '#8b949e',
              padding: 12,
              usePointStyle: true,
              pointStyleWidth: 10,
              font: { size: 12 },
            }
          },
          tooltip: {
            backgroundColor: '#161b22',
            borderColor: '#30363d',
            borderWidth: 1,
            titleColor: '#e6edf3',
            bodyColor: '#8b949e',
          }
        }
      }
    });

    // Top Talkers Horizontal Bar
    talkerBar = new Chart(document.getElementById('chart-talkers-bar'), {
      type: 'bar',
      data: {
        labels: [],
        datasets: [
          {
            label: 'bytes in',
            data: [],
            backgroundColor: 'rgba(63, 185, 80, 0.6)',
            borderColor: '#3fb950',
            borderWidth: 1,
            borderRadius: 3,
          },
          {
            label: 'bytes out',
            data: [],
            backgroundColor: 'rgba(88, 166, 255, 0.6)',
            borderColor: '#58a6ff',
            borderWidth: 1,
            borderRadius: 3,
          },
        ]
      },
      options: {
        indexAxis: 'y',
        animation: false,
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: {
            stacked: false,
            ticks: { color: '#8b949e', font: { size: 10 } },
            grid: { color: 'rgba(33, 38, 45, 0.8)' },
          },
          y: {
            ticks: {
              color: '#8b949e',
              font: { size: 11, family: "'JetBrains Mono', monospace" },
            },
            grid: { color: 'rgba(33, 38, 45, 0.8)' },
          }
        },
        plugins: {
          legend: {
            labels: {
              color: '#8b949e',
              font: { size: 11 },
              usePointStyle: true,
              pointStyleWidth: 10,
            }
          },
          tooltip: {
            backgroundColor: '#161b22',
            borderColor: '#30363d',
            borderWidth: 1,
            titleColor: '#e6edf3',
            bodyColor: '#8b949e',
            callbacks: {
              label: function(ctx) {
                const bytes = ctx.parsed.x;
                const label = ctx.dataset.label;
                return `${label}: ${formatBytes(bytes)}`;
              }
            }
          }
        }
      }
    });

    // Bandwidth Time Series
    bandwidth = new Chart(document.getElementById('chart-bandwidth'), {
      type: 'line',
      data: {
        labels: [],
        datasets: [
          {
            label: 'in (kB/s)',
            data: [],
            borderColor: '#3fb950',
            backgroundColor: 'rgba(63, 185, 80, 0.05)',
            fill: false,
            tension: 0.3,
            pointRadius: 0,
            borderWidth: 2,
          },
          {
            label: 'out (kB/s)',
            data: [],
            borderColor: '#58a6ff',
            backgroundColor: 'rgba(88, 166, 255, 0.05)',
            fill: false,
            tension: 0.3,
            pointRadius: 0,
            borderWidth: 2,
          },
        ]
      },
      options: {
        animation: false,
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: 'index', intersect: false },
        scales: {
          x: { display: false },
          y: {
            min: 0,
            ticks: { color: '#8b949e', font: { size: 11 } },
            grid: { color: 'rgba(33, 38, 45, 0.8)' },
          }
        },
        plugins: {
          legend: {
            labels: {
              color: '#8b949e',
              font: { size: 11 },
              usePointStyle: true,
              pointStyleWidth: 10,
            }
          },
          tooltip: {
            backgroundColor: '#161b22',
            borderColor: '#30363d',
            borderWidth: 1,
            titleColor: '#e6edf3',
            bodyColor: '#8b949e',
          }
        }
      }
    });

    // RTT Histogram
    rttHist = new Chart(document.getElementById('chart-rtt-hist'), {
      type: 'bar',
      data: {
        labels: [],
        datasets: [{
          label: 'count',
          data: [],
          backgroundColor: 'rgba(88, 166, 255, 0.25)',
          borderColor: '#58a6ff',
          borderWidth: 1,
          borderRadius: 2,
        }]
      },
      options: {
        animation: false,
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: {
            ticks: { color: '#8b949e', font: { size: 10 }, maxRotation: 0 },
            grid: { color: 'rgba(33, 38, 45, 0.8)' },
            title: { display: true, text: 'RTT (ms)', color: '#8b949e', font: { size: 11 } },
          },
          y: {
            ticks: { color: '#8b949e', font: { size: 10 } },
            grid: { color: 'rgba(33, 38, 45, 0.8)' },
          }
        },
        plugins: { legend: { display: false } }
      }
    });
  }

  // Update Functions

  function updateRttLine(series) {
    // series: [{t: unix_float, rtt: float}, ...]
    rttLine.data.labels = series.map(p =>
      new Date(p.t * 1000).toLocaleTimeString()
    );
    rttLine.data.datasets[0].data = series.map(p => p.rtt);
    rttLine.update('none');
  }

  function updateProtoPie(counts) {
    protoPie.data.datasets[0].data = [
      counts.TCP || 0,
      counts.UDP || 0,
      counts.ICMP || 0,
      counts.DNS || 0,
      counts.ARP || 0,
      counts.Other || 0,
    ];
    protoPie.update('none');
  }

  function updateTalkers(talkers) {
    // talkers: [{ip, bytes_in, bytes_out, packets}, ...]
    const top5 = talkers.slice(0, 5);
    talkerBar.data.labels = top5.map(t => t.ip);
    talkerBar.data.datasets[0].data = top5.map(t => t.bytes_in);
    talkerBar.data.datasets[1].data = top5.map(t => t.bytes_out);
    talkerBar.update('none');
  }

  function updateBandwidth(bps_in, bps_out, timestamp) {
    const MAX_POINTS = 120;
    const t = new Date(timestamp * 1000).toLocaleTimeString();
    bandwidth.data.labels.push(t);
    bandwidth.data.datasets[0].data.push(bps_in / 1024);   // kB/s
    bandwidth.data.datasets[1].data.push(bps_out / 1024);
    if (bandwidth.data.labels.length > MAX_POINTS) {
      bandwidth.data.labels.shift();
      bandwidth.data.datasets[0].data.shift();
      bandwidth.data.datasets[1].data.shift();
    }
    bandwidth.update('none');
  }

  function updateRttHist(series) {
    // Bin RTT values into 5ms buckets, 0–300ms
    const BINS = 60;
    const BIN_SIZE = 5;
    const bins = Array(BINS).fill(0);
    series.forEach(p => {
      const idx = Math.min(Math.floor(p.rtt / BIN_SIZE), BINS - 1);
      bins[idx]++;
    });
    // Only show bins up to the last non-zero value + a few extra
    let maxIdx = 0;
    bins.forEach((v, i) => { if (v > 0) maxIdx = i; });
    const showBins = Math.min(maxIdx + 3, BINS);
    const labels = [];
    const data = [];
    for (let i = 0; i < showBins; i++) {
      labels.push(`${i * BIN_SIZE}`);
      data.push(bins[i]);
    }
    rttHist.data.labels = labels;
    rttHist.data.datasets[0].data = data;
    rttHist.update('none');
  }

  // Helper
  function formatBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / (1024 * 1024)).toFixed(1) + ' MB';
  }

  return {
    init,
    updateRttLine,
    updateProtoPie,
    updateTalkers,
    updateBandwidth,
    updateRttHist,
  };
})();
