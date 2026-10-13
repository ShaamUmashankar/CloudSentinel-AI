/**
 * CloudSentinel AI - SOC Dashboard Chart.js Visualizer
 */

let severityChartInstance = null;
let trendChartInstance = null;
let categoryChartInstance = null;

async function initDashboardCharts() {
  try {
    const res = await fetch('/api/dashboard/stats');
    const data = await res.json();
    if (!data.success) return;

    renderSeverityChart(data.severity_counts);
    renderTrendChart(data.trends);
    renderCategoryChart(data.top_categories);
  } catch (err) {
    console.error('Failed to load dashboard metrics:', err);
  }
}

function renderSeverityChart(sevCounts) {
  const ctx = document.getElementById('severityChart');
  if (!ctx) return;

  if (severityChartInstance) severityChartInstance.destroy();

  const labels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const values = labels.map(l => sevCounts[l] || 0);

  severityChartInstance = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: labels,
      datasets: [{
        data: values,
        backgroundColor: ['#ff1744', '#ffab00', '#4facfe', '#00e676'],
        borderWidth: 2,
        borderColor: 'rgba(17, 24, 39, 0.8)'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom',
          labels: { color: '#94a3b8', font: { family: 'Inter', size: 12 } }
        }
      },
      cutout: '72%'
    }
  });
}

function renderTrendChart(trends) {
  const ctx = document.getElementById('trendChart');
  if (!ctx) return;

  if (trendChartInstance) trendChartInstance.destroy();

  const labels = trends.map(t => t.time_slot.replace('T', ' '));
  const totals = trends.map(t => t.total);
  const anomalies = trends.map(t => t.anomalies);

  trendChartInstance = new Chart(ctx, {
    type: 'line',
    data: {
      labels: labels.length ? labels : ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
      datasets: [
        {
          label: 'Total Ingested Events',
          data: totals.length ? totals : [4, 6, 12, 18, 14, 8],
          borderColor: '#4facfe',
          backgroundColor: 'rgba(79, 172, 254, 0.1)',
          fill: true,
          tension: 0.35,
          borderWidth: 2
        },
        {
          label: 'Anomalies / Threats',
          data: anomalies.length ? anomalies : [0, 1, 2, 5, 2, 1],
          borderColor: '#ff1744',
          backgroundColor: 'rgba(255, 23, 68, 0.15)',
          fill: true,
          tension: 0.35,
          borderWidth: 2
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          ticks: { color: '#64748b', maxTicksLimit: 6 },
          grid: { color: 'rgba(255, 255, 255, 0.05)' }
        },
        y: {
          ticks: { color: '#64748b' },
          grid: { color: 'rgba(255, 255, 255, 0.05)' }
        }
      },
      plugins: {
        legend: {
          position: 'top',
          labels: { color: '#94a3b8', font: { family: 'Inter', size: 12 } }
        }
      }
    }
  });
}

function renderCategoryChart(categories) {
  const ctx = document.getElementById('categoryChart');
  if (!ctx) return;

  if (categoryChartInstance) categoryChartInstance.destroy();

  const labels = categories.map(c => c.category);
  const data = categories.map(c => c.count);

  categoryChartInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels.length ? labels : ['Defense Evasion', 'IAM Privilege', 'Authentication', 'Data Access'],
      datasets: [{
        label: 'Suspicious Event Count',
        data: data.length ? data : [2, 3, 4, 1],
        backgroundColor: 'rgba(0, 242, 254, 0.75)',
        borderRadius: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          ticks: { color: '#64748b' },
          grid: { display: false }
        },
        y: {
          ticks: { color: '#64748b' },
          grid: { color: 'rgba(255, 255, 255, 0.05)' }
        }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });
}

document.addEventListener('DOMContentLoaded', () => {
  if (document.getElementById('severityChart')) {
    initDashboardCharts();
  }
});
