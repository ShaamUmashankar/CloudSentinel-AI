/**
 * CloudSentinel AI - Main Client Interactions & UI Controller
 */

// Theme Controller (Dark / Light)
(function initTheme() {
  const savedTheme = localStorage.getItem('cloudsentinel-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', savedTheme);
})();

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  const target = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', target);
  localStorage.setItem('cloudsentinel-theme', target);

  const icon = document.getElementById('theme-toggle-icon');
  if (icon) {
    icon.className = target === 'dark' ? 'bi bi-moon-stars-fill' : 'bi bi-sun-fill';
  }
}

// Global Toast Notification Helper
function showToast(message, type = 'info') {
  let toastContainer = document.getElementById('toast-container');
  if (!toastContainer) {
    toastContainer = document.createElement('div');
    toastContainer.id = 'toast-container';
    toastContainer.style.position = 'fixed';
    toastContainer.style.top = '1.5rem';
    toastContainer.style.right = '1.5rem';
    toastContainer.style.zIndex = '9999';
    document.body.appendChild(toastContainer);
  }

  const toast = document.createElement('div');
  const bgClass = type === 'success' ? 'bg-success' : type === 'danger' ? 'bg-danger' : type === 'warning' ? 'bg-warning text-dark' : 'bg-primary';
  toast.className = `toast align-items-center text-white ${bgClass} border-0 show shadow-lg mb-2`;
  toast.role = 'alert';
  toast.innerHTML = `
    <div class="d-flex">
      <div class="toast-body d-flex align-items-center gap-2">
        <i class="bi ${type === 'success' ? 'bi-check-circle-fill' : type === 'danger' ? 'bi-exclamation-octagon-fill' : 'bi-info-circle-fill'}"></i>
        <span>${message}</span>
      </div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
    </div>
  `;
  toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 400);
  }, 4500);
}

// Quick Sample Log Loader
async function loadSyntheticSampleLogs() {
  const btn = document.getElementById('btn-load-sample');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Ingesting Synthetic Logs...';
  }

  try {
    const res = await fetch('/api/logs/sample-load', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      showToast(`Ingested ${data.etl_summary.processed_records} events (${data.incidents_raised} threats identified)`, 'success');
      setTimeout(() => window.location.reload(), 1200);
    } else {
      showToast(`Ingestion failed: ${data.error}`, 'danger');
    }
  } catch (err) {
    showToast(`Error: ${err.message}`, 'danger');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<i class="bi bi-cloud-arrow-down me-1"></i>Load Demonstration Data';
    }
  }
}

// Retrain ML Model
async function retrainModel() {
  const btn = document.getElementById('btn-retrain-ml');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Training Model...';
  }

  try {
    const res = await fetch('/api/model/retrain', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      showToast(`Model retrained on ${data.metadata.sample_count} events with ${data.metadata.feature_count} features!`, 'success');
      setTimeout(() => window.location.reload(), 1200);
    } else {
      showToast(`Retrain error: ${data.error}`, 'danger');
    }
  } catch (err) {
    showToast(`Error: ${err.message}`, 'danger');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<i class="bi bi-cpu me-1"></i>Retrain ML Model';
    }
  }
}

// Simulated Incident Response Action with Confirmation
let pendingRemediation = null;

function promptSimulatedAction(incidentId, actionType, actionTitle) {
  pendingRemediation = { incidentId, actionType, actionTitle };
  const modalEl = document.getElementById('actionConfirmModal');
  if (!modalEl) return;

  document.getElementById('actionModalTitle').innerText = actionTitle;
  document.getElementById('actionModalDesc').innerText = `Simulate containment action: "${actionTitle}". This will test safety-governed cloud response workflows without modifying real AWS production assets.`;
  
  const modal = new bootstrap.Modal(modalEl);
  modal.show();
}

async function confirmSimulatedAction() {
  if (!pendingRemediation) return;
  const { incidentId, actionType } = pendingRemediation;
  
  const btn = document.getElementById('btn-execute-action-confirm');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Executing Simulation...';
  }

  try {
    const res = await fetch(`/api/incidents/${incidentId}/remediate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action_type: actionType, actor: 'SOC_Analyst' })
    });
    const data = await res.json();

    if (data.success) {
      showToast(`Executed: ${data.response.action_name} (${data.response.status})`, 'success');
      const modalEl = document.getElementById('actionConfirmModal');
      const modal = bootstrap.Modal.getInstance(modalEl);
      if (modal) modal.hide();
      setTimeout(() => window.location.reload(), 1200);
    } else {
      showToast(`Action execution failed: ${data.error}`, 'danger');
    }
  } catch (err) {
    showToast(`Error: ${err.message}`, 'danger');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<i class="bi bi-shield-check me-1"></i>Confirm & Simulate Action';
    }
  }
}

// Update Incident Status
async function updateIncidentStatus(incidentId, newStatus) {
  try {
    const res = await fetch(`/api/incidents/${incidentId}/status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus, actor: 'SOC_Analyst' })
    });
    const data = await res.json();
    if (data.success) {
      showToast(`Incident status updated to "${newStatus}"`, 'success');
      setTimeout(() => window.location.reload(), 800);
    } else {
      showToast(`Failed: ${data.error}`, 'danger');
    }
  } catch (err) {
    showToast(`Error: ${err.message}`, 'danger');
  }
}
