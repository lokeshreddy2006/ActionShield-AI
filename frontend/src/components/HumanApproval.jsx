import React, { useState } from 'react'
import { apiUrl } from '../config/api'

export default function HumanApproval({
  requests = [],
  loading = false,
  error = null,
  pendingCount = 0,
  onRefresh,
  onApprovalResolved,
}) {
  const [activeTab, setActiveTab] = useState('PENDING')
  const [processingId, setProcessingId] = useState(null)
  const [actionError, setActionError] = useState(null)
  const [actionSuccess, setActionSuccess] = useState(null)

  // Confirmation modal state
  const [confirmModal, setConfirmModal] = useState({
    isOpen: false,
    type: null, // 'APPROVE' | 'REJECT'
    requestId: null,
    actionType: null,
    comment: '',
  })

  const formatTimestamp = (isoString) => {
    if (!isoString) return '-'
    try {
      const date = new Date(isoString)
      return (
        date.toLocaleTimeString([], {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
          hour12: false,
        }) +
        ' ' +
        date.toLocaleDateString([], {
          month: 'short',
          day: 'numeric',
        })
      )
    } catch {
      return isoString
    }
  }

  const handleOpenConfirm = (type, req) => {
    setActionError(null)
    setActionSuccess(null)
    setConfirmModal({
      isOpen: true,
      type,
      requestId: req.id,
      actionType: req.action_type,
      comment: '',
    })
  }

  const handleCloseConfirm = () => {
    setConfirmModal({
      isOpen: false,
      type: null,
      requestId: null,
      actionType: null,
      comment: '',
    })
  }

  const handleConfirmAction = async () => {
    const { type, requestId, comment } = confirmModal
    if (!requestId || !type) return

    setProcessingId(requestId)
    setActionError(null)
    setActionSuccess(null)
    handleCloseConfirm()

    const endpoint =
      type === 'APPROVE'
        ? apiUrl(`/approvals/${requestId}/approve`)
        : apiUrl(`/approvals/${requestId}/reject`)

    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ comment: comment.trim() || undefined }),
      })

      const contentType = response.headers.get('content-type') || ''
      if (!contentType.includes('application/json')) {
        throw new Error(
          `${type === 'APPROVE' ? 'Approval' : 'Rejection'} failed with status ${response.status}`
        )
      }

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}))
        throw new Error(
          errorData.detail ||
            `${type === 'APPROVE' ? 'Approval' : 'Rejection'} failed with status ${response.status}`
        )
      }

      const data = await response.json()
      if (type === 'APPROVE') {
        const execStatus = data.execution?.execution_status || 'PROCESSED'
        setActionSuccess(
          `Action successfully approved! Execution outcome: ${execStatus}.`
        )
      } else {
        setActionSuccess('Action successfully rejected.')
      }

      // Notify parent to refresh approvals queue & audit logs
      if (onApprovalResolved) {
        onApprovalResolved()
      }
    } catch (err) {
      setActionError(err.message || 'Operation failed. Please try again.')
    } finally {
      setProcessingId(null)
    }
  }

  // Filter requests according to activeTab
  const filteredRequests = requests.filter((req) => {
    if (activeTab === 'ALL') return true
    return (req.status || '').toUpperCase() === activeTab
  })

  const approvedCount = requests.filter(
    (r) => (r.status || '').toUpperCase() === 'APPROVED'
  ).length
  const rejectedCount = requests.filter(
    (r) => (r.status || '').toUpperCase() === 'REJECTED'
  ).length

  return (
    <section className="approval-section card" aria-label="Human Approval Queue">
      {/* Header */}
      <div className="card-header-main">
        <div className="approval-header-left">
          <div className="approval-title-row">
            <h2 className="card-title">Human Approval Queue</h2>
            {pendingCount > 0 ? (
              <span className="badge-pending-counter" title={`${pendingCount} action(s) require review`}>
                <span className="pulse-dot" aria-hidden="true" />
                <span>{pendingCount} Pending Review</span>
              </span>
            ) : (
              <span className="badge-cleared">
                <span className="check-icon" aria-hidden="true">✓</span>
                <span>All Cleared</span>
              </span>
            )}
          </div>
          <p className="card-subtitle">
            Supervisory intervention checkpoint. Actions evaluated as REVIEW halt here
            until a human reviewer authorizes safe in-memory execution or rejects them.
          </p>
        </div>

        <div className="approval-header-actions">
          <button
            type="button"
            className="btn-refresh"
            onClick={onRefresh}
            disabled={loading}
            title="Refresh human approval queue from backend"
          >
            <span className={`refresh-icon ${loading ? 'spin' : ''}`} aria-hidden="true">
              ↻
            </span>
            <span>Refresh Queue</span>
          </button>
        </div>
      </div>

      {/* Status Notifications */}
      {actionSuccess && (
        <div className="alert-banner alert-success" role="status">
          <span className="alert-icon">✓</span>
          <span>{actionSuccess}</span>
          <button
            type="button"
            className="btn-alert-close"
            onClick={() => setActionSuccess(null)}
          >
            ✕
          </button>
        </div>
      )}

      {actionError && (
        <div className="alert-banner alert-error" role="alert">
          <span className="alert-icon">⚠</span>
          <span>{actionError}</span>
          <button
            type="button"
            className="btn-alert-close"
            onClick={() => setActionError(null)}
          >
            ✕
          </button>
        </div>
      )}

      {error && (
        <div className="alert-banner alert-error" role="alert">
          <span className="alert-icon">⚠</span>
          <span>Error loading queue: {error}</span>
        </div>
      )}

      {/* Filter Tabs */}
      <div className="approval-tabs" role="tablist">
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'PENDING'}
          className={`approval-tab ${activeTab === 'PENDING' ? 'active' : ''}`}
          onClick={() => setActiveTab('PENDING')}
        >
          Pending ({pendingCount})
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'APPROVED'}
          className={`approval-tab ${activeTab === 'APPROVED' ? 'active' : ''}`}
          onClick={() => setActiveTab('APPROVED')}
        >
          Approved ({approvedCount})
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'REJECTED'}
          className={`approval-tab ${activeTab === 'REJECTED' ? 'active' : ''}`}
          onClick={() => setActiveTab('REJECTED')}
        >
          Rejected ({rejectedCount})
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'ALL'}
          className={`approval-tab ${activeTab === 'ALL' ? 'active' : ''}`}
          onClick={() => setActiveTab('ALL')}
        >
          All History ({requests.length})
        </button>
      </div>

      {/* Request Cards List */}
      <div className="approval-list">
        {filteredRequests.length === 0 ? (
          <div className="approval-empty-state">
            <div className="empty-state-icon" aria-hidden="true">🛡️</div>
            <div className="empty-state-title">
              {activeTab === 'PENDING'
                ? 'No Pending Actions'
                : `No ${activeTab.toLowerCase()} requests found`}
            </div>
            <p className="empty-state-desc">
              {activeTab === 'PENDING'
                ? 'All proposed agent actions are authorized or cleared. Actions requiring human review will appear here.'
                : 'Switch tabs or run actions from the Action Testing Lab to view approval history.'}
            </p>
          </div>
        ) : (
          filteredRequests.map((req) => {
            const isPending = req.status === 'PENDING'
            const isApproved = req.status === 'APPROVED'
            const isRejected = req.status === 'REJECTED'
            const isProcessing = processingId === req.id

            const details = req.sanitized_details || {}

            return (
              <div
                key={req.id}
                className={`approval-item-card ${isPending ? 'card-pending-glow' : ''}`}
              >
                {/* Item Top Bar */}
                <div className="approval-item-top">
                  <div className="item-identifiers">
                    <span className="badge-action-type">{req.action_type}</span>
                    <span
                      className={`badge-status badge-status-${req.status.toLowerCase()}`}
                    >
                      {isPending && <span className="status-pulse-dot" />}
                      {req.status}
                    </span>
                    <span className="item-req-id" title={`ID: ${req.id}`}>
                      ID: {req.id.slice(0, 8)}...
                    </span>
                  </div>

                  <div className="item-meta-time">
                    <span className="time-label">Created:</span>
                    <span className="time-val">{formatTimestamp(req.created_at)}</span>
                  </div>
                </div>

                {/* Reason Callout */}
                <div className="approval-reason-callout">
                  <span className="reason-icon" aria-hidden="true">⚠</span>
                  <div className="reason-content">
                    <span className="reason-title">Interception Trigger:</span>
                    <p className="reason-text">{req.review_reason}</p>
                  </div>
                </div>

                {/* Sanitized Action Parameters Grid */}
                <div className="approval-details-grid">
                  <div className="details-header">Sanitized Action Parameters:</div>
                  <div className="details-chips">
                    {details.path && (
                      <div className="detail-chip">
                        <span className="chip-key">Target Path:</span>
                        <code className="chip-val">{details.path}</code>
                      </div>
                    )}
                    {details.command && (
                      <div className="detail-chip">
                        <span className="chip-key">Command:</span>
                        <code className="chip-val">{details.command}</code>
                      </div>
                    )}
                    {details.destination && (
                      <div className="detail-chip">
                        <span className="chip-key">Destination URL:</span>
                        <code className="chip-val">{details.destination}</code>
                      </div>
                    )}
                    {typeof details.is_permitted_location === 'boolean' && (
                      <div className="detail-chip">
                        <span className="chip-key">Permitted Location:</span>
                        <span className={`chip-badge ${details.is_permitted_location ? 'badge-yes' : 'badge-no'}`}>
                          {details.is_permitted_location ? 'Yes' : 'No'}
                        </span>
                      </div>
                    )}
                    {details.payload_redacted && (
                      <div className="detail-chip">
                        <span className="chip-key">Payload:</span>
                        <span className="chip-badge badge-redacted">[Redacted for Security]</span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Resolution Outcomes if Approved or Rejected */}
                {!isPending && (
                  <div className="resolution-summary-box">
                    <div className="resolution-row">
                      <span className="res-label">Resolved At:</span>
                      <span className="res-val">{formatTimestamp(req.resolved_at)}</span>
                    </div>
                    {req.resolution_comment && (
                      <div className="resolution-row">
                        <span className="res-label">Reviewer Note:</span>
                        <span className="res-val italic">{req.resolution_comment}</span>
                      </div>
                    )}
                    {isApproved && (
                      <div className="execution-outcome-row">
                        <span className="res-label">Simulation Execution:</span>
                        <span
                          className={`pill-exec ${
                            req.execution_status === 'EXECUTED'
                              ? 'pill-exec-success'
                              : 'pill-exec-blocked'
                          }`}
                        >
                          {req.execution_status || 'EXECUTED'}
                        </span>
                        {req.execution_result?.message && (
                          <div className="exec-result-msg">
                            {req.execution_result.message}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {/* Actions for PENDING items */}
                {isPending && (
                  <div className="approval-actions-bar">
                    <button
                      type="button"
                      className="btn-approve"
                      onClick={() => handleOpenConfirm('APPROVE', req)}
                      disabled={isProcessing}
                    >
                      {isProcessing ? (
                        <>
                          <span className="spinner-micro" />
                          <span>Processing...</span>
                        </>
                      ) : (
                        <>
                          <span className="btn-icon" aria-hidden="true">✓</span>
                          <span>Approve &amp; Execute Simulation</span>
                        </>
                      )}
                    </button>

                    <button
                      type="button"
                      className="btn-reject"
                      onClick={() => handleOpenConfirm('REJECT', req)}
                      disabled={isProcessing}
                    >
                      <span className="btn-icon" aria-hidden="true">✕</span>
                      <span>Reject Action</span>
                    </button>
                  </div>
                )}
              </div>
            )
          })
        )}
      </div>

      {/* Confirmation Modal */}
      {confirmModal.isOpen && (
        <div className="modal-overlay" role="dialog" aria-modal="true">
          <div className="modal-content">
            <div className="modal-header">
              <h3 className="modal-title">
                {confirmModal.type === 'APPROVE'
                  ? 'Confirm Action Approval'
                  : 'Confirm Action Rejection'}
              </h3>
              <button
                type="button"
                className="btn-modal-close"
                onClick={handleCloseConfirm}
                aria-label="Close dialog"
              >
                ✕
              </button>
            </div>

            <div className="modal-body">
              <p className="modal-description">
                {confirmModal.type === 'APPROVE' ? (
                  <>
                    Are you sure you want to approve this{' '}
                    <strong>{confirmModal.actionType}</strong> action? Upon approval,
                    it will be safely executed in the in-memory virtual workspace and
                    permanently recorded in the audit log.
                  </>
                ) : (
                  <>
                    Are you sure you want to reject this{' '}
                    <strong>{confirmModal.actionType}</strong> action? The action will
                    be permanently stopped, will not execute, and will be logged as
                    rejected.
                  </>
                )}
              </p>

              <div className="form-group-modal">
                <label htmlFor="modal-comment" className="modal-label">
                  Supervisor Comment / Note (Optional):
                </label>
                <input
                  id="modal-comment"
                  type="text"
                  className="modal-input"
                  placeholder={
                    confirmModal.type === 'APPROVE'
                      ? 'e.g. Authorized after verifying workspace safety'
                      : 'e.g. Denied - unauthorized destination or script'
                  }
                  value={confirmModal.comment}
                  onChange={(e) =>
                    setConfirmModal((prev) => ({
                      ...prev,
                      comment: e.target.value,
                    }))
                  }
                  autoFocus
                />
              </div>
            </div>

            <div className="modal-footer">
              <button
                type="button"
                className="btn-modal-cancel"
                onClick={handleCloseConfirm}
              >
                Cancel
              </button>

              <button
                type="button"
                className={
                  confirmModal.type === 'APPROVE'
                    ? 'btn-modal-confirm-approve'
                    : 'btn-modal-confirm-reject'
                }
                onClick={handleConfirmAction}
              >
                {confirmModal.type === 'APPROVE'
                  ? 'Yes, Authorize & Execute'
                  : 'Yes, Reject Action'}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}
