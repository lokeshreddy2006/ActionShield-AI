import React, { useState } from 'react'
import { apiUrl } from '../config/api'

export default function AuditTable({
  records = [],
  loading = false,
  error = null,
  limit = 50,
  lastUpdated = null,
  onLimitChange,
  onRefresh,
}) {
  const [expandedRow, setExpandedRow] = useState(null)
  const [clearing, setClearing] = useState(false)
  const [clearSuccess, setClearSuccess] = useState(null)
  const [clearError, setClearError] = useState(null)

  const handleClearLogs = async () => {
    const confirmed = window.confirm(
      'Are you sure you want to permanently clear all audit logs?\n\n' +
      'WARNING: This operation permanently deletes all audit log records from SQLite and cannot be undone.'
    )
    if (!confirmed) {
      return
    }

    setClearing(true)
    setClearError(null)
    setClearSuccess(null)

    try {
      const response = await fetch(apiUrl('/audit'), {
        method: 'DELETE',
        headers: {
          'Cache-Control': 'no-cache',
          Pragma: 'no-cache',
        },
      })

      const contentType = response.headers.get('content-type') || ''
      if (!contentType.includes('application/json')) {
        throw new Error(
          !response.ok
            ? `Clear failed with status ${response.status}`
            : 'Server returned non-JSON response format.'
        )
      }

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}))
        throw new Error(errorData.detail || `Clear failed with status ${response.status}`)
      }

      const data = await response.json()
      const count = typeof data.deleted_count === 'number' ? data.deleted_count : 0
      setClearSuccess(`Audit trail cleared successfully (${count} record${count === 1 ? '' : 's'} deleted).`)

      if (onRefresh) {
        onRefresh()
      }
    } catch (err) {
      setClearError(err.message || 'Failed to clear audit logs.')
    } finally {
      setClearing(false)
    }
  }

  const toggleRow = (id) => {
    setExpandedRow((prev) => (prev === id ? null : id))
  }

  const formatTimestamp = (isoString) => {
    if (!isoString) return '-'
    try {
      const date = new Date(isoString)
      return date.toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
      }) + ' ' + date.toLocaleDateString([], {
        month: 'short',
        day: 'numeric',
      })
    } catch {
      return isoString
    }
  }

  const formatLastUpdated = (date) => {
    if (!date) return null
    return date.toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    })
  }

  const getDecisionBadge = (decision) => {
    const dec = (decision || '').toUpperCase()
    let className = 'pill-block'
    if (dec === 'ALLOW') className = 'pill-allow'
    else if (dec === 'REVIEW') className = 'pill-review'
    return <span className={`pill ${className}`}>{dec || 'UNKNOWN'}</span>
  }

  const getExecutionBadge = (status) => {
    if (!status) {
      return <span className="pill-exec pill-eval-only">Evaluated Only</span>
    }
    const stat = status.toUpperCase()
    if (stat === 'EXECUTED') {
      return <span className="pill-exec pill-exec-success">EXECUTED</span>
    } else if (stat === 'SKIPPED_REVIEW_REQUIRED') {
      return <span className="pill-exec pill-exec-review">REVIEW REQ</span>
    } else if (stat === 'BLOCKED') {
      return <span className="pill-exec pill-exec-blocked">BLOCKED</span>
    }
    return <span className="pill-exec pill-exec-failed">{stat}</span>
  }

  return (
    <section className="audit-section card" aria-label="Recent Audit Activity">
      <div className="audit-header">
        <div>
          <div className="audit-title-wrap">
            <h2 className="card-title">Recent Audit Activity</h2>
            {loading ? (
              <span className="badge-refreshing">
                <span className="spinner-micro" aria-hidden="true" />
                <span>Refreshing...</span>
              </span>
            ) : lastUpdated ? (
              <span className="badge-last-updated" title={`Last verified with SQLite at ${formatLastUpdated(lastUpdated)}`}>
                <span className="dot-synced" aria-hidden="true" />
                <span>Last updated: {formatLastUpdated(lastUpdated)}</span>
              </span>
            ) : null}
          </div>
          <p className="card-subtitle">
            Immutable SQLite audit trail tracking action evaluations and controlled simulation outcomes.
          </p>
        </div>

        <div className="audit-controls">
          <div className="limit-selector-wrap">
            <label htmlFor="audit-limit" className="limit-label">Limit:</label>
            <select
              id="audit-limit"
              className="select-limit"
              value={limit}
              onChange={(e) => onLimitChange(Number(e.target.value))}
              disabled={loading}
            >
              <option value={10}>10</option>
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
          </div>

          <button
            type="button"
            className="btn-secondary btn-compact"
            onClick={onRefresh}
            disabled={loading || clearing}
            aria-busy={loading}
            title="Refresh latest audit records from SQLite"
          >
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={loading ? 'spin' : ''}>
              <path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.2" />
            </svg>
            <span>{loading ? 'Refreshing...' : 'Refresh Logs'}</span>
          </button>

          <button
            type="button"
            className="btn-secondary btn-compact btn-clear-audit"
            onClick={handleClearLogs}
            disabled={loading || clearing}
            aria-busy={clearing}
            title="Permanently clear all audit logs from SQLite after confirmation"
          >
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={clearing ? 'spin' : ''}>
              {clearing ? (
                <path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.2" />
              ) : (
                <>
                  <polyline points="3 6 5 6 21 6" />
                  <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
                  <line x1="10" y1="11" x2="10" y2="17" />
                  <line x1="14" y1="11" x2="14" y2="17" />
                </>
              )}
            </svg>
            <span>{clearing ? 'Clearing...' : 'Clear Audit Logs'}</span>
          </button>
        </div>
      </div>

      {/* Clear success notification */}
      {clearSuccess && (
        <div className="alert-banner alert-success" role="status">
          <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
            <polyline points="22 4 12 14.01 9 11.01" />
          </svg>
          <span>{clearSuccess}</span>
          <button
            type="button"
            className="btn-alert-close"
            onClick={() => setClearSuccess(null)}
            aria-label="Close notification"
          >
            &times;
          </button>
        </div>
      )}

      {/* Clear error notification */}
      {clearError && (
        <div className="alert-banner alert-error" role="alert">
          <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <circle cx="12" cy="12" r="10" />
            <line x1="12" y1="8" x2="12" y2="12" />
            <line x1="12" y1="16" x2="12.01" y2="16" />
          </svg>
          <div>
            <strong>Clear failed:</strong> {clearError}
          </div>
          <button
            type="button"
            className="btn-alert-close"
            onClick={() => setClearError(null)}
            aria-label="Close error notification"
          >
            &times;
          </button>
        </div>
      )}

      {/* Error state */}
      {error && (
        <div className="alert alert-error" role="alert">
          <div>
            <strong>Failed to load audit activity:</strong> {error}
          </div>
          <button type="button" className="btn-retry" onClick={onRefresh} disabled={loading || clearing}>
            Retry
          </button>
        </div>
      )}

      {/* Table state with subtle refresh indicator bar */}
      <div className={`table-responsive ${loading ? 'table-loading' : ''}`}>
        {loading && records.length > 0 && (
          <div className="table-refresh-bar" aria-hidden="true">
            <div className="table-refresh-shimmer" />
          </div>
        )}

        <table className="audit-table">
          <thead>
            <tr>
              <th scope="col">Time</th>
              <th scope="col">Action Type</th>
              <th scope="col">Policy Decision</th>
              <th scope="col">Execution</th>
              <th scope="col">Policy Reason / Outcome</th>
              <th scope="col">Details</th>
            </tr>
          </thead>
          <tbody>
            {loading && records.length === 0 ? (
              <tr>
                <td colSpan={6} className="table-cell-empty">
                  <div className="loading-state">
                    <span className="spinner" aria-hidden="true" />
                    <span>Loading audit records from SQLite...</span>
                  </div>
                </td>
              </tr>
            ) : records.length === 0 ? (
              <tr>
                <td colSpan={6} className="table-cell-empty">
                  <div className="empty-state">
                    <svg viewBox="0 0 24 24" width="32" height="32" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                      <polyline points="14 2 14 8 20 8" />
                      <line x1="16" y1="13" x2="8" y2="13" />
                      <line x1="16" y1="17" x2="8" y2="17" />
                      <polyline points="10 9 9 9 8 9" />
                    </svg>
                    <p className="empty-title">No Audit Records Found</p>
                    <p className="empty-desc">
                      Evaluate or execute an action in the Action Testing Lab above to populate the audit log.
                    </p>
                  </div>
                </td>
              </tr>
            ) : (
              records.map((record) => {
                const isExpanded = expandedRow === record.id
                const hasMetadata = record.metadata && Object.keys(record.metadata).length > 0

                return (
                  <React.Fragment key={record.id}>
                    <tr className={`audit-row ${isExpanded ? 'row-expanded' : ''}`}>
                      <td className="cell-time" title={record.timestamp}>
                        {formatTimestamp(record.timestamp)}
                      </td>
                      <td className="cell-action">
                        <span className="font-mono">{record.action_type}</span>
                      </td>
                      <td className="cell-decision">
                        {getDecisionBadge(record.policy_decision)}
                      </td>
                      <td className="cell-status">
                        {getExecutionBadge(record.execution_status)}
                      </td>
                      <td className="cell-message" title={record.message}>
                        {record.message}
                      </td>
                      <td className="cell-details">
                        {hasMetadata ? (
                          <button
                            type="button"
                            className="btn-details"
                            onClick={() => toggleRow(record.id)}
                            aria-expanded={isExpanded}
                          >
                            <span>{isExpanded ? 'Hide' : 'Inspect'}</span>
                            <span className="arrow-icon">{isExpanded ? '▲' : '▼'}</span>
                          </button>
                        ) : (
                          <span className="text-dim">-</span>
                        )}
                      </td>
                    </tr>

                    {/* Expandable Metadata Row */}
                    {isExpanded && hasMetadata && (
                      <tr className="metadata-row">
                        <td colSpan={6} className="metadata-cell">
                          <div className="metadata-wrap">
                            <span className="metadata-title">Sanitized Audit Metadata (Secrets Redacted):</span>
                            <pre className="metadata-json font-mono">
                              {JSON.stringify(record.metadata, null, 2)}
                            </pre>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                )
              })
            )}
          </tbody>
        </table>
      </div>

      <div className="audit-footer">
        <span>
          Showing {records.length} recent record{records.length === 1 ? '' : 's'} (newest first)
          {lastUpdated && ` • Synced at ${formatLastUpdated(lastUpdated)}`}
        </span>
        <span>Storage: SQLite (app/database/actionshield.db)</span>
      </div>
    </section>
  )
}
