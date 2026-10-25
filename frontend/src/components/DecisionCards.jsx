import React from 'react'

export default function DecisionCards({ auditRecords = [], loading = false }) {
  const counts = auditRecords.reduce(
    (acc, record) => {
      const decision = (record.policy_decision || '').toUpperCase()
      if (decision === 'ALLOW') acc.allow += 1
      else if (decision === 'REVIEW') acc.review += 1
      else if (decision === 'BLOCK') acc.block += 1
      return acc
    },
    { allow: 0, review: 0, block: 0 }
  )

  const totalLoaded = auditRecords.length
  const isInitialLoading = loading && totalLoaded === 0

  return (
    <section className="decision-cards-section" aria-label="Policy Decision Summary">
      <div className="section-header-compact">
        <div className="section-title-wrap">
          <h2 className="section-title">Decision Overview</h2>
          {loading && (
            <span className="updating-indicator" aria-live="polite">
              <span className="spinner-micro" aria-hidden="true" />
              <span>Updating...</span>
            </span>
          )}
        </div>
        <span className="section-note">
          {loading
            ? 'Refreshing counts from latest audit logs...'
            : `Calculated from ${totalLoaded} retrieved audit record${totalLoaded === 1 ? '' : 's'} (not lifetime totals)`}
        </span>
      </div>

      <div className="decision-grid">
        <div className="card decision-card card-allow">
          <div className="decision-card-header">
            <div className="decision-badge badge-allow">ALLOW</div>
            <span className="decision-icon" aria-hidden="true">✓</span>
          </div>
          <div className="decision-count">{isInitialLoading ? '-' : counts.allow}</div>
          <div className="decision-desc">
            Permitted safe actions executed or approved without restriction.
          </div>
        </div>

        <div className="card decision-card card-review">
          <div className="decision-card-header">
            <div className="decision-badge badge-review">REVIEW</div>
            <span className="decision-icon" aria-hidden="true">⚠</span>
          </div>
          <div className="decision-count">{isInitialLoading ? '-' : counts.review}</div>
          <div className="decision-desc">
            High-risk operations paused for human supervisor inspection.
          </div>
        </div>

        <div className="card decision-card card-block">
          <div className="decision-card-header">
            <div className="decision-badge badge-block">BLOCK</div>
            <span className="decision-icon" aria-hidden="true">✕</span>
          </div>
          <div className="decision-count">{isInitialLoading ? '-' : counts.block}</div>
          <div className="decision-desc">
            Forbidden operations, sensitive exfiltration, or invalid actions.
          </div>
        </div>
      </div>
    </section>
  )
}
