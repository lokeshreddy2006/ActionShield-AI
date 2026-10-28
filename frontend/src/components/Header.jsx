import React from 'react'

export default function Header({ backendStatus, checkingHealth, onCheckHealth }) {
  const isConnected = backendStatus === 'connected'

  return (
    <header className="navbar">
      <div className="navbar-brand">
        <div className="shield-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            <path d="M9 12l2 2 4-4" />
          </svg>
        </div>
        <div className="brand-text">
          <div className="brand-title-wrap">
            <span className="brand-title">ActionShield AI</span>
          </div>
          <span className="brand-subtitle">AI-Agent Safety Checkpoint &amp; Deterministic Policy Layer</span>
        </div>
      </div>

      <div className="navbar-actions">
        <div
          className={`status-indicator ${isConnected ? 'status-connected' : 'status-disconnected'}`}
          title={isConnected ? 'Backend connected on http://127.0.0.1:8000' : 'Backend connection unavailable'}
        >
          <span className="status-dot" aria-hidden="true" />
          <span className="status-text">
            {checkingHealth ? 'Checking...' : isConnected ? 'Backend Connected' : 'Backend Disconnected'}
          </span>
        </div>

        <button
          type="button"
          className="btn-secondary btn-compact"
          onClick={onCheckHealth}
          disabled={checkingHealth}
          title="Check backend health"
        >
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={checkingHealth ? 'spin' : ''}>
            <path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.2" />
          </svg>
          <span>{checkingHealth ? 'Checking' : 'Check Health'}</span>
        </button>
      </div>
    </header>
  )
}
