import React, { useCallback, useEffect, useState } from 'react'
import { apiUrl } from '../config/api'

export default function WorkflowCrashTestLab() {
  const [scenarios, setScenarios] = useState([])
  const [loadingScenarios, setLoadingScenarios] = useState(false)
  const [scenariosError, setScenariosError] = useState(null)

  // Map of scenario_id -> run result object
  const [runResults, setRunResults] = useState({})
  // ID of currently running scenario or 'ALL'
  const [runningId, setRunningId] = useState(null)
  const [runError, setRunError] = useState(null)

  // Track expanded scenario details
  const [expandedScenarios, setExpandedScenarios] = useState({})

  // Fetch scenario definitions
  const fetchScenarios = useCallback(async () => {
    setLoadingScenarios(true)
    setScenariosError(null)
    try {
      const response = await fetch(apiUrl(`/crash-tests/scenarios?_t=${Date.now()}`), {
        method: 'GET',
        cache: 'no-store',
        headers: { 'Cache-Control': 'no-cache', Pragma: 'no-cache' },
      })
      const contentType = response.headers.get('content-type') || ''
      if (!contentType.includes('application/json')) {
        throw new Error(
          !response.ok
            ? `Failed to load scenarios: status ${response.status}`
            : 'Server returned non-JSON response format.'
        )
      }
      if (!response.ok) {
        throw new Error(`Failed to load scenarios: status ${response.status}`)
      }
      const data = await response.json()
      setScenarios(Array.isArray(data.scenarios) ? data.scenarios : [])
    } catch (err) {
      setScenariosError(err.message || 'Failed to retrieve test scenarios.')
    } finally {
      setLoadingScenarios(false)
    }
  }, [])

  useEffect(() => {
    fetchScenarios()
  }, [fetchScenarios])

  const toggleExpand = (id) => {
    setExpandedScenarios((prev) => ({
      ...prev,
      [id]: !prev[id],
    }))
  }

  // Run a single scenario
  const handleRunScenario = async (scenarioId) => {
    if (runningId) return
    setRunningId(scenarioId)
    setRunError(null)

    try {
      const response = await fetch(apiUrl(`/crash-tests/run/${scenarioId}`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      })
      const contentType = response.headers.get('content-type') || ''
      if (!contentType.includes('application/json')) {
        throw new Error(
          !response.ok
            ? `Crash test failed with status ${response.status}`
            : 'Server returned non-JSON response format.'
        )
      }
      if (!response.ok) {
        const errData = await response.json().catch(() => ({}))
        throw new Error(errData.detail || `Crash test failed with status ${response.status}`)
      }
      const result = await response.json()
      setRunResults((prev) => ({
        ...prev,
        [scenarioId]: result,
      }))
      // Automatically expand the executed scenario to display results
      setExpandedScenarios((prev) => ({
        ...prev,
        [scenarioId]: true,
      }))
    } catch (err) {
      setRunError(err.message || 'Crash-test run failed.')
    } finally {
      setRunningId(null)
    }
  }

  // Run all scenarios
  const handleRunAll = async () => {
    if (runningId) return
    setRunningId('ALL')
    setRunError(null)

    try {
      const response = await fetch(apiUrl('/crash-tests/run-all'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      })
      const contentType = response.headers.get('content-type') || ''
      if (!contentType.includes('application/json')) {
        throw new Error(
          !response.ok
            ? `Aggregated crash test failed with status ${response.status}`
            : 'Server returned non-JSON response format.'
        )
      }
      if (!response.ok) {
        const errData = await response.json().catch(() => ({}))
        throw new Error(errData.detail || `Aggregated crash test failed with status ${response.status}`)
      }
      const report = await response.json()
      const newResults = {}
      const newExpanded = {}

      if (Array.isArray(report.scenarios)) {
        report.scenarios.forEach((res) => {
          newResults[res.scenario_id] = res
          newExpanded[res.scenario_id] = true
        })
      }

      setRunResults(newResults)
      setExpandedScenarios(newExpanded)
    } catch (err) {
      setRunError(err.message || 'Aggregated crash-test execution failed.')
    } finally {
      setRunningId(null)
    }
  }

  // Calculate summary metrics across completed runs
  const totalScenarios = scenarios.length
  const completedRuns = Object.values(runResults)
  const executedCount = completedRuns.length
  const passedCount = completedRuns.filter((r) => r.status === 'PASS').length
  const failedCount = completedRuns.filter((r) => r.status === 'FAIL').length

  const getDecisionBadge = (decision) => {
    const dec = (decision || '').toUpperCase()
    if (dec === 'ALLOW') return <span className="pill pill-allow">ALLOW</span>
    if (dec === 'REVIEW') return <span className="pill pill-review">REVIEW</span>
    if (dec === 'BLOCK') return <span className="pill pill-block">BLOCK</span>
    return <span className="pill pill-block">{dec || 'UNKNOWN'}</span>
  }

  const getExecutionBadge = (status) => {
    const s = (status || '').toUpperCase()
    if (s === 'EXECUTED') return <span className="pill-exec pill-exec-success">EXECUTED</span>
    if (s === 'SKIPPED_REVIEW_REQUIRED') return <span className="pill-exec pill-exec-review">HALTED FOR REVIEW</span>
    if (s === 'BLOCKED') return <span className="pill-exec pill-exec-blocked">BLOCKED</span>
    return <span className="pill-exec pill-exec-failed">{s || 'FAIL CLOSED'}</span>
  }

  return (
    <section className="crashtest-section card" aria-label="Workflow Crash-Test Lab">
      {/* Header */}
      <div className="card-header-main">
        <div className="crashtest-header-left">
          <div className="crashtest-title-row">
            <h2 className="card-title">Workflow Crash-Test Lab</h2>
            <span className="badge-lab-mode">
              <span className="dot-cyber" aria-hidden="true" />
              <span>Multi-Step Attack &amp; Bound Verification</span>
            </span>
          </div>
          <p className="card-subtitle">
            Automated resilience testing engine simulating multi-step autonomous agent attack vectors,
            exfiltration attempts, and benign operations against deterministic safety policies.
          </p>
        </div>

        <div className="crashtest-header-actions">
          <button
            type="button"
            className="btn-refresh"
            onClick={fetchScenarios}
            disabled={loadingScenarios || runningId !== null}
            title="Refresh scenario definitions"
          >
            <span className={`refresh-icon ${loadingScenarios ? 'spin' : ''}`}>↻</span>
            <span>Reload</span>
          </button>

          <button
            type="button"
            className="btn-run-all"
            onClick={handleRunAll}
            disabled={runningId !== null}
            title="Run all crash-test scenarios and generate aggregate safety report"
          >
            {runningId === 'ALL' ? (
              <>
                <span className="spinner-micro" />
                <span>Running All...</span>
              </>
            ) : (
              <>
                <span className="btn-icon">▶</span>
                <span>Run All Scenarios</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Summary Scorecard if tests have run */}
      {executedCount > 0 && (
        <div className="crashtest-scorecard">
          <div className="scorecard-metric">
            <span className="scorecard-label">Total Scenarios:</span>
            <span className="scorecard-value">{totalScenarios}</span>
          </div>
          <div className="scorecard-metric">
            <span className="scorecard-label">Executed:</span>
            <span className="scorecard-value">{executedCount} / {totalScenarios}</span>
          </div>
          <div className="scorecard-metric text-success">
            <span className="scorecard-label">Passed Safety Checks:</span>
            <span className="scorecard-value">{passedCount}</span>
          </div>
          <div className="scorecard-metric text-danger">
            <span className="scorecard-label">Failed Safety Checks:</span>
            <span className="scorecard-value">{failedCount}</span>
          </div>
          <div className="scorecard-metric">
            <span className="scorecard-label">Verification Rate:</span>
            <span className="scorecard-value">
              {Math.round((passedCount / executedCount) * 100)}%
            </span>
          </div>
        </div>
      )}

      {/* Alerts */}
      {scenariosError && (
        <div className="alert-banner alert-error" role="alert">
          <span className="alert-icon">⚠</span>
          <span>{scenariosError}</span>
        </div>
      )}

      {runError && (
        <div className="alert-banner alert-error" role="alert">
          <span className="alert-icon">⚠</span>
          <span>{runError}</span>
          <button
            type="button"
            className="btn-alert-close"
            onClick={() => setRunError(null)}
          >
            ✕
          </button>
        </div>
      )}

      {/* Scenarios List */}
      <div className="crashtest-list">
        {scenarios.map((scenario) => {
          const run = runResults[scenario.id]
          const isRunningThis = runningId === scenario.id || runningId === 'ALL'
          const isExpanded = Boolean(expandedScenarios[scenario.id])

          return (
            <div
              key={scenario.id}
              className={`crashtest-card ${
                run ? (run.status === 'PASS' ? 'card-status-pass' : 'card-status-fail') : ''
              }`}
            >
              {/* Card Header Top */}
              <div className="crashtest-card-top">
                <div className="crashtest-ident-group">
                  <span className="badge-scenario-id">{scenario.id}</span>
                  <h3 className="crashtest-name">{scenario.name}</h3>
                  <span className="badge-step-count">{scenario.step_count} Steps</span>

                  {run && (
                    <span
                      className={`badge-result ${
                        run.status === 'PASS' ? 'badge-pass' : 'badge-fail'
                      }`}
                    >
                      {run.status === 'PASS' ? '✓ ALL CHECKS PASSED' : '✕ SAFETY VIOLATION'}
                    </span>
                  )}
                </div>

                <div className="crashtest-card-actions">
                  <button
                    type="button"
                    className="btn-run-single"
                    onClick={() => handleRunScenario(scenario.id)}
                    disabled={runningId !== null}
                    title={`Execute test for '${scenario.name}'`}
                  >
                    {runningId === scenario.id ? (
                      <>
                        <span className="spinner-micro" />
                        <span>Running...</span>
                      </>
                    ) : (
                      <>
                        <span className="btn-icon">▶</span>
                        <span>{run ? 'Rerun Test' : 'Run Scenario'}</span>
                      </>
                    )}
                  </button>

                  <button
                    type="button"
                    className="btn-toggle-details"
                    onClick={() => toggleExpand(scenario.id)}
                    aria-expanded={isExpanded}
                  >
                    {isExpanded ? 'Hide Steps ▲' : 'Inspect Steps ▼'}
                  </button>
                </div>
              </div>

              {/* Safety Risk Statement */}
              <div className="crashtest-risk-callout">
                <span className="risk-icon" aria-hidden="true">⚡</span>
                <div className="risk-body">
                  <span className="risk-title">Safety Risk Tested:</span>
                  <p className="risk-text">{scenario.safety_risk}</p>
                </div>
              </div>

              {/* Expected Safety Outcome */}
              <div className="crashtest-expected-bar">
                <span className="expected-label">Expected Policy Outcome:</span>
                <span className="expected-val">{scenario.expected_outcome}</span>
              </div>

              {/* Detailed Per-Step Execution Table (when expanded) */}
              {isExpanded && (
                <div className="crashtest-steps-container">
                  <h4 className="steps-header">Workflow Step Sequence &amp; Policy Assertions:</h4>

                  <div className="steps-table-wrapper">
                    <table className="steps-table">
                      <thead>
                        <tr>
                          <th>Step</th>
                          <th>Action Type</th>
                          <th>Description</th>
                          <th>Expected</th>
                          <th>Actual Decision</th>
                          <th>Simulation Status</th>
                          <th>Step Result</th>
                        </tr>
                      </thead>
                      <tbody>
                        {scenario.steps.map((step) => {
                          const stepResult = run?.steps?.find(
                            (s) => s.step_number === step.step_number
                          )

                          return (
                            <tr key={step.step_number} className="step-row">
                              <td className="step-num-cell">#{step.step_number}</td>
                              <td>
                                <span className="badge-action-type">
                                  {step.action?.action_type || 'UNKNOWN'}
                                </span>
                              </td>
                              <td className="step-desc-cell">{step.description}</td>
                              <td>{getDecisionBadge(step.expected_decision)}</td>
                              <td>
                                {stepResult ? (
                                  <div className="actual-decision-wrap">
                                    {getDecisionBadge(stepResult.actual_decision)}
                                    <span
                                      className={`match-icon ${
                                        stepResult.decision_matches
                                          ? 'text-success'
                                          : 'text-danger'
                                      }`}
                                      title={
                                        stepResult.decision_matches
                                          ? 'Decision matches expectation'
                                          : 'Decision mismatch'
                                      }
                                    >
                                      {stepResult.decision_matches ? '✓' : '✕'}
                                    </span>
                                  </div>
                                ) : (
                                  <span className="text-muted italic">Pending run</span>
                                )}
                              </td>
                              <td>
                                {stepResult ? (
                                  getExecutionBadge(stepResult.execution_status)
                                ) : (
                                  <span className="text-muted">-</span>
                                )}
                              </td>
                              <td>
                                {stepResult ? (
                                  <span
                                    className={`pill-step-result ${
                                      stepResult.passed ? 'step-pass' : 'step-fail'
                                    }`}
                                  >
                                    {stepResult.passed ? 'PASS' : 'FAIL'}
                                  </span>
                                ) : (
                                  <span className="text-muted">-</span>
                                )}
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>

                  {/* Explanatory Step Log Details */}
                  {run?.steps && (
                    <div className="steps-log-details">
                      <div className="log-details-title">Step Evaluation Trace:</div>
                      {run.steps.map((s) => (
                        <div key={s.step_number} className="step-log-item">
                          <span className="log-bullet">•</span>
                          <span className="log-step-num">Step {s.step_number}:</span>
                          <span className="log-message">{s.message}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </section>
  )
}
