import React, { useCallback, useEffect, useRef, useState } from 'react'
import Header from './components/Header'
import DecisionCards from './components/DecisionCards'
import HumanApproval from './components/HumanApproval'
import ActionLab from './components/ActionLab'
import IntentAnalysis from './components/IntentAnalysis'
import WorkflowCrashTestLab from './components/WorkflowCrashTestLab'
import AuditTable from './components/AuditTable'
import { apiUrl } from './config/api'
import './App.css'


export default function App() {
  const [backendStatus, setBackendStatus] = useState('checking')
  const [checkingHealth, setCheckingHealth] = useState(false)

  // Audit records state
  const [auditRecords, setAuditRecords] = useState([])
  const [auditLoading, setAuditLoading] = useState(false)
  const [auditError, setAuditError] = useState(null)
  const [auditLimit, setAuditLimit] = useState(50)
  const [lastUpdated, setLastUpdated] = useState(null)

  // Human approval queue state
  const [approvalRequests, setApprovalRequests] = useState([])
  const [approvalLoading, setApprovalLoading] = useState(false)
  const [approvalError, setApprovalError] = useState(null)
  const [pendingCount, setPendingCount] = useState(0)

  // Ref to prevent duplicate in-flight requests from rapid repeated clicks
  const isFetchingAuditRef = useRef(false)
  const isFetchingApprovalRef = useRef(false)

  // 1. Check Backend Health
  const checkHealth = useCallback(async () => {
    setCheckingHealth(true)
    try {
      const response = await fetch(apiUrl(`/health?_t=${Date.now()}`), {
        method: 'GET',
        cache: 'no-store',
        headers: { 'Cache-Control': 'no-cache', Pragma: 'no-cache' },
      })
      if (!response.ok) {
        throw new Error(`Health check returned status ${response.status}`)
      }
      const data = await response.json()
      if (data && data.status === 'ok') {
        setBackendStatus('connected')
      } else {
        setBackendStatus('disconnected')
      }
    } catch {
      setBackendStatus('disconnected')
    } finally {
      setCheckingHealth(false)
    }
  }, [])

  // 2. Fetch Recent Audit Logs with cache-busting and duplicate prevention
  const fetchAuditLogs = useCallback(async (limit = auditLimit) => {
    if (isFetchingAuditRef.current) return
    isFetchingAuditRef.current = true

    setAuditLoading(true)
    setAuditError(null)

    const startTime = Date.now()

    try {
      const response = await fetch(apiUrl(`/audit?limit=${limit}&_t=${Date.now()}`), {
        method: 'GET',
        cache: 'no-store',
        headers: {
          'Cache-Control': 'no-cache',
          Pragma: 'no-cache',
        },
      })

      const contentType = response.headers.get('content-type') || ''
      if (!contentType.includes('application/json')) {
        throw new Error(
          !response.ok
            ? `Audit fetch failed with status ${response.status}`
            : 'Server returned non-JSON response format.'
        )
      }

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}))
        throw new Error(errorData.detail || `Audit fetch failed with status ${response.status}`)
      }

      const data = await response.json()
      const newRecords = Array.isArray(data.records) ? data.records : []

      const elapsed = Date.now() - startTime
      if (elapsed < 250) {
        await new Promise((resolve) => setTimeout(resolve, 250 - elapsed))
      }

      setAuditRecords(newRecords)
      setLastUpdated(new Date())
    } catch (err) {
      setAuditError(err.message || 'Failed to retrieve audit records.')
    } finally {
      setAuditLoading(false)
      isFetchingAuditRef.current = false
    }
  }, [auditLimit])

  // 3. Fetch Approval Requests Queue
  const fetchApprovals = useCallback(async () => {
    if (isFetchingApprovalRef.current) return
    isFetchingApprovalRef.current = true

    setApprovalLoading(true)
    setApprovalError(null)

    try {
      const response = await fetch(apiUrl(`/approvals?_t=${Date.now()}`), {
        method: 'GET',
        cache: 'no-store',
        headers: {
          'Cache-Control': 'no-cache',
          Pragma: 'no-cache',
        },
      })

      const contentType = response.headers.get('content-type') || ''
      if (!contentType.includes('application/json')) {
        throw new Error(
          !response.ok
            ? `Failed to fetch approvals: server returned status ${response.status}`
            : 'Server returned non-JSON response format.'
        )
      }

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}))
        throw new Error(
          errorData.detail || `Failed to fetch approvals: status ${response.status}`
        )
      }

      const data = await response.json()
      setApprovalRequests(Array.isArray(data.requests) ? data.requests : [])
      setPendingCount(typeof data.pending_count === 'number' ? data.pending_count : 0)
    } catch (err) {
      setApprovalError(err.message || 'Failed to retrieve approval queue.')
    } finally {
      setApprovalLoading(false)
      isFetchingApprovalRef.current = false
    }
  }, [])

  // Initial load
  useEffect(() => {
    checkHealth()
    fetchAuditLogs(50)
    fetchApprovals()
  }, [checkHealth, fetchAuditLogs, fetchApprovals])

  // Refresh callback triggered by ActionLab
  const handleActionActivity = () => {
    fetchAuditLogs(auditLimit)
    fetchApprovals()
  }

  // Refresh callback triggered after an approval or rejection
  const handleApprovalResolved = () => {
    fetchApprovals()
    fetchAuditLogs(auditLimit)
  }

  const handleLimitChange = (newLimit) => {
    setAuditLimit(newLimit)
    fetchAuditLogs(newLimit)
  }

  return (
    <div className="dashboard-app">
      <Header
        backendStatus={backendStatus}
        checkingHealth={checkingHealth}
        onCheckHealth={checkHealth}
      />

      <main className="dashboard-content">
        {/* Intro banner */}
        <section className="dashboard-intro">
          <div className="intro-text">
            <h1 className="intro-title">ActionShield AI Security Operations</h1>
            <p className="intro-desc">
              Real-time policy interception and controlled execution sandbox. Every action proposed by an autonomous AI agent is verified against deterministic security policies before execution.
            </p>
          </div>
        </section>

        {/* 1. Summary Cards (ALLOW, REVIEW, BLOCK) */}
        <DecisionCards
          auditRecords={auditRecords}
          loading={auditLoading}
        />

        {/* 2. Human Approval Workflow Queue */}
        <HumanApproval
          requests={approvalRequests}
          loading={approvalLoading}
          error={approvalError}
          pendingCount={pendingCount}
          onRefresh={fetchApprovals}
          onApprovalResolved={handleApprovalResolved}
        />

        {/* 3. Action Testing Lab */}
        <ActionLab
          onActionEvaluated={handleActionActivity}
          onActionExecuted={handleActionActivity}
        />

        {/* 4. AI-Assisted Intent Analysis */}
        <IntentAnalysis />

        {/* 5. Workflow Crash-Test Lab */}
        <WorkflowCrashTestLab />

        {/* 6. Recent Audit Activity Table */}
        <AuditTable
          records={auditRecords}
          loading={auditLoading}
          error={auditError}
          limit={auditLimit}
          lastUpdated={lastUpdated}
          onLimitChange={handleLimitChange}
          onRefresh={() => fetchAuditLogs(auditLimit)}
        />
      </main>

      <footer className="footer">
        <div>
          ActionShield AI &bull; AI-Agent Safety &amp; Audit Layer
        </div>
        <div className="footer-sub">
          FastAPI &bull; React + Vite &bull; SQLite &bull; Policy Rules &bull; Human Approvals &bull; Crash-Test Lab &bull; Intent Analysis
        </div>
      </footer>

    </div>
  )
}
