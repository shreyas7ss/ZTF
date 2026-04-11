import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Activity, 
  Terminal, 
  Lock, 
  AlertTriangle, 
  Settings, 
  RefreshCw,
  Search,
  FileText,
  UserX
} from 'lucide-react';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  Cell
} from 'recharts';

// --- Mock Telemetry for Chart (Initial State) ---
const INITIAL_CHART_DATA = [
  { name: 'Sess-1', score: 0.1 },
  { name: 'Sess-2', score: 0.2 },
  { name: 'Sess-3', score: 0.15 },
  { name: 'Sess-4', score: 0.25 },
  { name: 'Current', score: 0.0 },
];

function App() {
  const [alert, setAlert] = useState("Suspicious CAN bus activity detected on IP 192.168.1.45");
  const [scenario, setScenario] = useState("normal"); // normal, malicious_policy, malicious_behavior
  const [loading, setLoading] = useState(false);
  const [sessionId, setSessionId] = useState(null);
  const [status, setStatus] = useState(null);
  const [dashboardStats, setDashboardStats] = useState({
    total_investigations: 0,
    active_lockdowns: 0,
    quarantined_agents: 0
  });

  // Polling for dashboard stats
  useEffect(() => {
    const fetchStats = async () => {
      try {
        const res = await fetch('http://localhost:8000/api/dashboard/stats');
        const data = await res.json();
        setDashboardStats(data);
      } catch (err) {
        console.error("Failed to fetch stats", err);
      }
    };
    fetchStats();
    const interval = setInterval(fetchStats, 5000);
    return () => clearInterval(interval);
  }, []);

  // Polling for active session status
  useEffect(() => {
    if (!sessionId || (status && status.status === "COMPLETED")) return;

    const checkStatus = async () => {
      try {
        const res = await fetch(`http://localhost:8000/api/status/${sessionId}`);
        const data = await res.json();
        setStatus(data);
        if (data.status === "COMPLETED") {
          // Trigger a stats refresh when done
          fetch('http://localhost:8000/api/dashboard/stats').then(r => r.json()).then(setDashboardStats);
        }
      } catch (err) {
        console.error("Status check failed", err);
      }
    };

    const interval = setInterval(checkStatus, 1500);
    return () => clearInterval(interval);
  }, [sessionId, status]);

  const handleStart = async () => {
    setLoading(true);
    setStatus(null);
    try {
      const res = await fetch('http://localhost:8000/api/investigate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ alert, scenario })
      });
      const data = await res.json();
      setSessionId(data.session_id);
    } catch (err) {
      alert("Backend not reachable. Ensure api_server.py is running.");
    } finally {
      setLoading(false);
    }
  };

  const handleReset = async () => {
    await fetch('http://localhost:8000/api/system/reset', { method: 'POST' });
    setSessionId(null);
    setStatus(null);
    setDashboardStats({ total_investigations: 0, active_lockdowns: 0, quarantined_agents: 0 });
  };

  return (
    <div className="min-h-screen">
      {/* Header */}
      <header className="p-6 border-b border-white/10 flex justify-between items-center glass m-4 mt-2">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-primary/20 rounded-lg">
            <Shield className="text-primary" size={28} />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight">ZT-SOC COMMAND CENTER</h1>
            <p className="text-xs text-text-muted">Zero-Trust Non-Human Identity Framework — DS308</p>
          </div>
        </div>
        <div className="flex gap-4">
          <button onClick={handleReset} className="btn bg-white/5 hover:bg-white/10 text-sm flex items-center gap-2">
            <RefreshCw size={16} /> Reset System
          </button>
          <div className="flex items-center gap-4 text-sm px-4 py-2 border border-white/10 rounded-lg bg-black/20">
            <span className="flex items-center gap-2"><Activity size={14} className="text-success" /> Active Monitors</span>
            <span className="text-primary font-mono">{dashboardStats.total_investigations} Sessions</span>
          </div>
        </div>
      </header>

      {/* Main Dashboard */}
      <main className="dashboard-grid">
        {/* Left Column: Mission Control */}
        <div className="flex flex-col gap-6">
          
          {/* Stats Row */}
          <div className="grid grid-cols-3 gap-4">
            <div className="glass p-4 text-center">
              <p className="text-text-muted text-xs uppercase mb-1">Total Investigation</p>
              <p className="text-2xl font-bold">{dashboardStats.total_investigations}</p>
            </div>
            <div className="glass p-4 text-center border-danger/20">
              <p className="text-text-muted text-xs uppercase mb-1 text-danger">Active Blocked</p>
              <p className="text-2xl font-bold text-danger">{dashboardStats.active_lockdowns}</p>
            </div>
            <div className="glass p-4 text-center border-warning/20">
              <p className="text-text-muted text-xs uppercase mb-1 text-warning">Quarantined</p>
              <p className="text-2xl font-bold text-warning">{dashboardStats.quarantined_agents}</p>
            </div>
          </div>

          {/* Alert Input Area */}
          <section className="glass p-6 flex flex-col gap-4">
            <div className="flex items-center gap-2 text-text-muted text-sm font-semibold uppercase">
              <Terminal size={16} /> New Investigation Case
            </div>
            <textarea 
              value={alert}
              onChange={(e) => setAlert(e.target.value)}
              className="w-full bg-black/40 border border-white/10 rounded-lg p-4 font-mono text-sm text-primary h-24 focus:outline-none focus:border-primary/50"
              placeholder="Enter security alert string..."
            />
            
            <div className="flex flex-col gap-2">
              <label className="text-xs text-text-muted uppercase font-bold">Investigation Scenario</label>
              <div className="grid grid-cols-3 gap-2">
                <button 
                  onClick={() => setScenario("normal")}
                  className={`btn text-xs ${scenario === "normal" ? 'btn-primary' : 'bg-white/5 border border-white/10'}`}
                >
                  NORMAL (LEGIT)
                </button>
                <button 
                  onClick={() => setScenario("malicious_policy")}
                  className={`btn text-xs ${scenario === "malicious_policy" ? 'bg-danger text-white' : 'bg-white/5 border border-white/10'}`}
                >
                  GATE 3 VIOLATION
                </button>
                <button 
                  onClick={() => setScenario("malicious_behavior")}
                  className={`btn text-xs ${scenario === "malicious_behavior" ? 'bg-danger text-white' : 'bg-white/5 border border-white/10'}`}
                >
                  GATE 4 ANOMALY
                </button>
              </div>
            </div>

            <button 
              onClick={handleStart}
              disabled={loading || (status && status.status === "RUNNING")}
              className="btn btn-primary w-full mt-2 py-4 text-lg flex justify-center items-center gap-2"
            >
              {loading ? <RefreshCw className="animate-spin" /> : <Search size={20} />} 
              LAUNCH AUTOMATED INVESTIGATION
            </button>
          </section>

          {/* Workflow Status */}
          <section className="glass p-6 flex-1">
            <div className="flex justify-between items-center mb-6">
              <div className="flex items-center gap-2 text-text-muted text-sm font-semibold uppercase">
                <Activity size={16} /> Investigation Workflow
              </div>
              <div className="badge badge-success">Phase 4 Active</div>
            </div>

            {!status ? (
              <div className="flex flex-col items-center justify-center h-64 text-text-muted gap-4">
                <Lock size={48} className="opacity-10" />
                <p>System idle. Waiting for alert input...</p>
              </div>
            ) : (
              <div className="flex flex-col gap-4">
                {/* Gate Progress Simulation (In a real app, these would come from status) */}
                <GateInstance name="Gate 1: JWT Cryptographic ID" status={status.status === "FAILED" ? "FAILED" : "SUCCESS"} />
                <GateInstance name="Gate 2: Redis Real-time Revocation" status={status.status === "FAILED" ? "FAILED" : "SUCCESS"} />
                <GateInstance 
                   name="Gate 3: OPA Centralized Policy" 
                   status={status.scenario === "malicious_policy" ? "FAILED" : "SUCCESS"} 
                />
                <GateInstance 
                  name="Gate 4: ML Behavioral Supervisor" 
                  status={status.scenario === "malicious_behavior" ? "FAILED" : "SUCCESS"} 
                />

                <div className="mt-6 p-4 bg-black/40 rounded border border-white/5 font-mono text-xs">
                   <p className="text-text-muted mb-2">// SESSION CONTEXT</p>
                   <p><span className="text-primary">SESSION_ID:</span> {status.id}</p>
                   <p><span className="text-primary">RESULT:</span> {status.final_status || "ANALYZING..."}</p>
                </div>
              </div>
            )}
          </section>
        </div>

        {/* Right Column: Analytics */}
        <div className="flex flex-col gap-6">
          <section className="glass p-6">
            <div className="flex items-center gap-2 text-text-muted text-sm font-semibold uppercase mb-6">
              <Activity size={16} /> ML behavioral analytics
            </div>
            
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={INITIAL_CHART_DATA}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                  <XAxis dataKey="name" stroke="#64748b" fontSize={10} />
                  <YAxis stroke="#64748b" fontSize={10} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#1e293b', border: 'none', borderRadius: '8px', fontSize: '12px' }}
                  />
                  <Bar dataKey="score" radius={[4, 4, 0, 0]}>
                    {INITIAL_CHART_DATA.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.score > 0.5 ? '#ef4444' : '#6366f1'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
            <p className="text-[10px] text-text-muted mt-4 uppercase tracking-widest text-center">
              Anomalous behavior trigger threshold: 0.55
            </p>
          </section>

          <section className="glass p-6 flex-1">
             <div className="flex items-center gap-2 text-text-muted text-sm font-semibold uppercase mb-4">
              <UserX size={16} /> Quarantine History
            </div>
            <div className="flex flex-col gap-3">
              <div className="p-3 border-l-2 border-danger bg-danger/5 rounded-r">
                <p className="text-xs font-bold text-danger">LOCKDOWN-4922</p>
                <p className="text-[10px] text-text-muted">Agent agent-666 blocked in Gate 3 (OPA)</p>
              </div>
              <div className="p-3 border-l-2 border-warning bg-warning/5 rounded-r">
                <p className="text-xs font-bold text-warning">ANOMALY-8812</p>
                <p className="text-[10px] text-text-muted">High-frequency read_logs detected (ML)</p>
              </div>
            </div>
          </section>
        </div>
      </main>
    </div>
  );
}

function GateInstance({ name, status }) {
  const getStatusColor = () => {
    if (status === "SUCCESS") return "status-pass";
    if (status === "FAILED") return "status-fail";
    if (status === "PENDING") return "status-pending";
    return "status-inactive";
  };

  return (
    <div className="flex items-center justify-between p-3 bg-white/5 rounded-lg border border-white/5">
      <div className="flex items-center gap-3">
        <div className={`status-indicator ${getStatusColor()}`} />
        <span className="text-sm font-medium">{name}</span>
      </div>
      {status === "SUCCESS" ? (
        <span className="text-[10px] font-bold text-success uppercase">Verified</span>
      ) : status === "FAILED" ? (
        <span className="text-[10px] font-bold text-danger uppercase">Blocked</span>
      ) : null}
    </div>
  );
}

export default App;
