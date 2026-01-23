import { useState } from 'react';
import { Target, Loader2, AlertCircle, Wifi, Play, Terminal, Activity, ShieldAlert, Monitor, Server, Smartphone, Router, HelpCircle } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

interface Service {
    port: number;
    protocol: string;
    name: string;
    version: string;
    cves: string[];
}

interface Host {
    ip: string;
    mac: string;
    hostname: string;
    vendor: string;
    os_family: string;
    device_type: string;
    open_ports: number[];
    services: Service[];
    risk_score: number;
}

interface ScanResponse {
    target: string;
    status: string;
    hosts: Host[];
}

export default function Scanner() {
    const [target, setTarget] = useState('192.168.1.0/24');
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState<ScanResponse | null>(null);

    const handleScan = async (useAuto = false) => {
        setLoading(true);
        setResult(null);

        const payloadTarget = useAuto ? "auto" : target;

        try {
            const res = await fetch('http://localhost:8000/api/v1/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    target: payloadTarget,
                    start_port: 1,
                    end_port: 1000
                })
            });
            const data = await res.json();
            setResult(data);
            if (useAuto && data.target) setTarget(data.target);
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const getOsIcon = (os: string) => {
        if (os.includes("Windows")) return <Monitor className="text-blue-400" />;
        if (os.includes("Linux")) return <Terminal className="text-orange-400" />;
        if (os.includes("Apple") || os.includes("macOS") || os.includes("iOS")) return <Smartphone className="text-slate-200" />; // Apple icon not in Lucide, using generic
        return <HelpCircle className="text-slate-600" />;
    };

    const getDeviceIcon = (type: string) => {
        if (type.includes("Server")) return <Server className="text-purple-400" />;
        if (type.includes("Router")) return <Router className="text-emerald-400" />;
        if (type.includes("Mobile")) return <Smartphone className="text-pink-400" />;
        return <Monitor className="text-slate-400" />;
    };

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
            className="max-w-7xl mx-auto space-y-8"
        >
            <header className="flex justify-between items-end">
                <div>
                    <h2 className="text-3xl font-bold flex items-center gap-3 mb-2 text-white">
                        <Activity className="text-aegis-500" />
                        Next-Gen Asset Discovery
                    </h2>
                    <p className="text-slate-400">Autonomous reconnaissance engine with OS fingerprinting and Vulnerability Assessment.</p>
                </div>
            </header>

            {/* Control Panel */}
            <div className="glass-panel p-8 rounded-2xl relative overflow-hidden">
                <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-aegis-500 via-aegis-accent to-aegis-500 opacity-50" />

                <div className="flex gap-6 items-end relative z-10 w-full">
                    <div className="flex-1 space-y-3">
                        <label className="text-xs font-bold text-aegis-400 uppercase tracking-widest flex items-center gap-2">
                            <Terminal size={14} /> Target Scope (CIDR)
                        </label>
                        <div className="relative group">
                            <input
                                type="text"
                                value={target}
                                onChange={(e) => setTarget(e.target.value)}
                                className="w-full bg-slate-900/50 border border-white/10 rounded-xl px-5 py-4 focus:outline-none focus:border-aegis-500 focus:bg-slate-900/80 transition-all font-mono text-lg text-white placeholder-slate-600 group-hover:border-white/20"
                                placeholder="Enter CIDR (192.168.1.0/24)"
                            />
                        </div>
                    </div>

                    <button onClick={() => handleScan(false)} disabled={loading} className="h-[60px] bg-white/5 border border-white/10 hover:bg-white/10 text-white font-bold px-8 rounded-xl flex items-center gap-3 transition-all disabled:opacity-50">
                        {loading ? <Loader2 className="animate-spin" /> : <Play size={18} />} MANUAL
                    </button>

                    <button onClick={() => handleScan(true)} disabled={loading} className="h-[60px] bg-gradient-to-b from-aegis-500 to-aegis-600 hover:from-aegis-400 hover:to-aegis-500 text-white font-bold px-8 rounded-xl flex items-center gap-3 transition-all disabled:opacity-50 shadow-lg shadow-aegis-500/20 active:scale-95">
                        {loading ? <Loader2 className="animate-spin" /> : <Wifi strokeWidth={3} />} AUTO DISCOVERY
                    </button>
                </div>
            </div>

            {/* Loading */}
            <AnimatePresence>
                {loading && (
                    <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} className="overflow-hidden">
                        <div className="glass-card p-6 rounded-xl border-l-4 border-aegis-500 flex items-center gap-6">
                            <Loader2 className="animate-spin text-aegis-400" size={32} />
                            <div className="font-mono text-sm space-y-1">
                                <div className="text-aegis-400">&gt;&gt; ORCHESTRATING_SCANNERS [ARP, TCP, ICMP]...</div>
                                <div className="text-white">&gt;&gt; FINGERPRINTING_OS_STACKS (TTL HEURISTICS)...</div>
                                <div className="text-slate-400">&gt;&gt; CORRELATING_CVES_AGAINST_NVD...</div>
                            </div>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>

            {/* Results */}
            {result && !loading && (
                <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6">
                    <div className="flex justify-between items-center text-white mb-4">
                        <h3 className="text-xl font-bold flex gap-2"><Monitor /> Network Topology</h3>
                        <span className="bg-aegis-500/20 text-aegis-400 px-3 py-1 rounded-full text-sm font-mono">{result.hosts.length} Assets Identified</span>
                    </div>

                    <div className="grid grid-cols-1 gap-4">
                        {result.hosts.map(host => (
                            <div key={host.ip} className="glass-panel p-6 rounded-xl border border-white/5 hover:border-aegis-500/30 transition-all group">
                                <div className="flex flex-col md:flex-row justify-between gap-6">
                                    {/* Asset Info */}
                                    <div className="flex items-start gap-4">
                                        <div className="p-3 bg-white/5 rounded-lg border border-white/10 group-hover:bg-aegis-500/10 transition-colors">
                                            {getDeviceIcon(host.device_type)}
                                        </div>
                                        <div>
                                            <div className="flex items-center gap-3 mb-1">
                                                <h4 className="text-lg font-bold text-white">{host.ip}</h4>
                                                {host.hostname && <span className="text-xs text-slate-400 bg-black/20 px-2 py-0.5 rounded">{host.hostname}</span>}
                                            </div>
                                            <div className="text-sm text-slate-400 font-mono mb-2">{host.mac} • {host.vendor}</div>
                                            <div className="flex gap-2">
                                                <span className="flex items-center gap-1.5 text-xs bg-white/5 px-2 py-1 rounded text-slate-300 border border-white/5">
                                                    {getOsIcon(host.os_family)} {host.os_family}
                                                </span>
                                                <span className="text-xs bg-white/5 px-2 py-1 rounded text-slate-300 border border-white/5">
                                                    Type: {host.device_type}
                                                </span>
                                            </div>
                                        </div>
                                    </div>

                                    {/* Risk & Ports */}
                                    <div className="flex flex-col items-end gap-3 min-w-[200px]">
                                        <div className="flex items-center gap-3">
                                            <div className="text-right">
                                                <div className="text-xs text-slate-500 uppercase font-bold tracking-wider">Risk Score</div>
                                                <div className={`text-xl font-bold ${host.risk_score > 50 ? 'text-red-500' : host.risk_score > 20 ? 'text-yellow-400' : 'text-emerald-400'}`}>
                                                    {host.risk_score}/100
                                                </div>
                                            </div>
                                            {host.risk_score > 50 && <ShieldAlert className="text-red-500 animate-pulse" size={28} />}
                                        </div>

                                        <div className="flex flex-wrap justify-end gap-1 max-w-[300px]">
                                            {host.open_ports.map(p => (
                                                <span key={p} className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${p === 445 || p === 3389 ? 'bg-red-500/20 text-red-300 border-red-500/30' : 'bg-aegis-500/10 text-aegis-300 border-aegis-500/20'} border`}>
                                                    {p}
                                                </span>
                                            ))}
                                            {host.open_ports.length === 0 && <span className="text-xs text-slate-600 italic">No open ports</span>}
                                        </div>
                                    </div>
                                </div>

                                {/* Vulnerabilities (if any) */}
                                {host.services.some(s => s.cves.length > 0) && (
                                    <div className="mt-4 pt-4 border-t border-white/5">
                                        <h5 className="text-xs font-bold text-red-400 uppercase tracking-widest mb-2 flex items-center gap-2"><AlertCircle size={12} /> Critical Vulnerabilities Detected</h5>
                                        <div className="space-y-1">
                                            {host.services.map(s => s.cves.map(cveString => {
                                                const [cveId, cveUrl] = cveString.split('|');
                                                return (
                                                    <div key={cveId} className="flex justify-between items-center text-sm text-slate-300 font-mono bg-red-500/5 px-2 py-1 rounded hover:bg-red-500/10 transition-colors">
                                                        <a href={cveUrl} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 text-red-300 hover:text-red-200 hover:underline">
                                                            <ShieldAlert size={12} />
                                                            {cveId}
                                                        </a>
                                                        <span className="text-slate-500 text-xs">Port {s.port}</span>
                                                    </div>
                                                );
                                            }))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        ))}
                    </div>
                </motion.div>
            )}
        </motion.div>
    );
}
