import { useState, useEffect } from 'react';
import { Search, Terminal, Download, Pause, Play } from 'lucide-react';
import { clsx } from 'clsx';
import { motion } from 'framer-motion';

export default function Logs() {
    const [isLive, setIsLive] = useState(true);

    const [logs, setLogs] = useState<any[]>([]);

    const fetchLogs = async () => {
        try {
            const res = await fetch('http://localhost:8000/api/v1/logs');
            const data = await res.json();
            setLogs(data);
        } catch (e) {
            console.error(e);
        }
    };

    // Poll logs every 2 seconds
    useEffect(() => {
        fetchLogs();
        if (isLive) {
            const interval = setInterval(fetchLogs, 2000);
            return () => clearInterval(interval);
        }
    }, [isLive]);

    return (
        <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="h-[calc(100vh-8rem)] flex flex-col space-y-6 max-w-7xl mx-auto"
        >
            <header className="flex justify-between items-end">
                <div>
                    <h2 className="text-3xl font-bold text-white mb-2 flex items-center gap-3">
                        <Terminal className="text-aegis-500" />
                        Event Stream
                    </h2>
                    <p className="text-slate-400">Real-time security telemetry and system logs.</p>
                </div>
                <div className="flex gap-3">
                    <button
                        onClick={() => setIsLive(!isLive)}
                        className={clsx(
                            "px-4 py-2 rounded-lg font-bold text-xs tracking-wider flex items-center gap-2 border transition-all",
                            isLive
                                ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20 hover:bg-emerald-500/20"
                                : "bg-warning-500/10 text-warning-400 border-warning-500/20 hover:bg-warning-500/20"
                        )}
                    >
                        {isLive ? <><Pause size={14} /> LIVE STREAM ACTIVE</> : <><Play size={14} /> STREAM PAUSED</>}
                    </button>
                    <button className="btn-glass flex items-center gap-2 px-4 py-2 rounded-lg text-sm text-slate-300 hover:text-white border border-white/10 hover:bg-white/5 transition-colors">
                        <Download size={16} /> Export
                    </button>
                </div>
            </header>

            {/* Log Console Container */}
            <div className="flex-1 glass-panel rounded-xl overflow-hidden flex flex-col shadow-2xl relative">
                {/* Live Indicator Line */}
                {isLive && <div className="absolute top-0 left-0 w-full h-[2px] bg-gradient-to-r from-transparent via-aegis-500 to-transparent z-20 animate-pulse" />}

                {/* Toolbar */}
                <div className="bg-surface/50 backdrop-blur-md px-4 py-3 border-b border-white/5 flex items-center gap-4 z-10">
                    <div className="relative flex-1 group">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 group-focus-within:text-aegis-400 transition-colors" size={18} />
                        <input
                            type="text"
                            placeholder="Search logs (regex supported)..."
                            className="w-full bg-black/20 border border-white/5 rounded-lg pl-10 pr-4 py-2 focus:outline-none focus:border-aegis-500/50 focus:bg-black/40 transition-all font-mono text-sm text-slate-200 placeholder-slate-600"
                        />
                    </div>
                    <div className="h-6 w-px bg-white/10" />
                    <div className="flex gap-2">
                        <button className="bg-red-500/10 border border-red-500/20 text-red-400 px-2 py-1 rounded text-[10px] font-bold hover:brightness-110 transition-all">
                            ERROR (12)
                        </button>
                        <button className="bg-yellow-500/10 border border-yellow-500/20 text-yellow-400 px-2 py-1 rounded text-[10px] font-bold hover:brightness-110 transition-all">
                            WARN (5)
                        </button>
                    </div>
                </div>

                {/* Table */}
                <div className="flex-1 overflow-auto custom-scrollbar bg-black/20">
                    <table className="w-full text-left font-mono text-xs sm:text-sm">
                        <thead className="bg-surface/80 text-slate-500 sticky top-0 z-10 backdrop-blur-sm shadow-sm">
                            <tr>
                                <th className="px-6 py-3 w-48 font-semibold tracking-wider">Timestamp</th>
                                <th className="px-6 py-3 w-32 font-semibold tracking-wider">Level</th>
                                <th className="px-6 py-3 w-48 font-semibold tracking-wider">Source</th>
                                <th className="px-6 py-3 font-semibold tracking-wider">Message</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-white/5">
                            {/* Real Data Rows */}
                            {logs.map((log: any) => (
                                <LogKeyRow key={log.id} log={log} />
                            ))}
                        </tbody>
                    </table>
                </div>

                {/* Footer Status */}
                <div className="bg-surface/50 border-t border-white/5 px-4 py-2 text-[10px] font-mono text-slate-500 flex justify-between uppercase tracking-wider">
                    <span>Buffer Usage: 12%</span>
                    <span>Connected to Sentinel-Core</span>
                </div>
            </div>
        </motion.div>
    );
}

function LogKeyRow({ log }: { log: any }) {
    const isError = log.level === 'ERROR';
    const isWarn = log.level === 'WARN' && !isError;

    return (
        <tr className="hover:bg-white/5 transition-colors group cursor-default">
            <td className="px-6 py-2.5 text-slate-500 whitespace-nowrap opacity-70 group-hover:opacity-100">
                <span className="text-aegis-600 mr-2">➜</span>
                {new Date(log.event_time).toLocaleString()}
            </td>
            <td className="px-6 py-2.5">
                <span className={clsx(
                    "inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold tracking-wider",
                    isError ? "bg-red-500/10 text-red-500 border border-red-500/20 shadow-[0_0_10px_rgba(239,68,68,0.1)]" :
                        isWarn ? "bg-yellow-500/10 text-yellow-500 border border-yellow-500/20" :
                            "bg-blue-500/10 text-blue-400 border border-blue-500/20"
                )}>
                    {log.level}
                </span>
            </td>
            <td className="px-6 py-2.5 text-aegis-300/80 font-semibold">{log.source}</td>
            <td className={clsx(
                "px-6 py-2.5 truncate max-w-2xl",
                isError ? "text-red-300" : isWarn ? "text-yellow-100" : "text-slate-400",
                "group-hover:text-white transition-colors"
            )}>
                {log.message}
            </td>
        </tr>
    )
}


