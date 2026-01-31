import { useEffect, useState } from 'react';
import { Activity, ArrowRight, Globe, Shield, Wifi, FileText, AlertTriangle, Zap, Database, MessageSquare, Monitor, Film, Gamepad2, Mail, Server, Phone, Search, X } from 'lucide-react';

interface TrafficFlow {
    src_ip: string;
    dst_ip: string;
    src_port: number;
    dst_port: number;
    protocol: string;
    service: string;
    application?: string;
    sni?: string;
    dns_query?: string;
    http_host?: string;
    resolved_domain?: string;
    bytes: number;
    packet_count: number;
    last_seen: number;
    category: string;
    insight: string;
}

interface DeviceTraffic {
    ip: string;
    total_bytes: number;
    total_packets: number;
    protocols: Record<string, number>;
    top_services: Record<string, number>;
    top_destinations: Record<string, number>;
}

interface TrafficResponse {
    flows: TrafficFlow[];
    device_stats: DeviceTraffic[];
}

const getCategoryIcon = (category: string) => {
    switch (category) {
        case 'Media': return <Film className="text-purple-400" size={14} />;
        case 'Social': return <MessageSquare className="text-blue-400" size={14} />;
        case 'Gaming': return <Gamepad2 className="text-green-400" size={14} />;
        case 'Web': return <Globe className="text-cyan-400" size={14} />;
        case 'System': case 'System/Cloud': return <Server className="text-gray-400" size={14} />;
        case 'Remote Access': return <Monitor className="text-red-400" size={14} />;
        case 'Email': return <Mail className="text-yellow-400" size={14} />;
        case 'Database': return <Database className="text-orange-400" size={14} />;
        case 'VoIP': case 'Communication': return <Phone className="text-pink-400" size={14} />;
        default: return <Zap className="text-slate-400" size={14} />;
    }
};

const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
};

export default function TrafficDashboard() {
    const [data, setData] = useState<TrafficResponse | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [filter, setFilter] = useState('');

    useEffect(() => {
        const fetchTraffic = async () => {
            try {
                const res = await fetch('http://localhost:8000/api/v1/traffic');
                if (!res.ok) throw new Error('Backend not reachable');
                const json = await res.json();
                setData(json);
                setError(null);
            } catch (e) {
                setError("Backend offline or not running as Admin.");
            }
        };

        fetchTraffic();
        const interval = setInterval(fetchTraffic, 1000);
        return () => clearInterval(interval);
    }, []);

    if (error) return (
        <div className="glass-panel p-6 rounded-xl border-l-4 border-red-500 flex items-center gap-4">
            <AlertTriangle className="text-red-400" size={24} />
            <div>
                <div className="text-white font-bold">Traffic Probe Offline</div>
                <div className="text-slate-400 text-sm">{error}</div>
            </div>
        </div>
    );

    if (!data) return <div className="text-slate-400 animate-pulse flex items-center gap-2"><Wifi className="animate-bounce" /> Initializing Traffic Probe...</div>;

    // Filter Logic - searches EVERYTHING
    const filterLower = filter.toLowerCase();
    const filteredFlows = data.flows.filter(f => {
        if (!filter) return true;
        // Stringify all fields and search
        const searchable = [
            f.src_ip,
            f.dst_ip,
            String(f.src_port),
            String(f.dst_port),
            f.protocol,
            f.service,
            f.application || '',
            f.sni || '',
            f.dns_query || '',
            f.http_host || '',
            f.resolved_domain || '',
            f.category,
            f.insight
        ].join(' ').toLowerCase();
        return searchable.includes(filterLower);
    });

    const sortedFlows = [...filteredFlows].sort((a, b) => b.last_seen - a.last_seen).slice(0, 50);
    const categoryStats: Record<string, number> = {};
    filteredFlows.forEach(f => { categoryStats[f.category] = (categoryStats[f.category] || 0) + f.bytes; });

    return (
        <div className="space-y-6">
            {/* Filter Bar */}
            <div className="glass-panel p-4 rounded-xl border border-white/5">
                <div className="flex items-center gap-3">
                    <Search className="text-slate-400" size={18} />
                    <input
                        type="text"
                        value={filter}
                        onChange={(e) => setFilter(e.target.value)}
                        placeholder="Filter by IP, domain, app (e.g. 192.168.1.50, youtube, pornhub...)"
                        className="flex-1 bg-transparent border-none outline-none text-white placeholder-slate-500 text-sm"
                    />
                    {filter && (
                        <button onClick={() => setFilter('')} className="text-slate-400 hover:text-white transition-colors">
                            <X size={16} />
                        </button>
                    )}
                    <span className="text-xs text-slate-500">{filteredFlows.length} / {data.flows.length} flows</span>
                </div>
            </div>

            {/* Summary Cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="glass-panel p-4 rounded-xl border border-white/5">
                    <div className="text-xs text-slate-500 uppercase font-bold">Active Flows</div>
                    <div className="text-2xl font-bold text-white">{data.flows.length}</div>
                </div>
                <div className="glass-panel p-4 rounded-xl border border-white/5">
                    <div className="text-xs text-slate-500 uppercase font-bold">Active Devices</div>
                    <div className="text-2xl font-bold text-aegis-400">{data.device_stats.length}</div>
                </div>
                <div className="glass-panel p-4 rounded-xl border border-white/5">
                    <div className="text-xs text-slate-500 uppercase font-bold">Total Traffic</div>
                    <div className="text-2xl font-bold text-emerald-400">{formatBytes(data.device_stats.reduce((a, d) => a + d.total_bytes, 0))}</div>
                </div>
                <div className="glass-panel p-4 rounded-xl border border-white/5">
                    <div className="text-xs text-slate-500 uppercase font-bold">Total Packets</div>
                    <div className="text-2xl font-bold text-purple-400">{data.device_stats.reduce((a, d) => a + d.total_packets, 0).toLocaleString()}</div>
                </div>
            </div>

            {/* Category Breakdown */}
            <div className="glass-panel p-4 rounded-xl border border-white/5">
                <h4 className="text-sm font-bold text-white mb-3 flex items-center gap-2"><FileText size={14} /> Traffic Categories</h4>
                <div className="flex flex-wrap gap-2">
                    {Object.entries(categoryStats).sort((a, b) => b[1] - a[1]).map(([cat, bytes]) => (
                        <div key={cat} className="flex items-center gap-2 bg-white/5 px-3 py-1.5 rounded-lg text-sm">
                            {getCategoryIcon(cat)}
                            <span className="text-white font-medium">{cat}</span>
                            <span className="text-slate-400">{formatBytes(bytes)}</span>
                        </div>
                    ))}
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Live Flows Panel */}
                <div className="glass-panel p-6 rounded-xl border border-white/5">
                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                        <Activity className="text-aegis-400" /> Live Network Flows
                    </h3>
                    <div className="space-y-2 max-h-[500px] overflow-y-auto pr-2">
                        {sortedFlows.length === 0 && <div className="text-slate-500 italic">No traffic detected. (Running as Admin?)</div>}
                        {sortedFlows.map((flow, idx) => (
                            <div key={idx} className="bg-white/5 p-3 rounded-lg border border-white/5 hover:border-aegis-500/30 transition-all">
                                <div className="flex justify-between items-start mb-2">
                                    <div className="flex items-center gap-2 text-xs">
                                        {getCategoryIcon(flow.category)}
                                        <span className="bg-white/10 px-2 py-0.5 rounded text-slate-300">{flow.category}</span>
                                        <span className="bg-aegis-500/20 text-aegis-300 px-2 py-0.5 rounded">{flow.service}</span>
                                        {flow.application && <span className="bg-purple-500/20 text-purple-300 px-2 py-0.5 rounded font-bold">{flow.application}</span>}
                                    </div>
                                    <div className="text-right text-xs text-slate-400">
                                        {(Date.now() / 1000 - flow.last_seen).toFixed(0)}s ago
                                    </div>
                                </div>

                                <div className="flex items-center gap-2 text-sm font-mono mb-1">
                                    <span className="text-white">{flow.src_ip}:{flow.src_port}</span>
                                    <ArrowRight size={12} className="text-slate-500" />
                                    <span className="text-slate-300">{flow.dst_ip}:{flow.dst_port}</span>
                                </div>

                                {(flow.resolved_domain || flow.sni || flow.dns_query || flow.http_host) && (
                                    <div className="text-xs text-blue-300 flex items-center gap-1 mb-1">
                                        <Globe size={10} /> {flow.resolved_domain || flow.sni || flow.dns_query || flow.http_host}
                                    </div>
                                )}

                                <div className="flex justify-between items-center text-xs mt-2 pt-2 border-t border-white/5">
                                    <span className="text-slate-400 italic">{flow.insight}</span>
                                    <div className="text-right">
                                        <span className="text-aegis-400 font-bold">{formatBytes(flow.bytes)}</span>
                                        <span className="text-slate-500 ml-2">({flow.packet_count} pkts)</span>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Top Talkers Panel */}
                <div className="glass-panel p-6 rounded-xl border border-white/5">
                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                        <Shield className="text-emerald-400" /> Top Talkers (By Volume)
                    </h3>
                    <div className="space-y-3 max-h-[500px] overflow-y-auto pr-2">
                        {data.device_stats.sort((a, b) => b.total_bytes - a.total_bytes).slice(0, 15).map(dev => {
                            const topService = Object.entries(dev.top_services).sort((a, b) => b[1] - a[1])[0];
                            const topDest = Object.entries(dev.top_destinations).sort((a, b) => b[1] - a[1])[0];

                            return (
                                <div key={dev.ip} className="bg-white/5 p-3 rounded-lg border border-white/5">
                                    <div className="flex justify-between items-center mb-2">
                                        <span className="font-mono text-white font-bold">{dev.ip}</span>
                                        <span className="text-aegis-400 font-bold">{formatBytes(dev.total_bytes)}</span>
                                    </div>
                                    <div className="flex gap-4 text-xs text-slate-400">
                                        <span>{dev.total_packets.toLocaleString()} packets</span>
                                        {topService && <span>Top: <span className="text-white">{topService[0]}</span></span>}
                                        {topDest && <span>→ <span className="text-slate-300">{topDest[0]}</span></span>}
                                    </div>
                                    <div className="flex gap-1 mt-2 flex-wrap">
                                        {Object.keys(dev.protocols).map(proto => (
                                            <span key={proto} className="text-[10px] bg-white/10 px-1.5 py-0.5 rounded text-slate-300">{proto}</span>
                                        ))}
                                    </div>
                                </div>
                            );
                        })}
                        {data.device_stats.length === 0 && <div className="text-slate-500 italic">No device statistics yet.</div>}
                    </div>
                </div>
            </div>
        </div>
    );
}
