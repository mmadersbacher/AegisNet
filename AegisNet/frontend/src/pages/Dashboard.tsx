import React from 'react';
import { Shield, Server, Wifi, Activity, Cpu } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';
import { motion } from 'framer-motion';

const dummyData = [
    { name: '10:00', events: 40, traffic: 2400 },
    { name: '10:05', events: 32, traffic: 1398 },
    { name: '10:10', events: 55, traffic: 9800 },
    { name: '10:15', events: 80, traffic: 3908 },
    { name: '10:20', events: 25, traffic: 4800 },
    { name: '10:25', events: 35, traffic: 3800 },
    { name: '10:30', events: 60, traffic: 4300 },
];

const container = {
    hidden: { opacity: 0 },
    show: {
        opacity: 1,
        transition: {
            staggerChildren: 0.1
        }
    }
};

const item = {
    hidden: { y: 20, opacity: 0 },
    show: { y: 0, opacity: 1 }
};

export default function Dashboard() {
    return (
        <motion.div
            variants={container}
            initial="hidden"
            animate="show"
            className="space-y-8"
        >
            <header>
                <h2 className="text-4xl font-bold flex items-center gap-4 mb-2 text-white tracking-tight">
                    <Activity className="text-aegis-500 animate-pulse" size={32} />
                    Command Center
                </h2>
                <p className="text-slate-400 font-lg max-w-2xl">
                    Real-time threat intelligence and infrastructure monitoring.
                    System status is <span className="text-emerald-400 font-mono font-bold">OPTIMAL</span>.
                </p>
            </header>

            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <StatCard icon={<Shield />} label="Threat Level" value="LOW" sub="No active incursions" color="text-emerald-400" />
                <StatCard icon={<Server />} label="Active Agents" value="3/12" sub="9 standby" color="text-aegis-400" />
                <StatCard icon={<Wifi />} label="Network Load" value="1.2 Gbps" sub="Peak: 2.4 Gbps" color="text-aegis-accent" />
                <StatCard icon={<Cpu />} label="System Load" value="42%" sub="Core temps normal" color="text-slate-200" />
            </div>

            {/* Charts Section */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-[26rem]">
                <motion.div variants={item} className="lg:col-span-2 glass-panel p-6 rounded-2xl flex flex-col">
                    <div className="flex justify-between items-center mb-6">
                        <h3 className="text-lg font-semibold flex items-center gap-2 text-slate-100">
                            <span className="w-1.5 h-6 bg-gradient-to-b from-aegis-400 to-aegis-600 rounded-full"></span>
                            Network Traffic Analysis
                        </h3>
                        <div className="flex gap-2">
                            {['1H', '24H', '7D'].map(t => (
                                <button key={t} className="px-3 py-1 rounded-md text-xs font-medium bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white transition-colors">
                                    {t}
                                </button>
                            ))}
                        </div>
                    </div>
                    <div className="flex-1 w-full min-h-0">
                        <ResponsiveContainer width="100%" height="100%">
                            <AreaChart data={dummyData}>
                                <defs>
                                    <linearGradient id="colorTraffic" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                                        <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                                    </linearGradient>
                                </defs>
                                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                                <XAxis dataKey="name" stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                                <YAxis stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} tickFormatter={(value) => `${value / 1000}k`} />
                                <Tooltip
                                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
                                    itemStyle={{ color: '#bae6fd' }}
                                    cursor={{ stroke: '#334155', strokeWidth: 1 }}
                                />
                                <Area type="monotone" dataKey="traffic" stroke="#3b82f6" strokeWidth={3} fillOpacity={1} fill="url(#colorTraffic)" />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                </motion.div>

                {/* Recent Alerts Feed */}
                <motion.div variants={item} className="glass-panel p-6 rounded-2xl flex flex-col overflow-hidden">
                    <div className="flex justify-between items-center mb-6">
                        <h3 className="text-lg font-semibold text-slate-100">Recent Alerts</h3>
                        <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse box-shadow-[0_0_10px_rgba(239,68,68,0.5)]" />
                    </div>

                    <div className="flex-1 overflow-y-auto space-y-3 custom-scrollbar pr-2">
                        {[1, 2, 3, 4, 5, 6].map(i => (
                            <div key={i} className="group p-4 bg-white/5 rounded-xl border border-white/5 hover:border-white/10 hover:bg-white/10 transition-all cursor-pointer">
                                <div className="flex justify-between items-start mb-2">
                                    <div className="flex items-center gap-2">
                                        <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
                                        <span className="text-slate-200 text-sm font-semibold tracking-wide">SSH_BRUTE_FORCE</span>
                                    </div>
                                    <span className="text-slate-500 text-xs font-mono">10:42:{10 + i}</span>
                                </div>
                                <div className="text-xs text-slate-400 font-mono pl-3.5 border-l border-slate-700">
                                    Failed password for root from 192.168.1.{100 + i}
                                </div>
                            </div>
                        ))}
                    </div>
                </motion.div>
            </div>
        </motion.div>
    );
}

function StatCard({ icon, label, value, sub, color }: any) {
    return (
        <motion.div variants={item} className="glass-card p-6 rounded-2xl relative overflow-hidden group">
            <div className={`absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity transform group-hover:scale-110 duration-500 ${color}`}>
                {React.cloneElement(icon, { size: 64 })}
            </div>

            <div className="relative z-10 flex flex-col h-full justify-between">
                <div className="mb-4">
                    <div className={`p-3 w-fit rounded-xl bg-white/5 ${color} mb-3`}>{React.cloneElement(icon, { size: 24 })}</div>
                    <div className="text-slate-400 text-sm font-medium uppercase tracking-wider">{label}</div>
                </div>
                <div>
                    <div className="text-3xl font-bold text-white tracking-tight mb-1">{value}</div>
                    <div className="text-xs text-slate-500 font-mono">{sub}</div>
                </div>
            </div>
        </motion.div>
    )
}
