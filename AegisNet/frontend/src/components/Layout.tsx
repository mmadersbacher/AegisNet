import React from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { Shield, Activity, Radio, FileText, Settings, LogOut } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import clsx from 'clsx';

export default function Layout() {
    return (
        <div className="flex h-screen overflow-hidden selection:bg-aegis-500/30 selection:text-aegis-100">
            {/* Sidebar */}
            <motion.aside
                initial={{ x: -20, opacity: 0 }}
                animate={{ x: 0, opacity: 1 }}
                className="w-72 bg-surface/30 backdrop-blur-xl border-r border-white/5 flex flex-col relative z-20"
            >
                <div className="p-8 pb-10">
                    <div className="flex items-center gap-3 mb-1">
                        <div className="relative">
                            <Shield className="w-8 h-8 text-aegis-500 relative z-10" />
                            <div className="absolute inset-0 bg-aegis-500 blur-lg opacity-50" />
                        </div>
                        <div>
                            <h1 className="text-2xl font-bold tracking-wider text-white">AEGIS<span className="text-aegis-500">NET</span></h1>
                            <div className="text-[10px] tracking-[0.2em] text-aegis-accent/80 font-mono uppercase">Sentinel System</div>
                        </div>
                    </div>
                </div>

                <nav className="flex-1 px-4 space-y-2">
                    <NavItem to="/" icon={<Activity />} label="Command Center" delay={0.1} />
                    <NavItem to="/scanner" icon={<Radio />} label="Scanner Engine" delay={0.2} />
                    <NavItem to="/logs" icon={<FileText />} label="SIEM Logs" delay={0.3} />
                </nav>

                <div className="p-4 border-t border-white/5 mx-4 mb-4">
                    <NavItem to="/settings" icon={<Settings />} label="Configuration" delay={0.4} />
                    <div className="mt-4 pt-4 border-t border-white/5 flex items-center gap-3 px-4 py-2 opacity-50 hover:opacity-100 transition-opacity cursor-pointer text-sm font-mono text-slate-400">
                        <LogOut size={16} />
                        <span>TERMINATE SESSION</span>
                    </div>
                </div>
            </motion.aside>

            {/* Main Content Area */}
            <main className="flex-1 relative overflow-hidden flex flex-col">
                {/* Top Header / Breadcrumbs could go here */}
                <div className="h-16 border-b border-white/5 bg-surface/20 backdrop-blur-sm flex items-center justify-between px-8">
                    <div className="text-sm font-mono text-slate-400 flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                        SYSTEM ONLINE
                    </div>
                    <div className="text-xs font-mono text-slate-600">
                        v0.9.2-BETA // AUTH: ENCRYPTED
                    </div>
                </div>

                {/* Page Content with Transitions */}
                <div className="flex-1 overflow-auto p-4 md:p-8 relative">
                    {/* Background Grid Pattern */}
                    <div className="absolute inset-0 bg-grid-pattern opacity-[0.03] pointer-events-none" />
                    <ContentWrapper />
                </div>
            </main>
        </div>
    );
}

function ContentWrapper() {
    const location = useLocation();
    return (
        <AnimatePresence mode="wait">
            <motion.div
                key={location.pathname}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                transition={{ duration: 0.2 }}
                className="relative z-10 max-w-7xl mx-auto"
            >
                <Outlet />
            </motion.div>
        </AnimatePresence>
    );
}

function NavItem({ to, icon, label, delay }: { to: string; icon: React.ReactNode; label: string; delay: number }) {
    return (
        <NavLink to={to}>
            {({ isActive }) => (
                <motion.div
                    initial={{ x: -10, opacity: 0 }}
                    animate={{ x: 0, opacity: 1 }}
                    transition={{ delay }}
                    className={clsx(
                        "group relative px-4 py-3.5 rounded-xl flex items-center gap-3 transition-all duration-300 overflow-hidden",
                        isActive ? "text-white" : "text-slate-400 hover:text-white"
                    )}
                >
                    {/* Active Background & Glow */}
                    {isActive && (
                        <motion.div
                            layoutId="nav-bg"
                            className="absolute inset-0 bg-gradient-to-r from-aegis-500/20 to-transparent border-l-2 border-aegis-500"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                        />
                    )}

                    {/* Hover Effect */}
                    <div className="absolute inset-0 bg-white/5 opacity-0 group-hover:opacity-100 transition-opacity rounded-xl" />

                    {/* Icon & Label */}
                    <div className="relative z-10 flex items-center gap-3">
                        {React.cloneElement(icon as React.ReactElement, {
                            size: 20,
                            className: isActive ? "text-aegis-400 drop-shadow-[0_0_8px_rgba(59,130,246,0.5)]" : "group-hover:text-aegis-200 transition-colors"
                        })}
                        <span className={clsx("text-sm font-medium tracking-wide", isActive ? "font-semibold" : "")}>{label}</span>
                    </div>
                </motion.div>
            )}
        </NavLink>
    );
}
