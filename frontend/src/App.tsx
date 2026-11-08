import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Sidebar, TabType } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { OverviewModule } from './components/modules/OverviewModule';
import { ReactFlowDetectionsModule } from './components/modules/ReactFlowDetectionsModule';
import { CveExplorerModule } from './components/modules/CveExplorerModule';
import { IocRepositoryModule } from './components/modules/IocRepositoryModule';
import { AptGroupsModule } from './components/modules/AptGroupsModule';
import { MalwareModule } from './components/modules/MalwareModule';
import { PocLibraryModule } from './components/modules/PocLibraryModule';
import { FeedMonitoringModule } from './components/modules/FeedMonitoringModule';
import { ExportModule } from './components/modules/ExportModule';
import { CorrelationGraphModule } from './components/modules/CorrelationGraphModule';
import { AuthScreen } from './components/auth/AuthScreen';
import { RequestIocModal } from './components/common/RequestIocModal';
import { ErrorBoundary } from './components/common/ErrorBoundary';
import { OverviewStats } from './types';
import { api } from './services/api';

export function App() {
  const [currentUser, setCurrentUser] = useState<any | null>(null);
  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [stats, setStats] = useState<OverviewStats | null>(null);
  const [isSyncing, setIsSyncing] = useState(false);
  const [isRequestIocOpen, setIsRequestIocOpen] = useState(false);

  // Check existing session
  useEffect(() => {
    const user = api.getCurrentUser();
    if (user) {
      setCurrentUser(user);
    }
  }, []);

  const fetchStats = async () => {
    if (!currentUser) return;
    try {
      const data = await api.getOverviewStats();
      setStats(data);
    } catch (e) {
      console.warn('API telemetry sync note');
    }
  };

  useEffect(() => {
    if (currentUser) {
      fetchStats();
      const interval = setInterval(fetchStats, 20000);
      return () => clearInterval(interval);
    }
  }, [currentUser]);

  const handleTriggerSync = async () => {
    try {
      setIsSyncing(true);
      await api.triggerSync();
      setTimeout(async () => {
        await fetchStats();
        setIsSyncing(false);
      }, 3000);
    } catch (e) {
      console.error(e);
      setIsSyncing(false);
    }
  };

  const handleLogout = () => {
    api.logout();
    setCurrentUser(null);
  };

  // If not logged in, show Executive Light Authentication Screen
  if (!currentUser) {
    return <AuthScreen onLoginSuccess={(user) => setCurrentUser(user)} />;
  }

  return (
    <ErrorBoundary fallbackTitle="VegaIntel Dashboard Shell">
      <div className="flex h-screen w-screen overflow-hidden bg-[#f8fafc] text-slate-800 font-sans antialiased">
        {/* Fixed Enterprise Sidebar */}
        <Sidebar
          activeTab={activeTab}
          setActiveTab={setActiveTab}
        />

        {/* Main Content Area */}
        <div className="flex-1 flex flex-col h-full min-w-0 overflow-hidden">
          {/* Top Header */}
          <Header
            activeTab={activeTab}
            isSyncing={isSyncing}
            onTriggerSync={handleTriggerSync}
            onRequestIocOpen={() => setIsRequestIocOpen(true)}
            onLogout={handleLogout}
            currentUser={currentUser}
          />

          {/* Scrollable Module Canvas (Full Width, Zero Horizontal Overflow) */}
          <main className="flex-1 overflow-y-auto overflow-x-hidden p-6 lg:p-8 min-w-0">
            <ErrorBoundary fallbackTitle={`Module: ${activeTab.toUpperCase()}`}>
              <AnimatePresence mode="wait">
                <motion.div
                  key={activeTab}
                  initial={{ opacity: 0, y: 5 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -5 }}
                  transition={{ duration: 0.16, ease: 'easeOut' }}
                  className="w-full space-y-6"
                >
                  {activeTab === 'overview' && (
                    <OverviewModule stats={stats} onNavigate={setActiveTab} />
                  )}
                  {activeTab === 'detections' && (
                    <ReactFlowDetectionsModule onRequestIocOpen={() => setIsRequestIocOpen(true)} />
                  )}
                  {activeTab === 'cves' && (
                    <CveExplorerModule />
                  )}
                  {activeTab === 'iocs' && (
                    <IocRepositoryModule onRequestIocOpen={() => setIsRequestIocOpen(true)} />
                  )}
                  {activeTab === 'graph' && (
                    <CorrelationGraphModule />
                  )}
                  {activeTab === 'apt' && (
                    <AptGroupsModule />
                  )}
                  {activeTab === 'malware' && (
                    <MalwareModule />
                  )}
                  {activeTab === 'pocs' && (
                    <PocLibraryModule />
                  )}
                  {activeTab === 'feeds' && (
                    <FeedMonitoringModule />
                  )}
                  {activeTab === 'export' && (
                    <ExportModule />
                  )}
                </motion.div>
              </AnimatePresence>
            </ErrorBoundary>
          </main>
        </div>

        {/* On-Demand IOC Submission & Enrichment Modal */}
        <RequestIocModal
          isOpen={isRequestIocOpen}
          onClose={() => setIsRequestIocOpen(false)}
          onSuccess={() => {
            setIsRequestIocOpen(false);
            fetchStats();
          }}
        />
      </div>
    </ErrorBoundary>
  );
}

export default App;
