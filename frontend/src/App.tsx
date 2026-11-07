import React, { useState, useEffect } from 'react';
import { Tabs } from '@ark-ui/react';
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
    <div className="flex h-screen w-screen overflow-hidden bg-[#f8fafc] text-slate-800 font-sans antialiased">
      {/* Fixed Enterprise Sidebar */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        dedupRatio={stats?.metrics.deduplication_ratio_pct ?? 0}
      />

      {/* Main Content Area powered by Ark UI Tabs */}
      <Tabs.Root
        value={activeTab}
        onValueChange={(details) => setActiveTab(details.value as TabType)}
        className="flex-1 flex flex-col h-full min-w-0 overflow-hidden"
      >
        {/* Top Header */}
        <Header
          activeTab={activeTab}
          isSyncing={isSyncing}
          onTriggerSync={handleTriggerSync}
          onRequestIocOpen={() => setIsRequestIocOpen(true)}
          onLogout={handleLogout}
          currentUser={currentUser}
          uniqueIocs={stats?.metrics.total_canonical_iocs ?? 0}
          dedupRatio={stats?.metrics.deduplication_ratio_pct ?? 0}
        />

        {/* Scrollable Module Canvas (Full Width, Zero Horizontal Overflow) */}
        <main className="flex-1 overflow-y-auto overflow-x-hidden p-6 lg:p-8 min-w-0">
          <div className="w-full space-y-6">
            <Tabs.Content value="overview">
              <OverviewModule stats={stats} onNavigate={setActiveTab} />
            </Tabs.Content>
            <Tabs.Content value="detections">
              <ReactFlowDetectionsModule onRequestIocOpen={() => setIsRequestIocOpen(true)} />
            </Tabs.Content>
            <Tabs.Content value="cves">
              <CveExplorerModule />
            </Tabs.Content>
            <Tabs.Content value="iocs">
              <IocRepositoryModule onRequestIocOpen={() => setIsRequestIocOpen(true)} />
            </Tabs.Content>
            <Tabs.Content value="graph">
              <CorrelationGraphModule />
            </Tabs.Content>
            <Tabs.Content value="apt">
              <AptGroupsModule />
            </Tabs.Content>
            <Tabs.Content value="malware">
              <MalwareModule />
            </Tabs.Content>
            <Tabs.Content value="pocs">
              <PocLibraryModule />
            </Tabs.Content>
            <Tabs.Content value="feeds">
              <FeedMonitoringModule />
            </Tabs.Content>
            <Tabs.Content value="export">
              <ExportModule />
            </Tabs.Content>
          </div>
        </main>
      </Tabs.Root>

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
  );
}

export default App;
