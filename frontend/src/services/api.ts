import { OverviewStats, IOC, CVE, APTGroup, MalwareFamily, PoCReference, FeedStatus, IngestionJob } from '../types';

const API_BASE = '/api';

function getAuthHeader(): Record<string, string> {
  const token = localStorage.getItem('vegaintel_token');
  if (token) {
    return { Authorization: `Bearer ${token}` };
  }
  return {};
}

export const api = {
  // Authentication
  async login(email: string, password: string, recaptchaToken?: string): Promise<{ access_token: string; user: any }> {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, recaptcha_token: recaptchaToken }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Login failed' }));
      throw new Error(err.detail || 'Login failed');
    }
    const data = await res.json();
    localStorage.setItem('vegaintel_token', data.access_token);
    localStorage.setItem('vegaintel_user', JSON.stringify(data.user));
    return data;
  },

  async register(
    emailOrPayload: string | { email: string; password: string; full_name?: string; organization?: string; recaptcha_token?: string },
    password?: string,
    fullName?: string,
    org?: string,
    recaptchaToken?: string
  ): Promise<{ access_token: string; user: any }> {
    const payload =
      typeof emailOrPayload === 'object'
        ? emailOrPayload
        : { email: emailOrPayload, password: password!, full_name: fullName, organization: org, recaptcha_token: recaptchaToken };

    const res = await fetch(`${API_BASE}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Registration failed' }));
      throw new Error(err.detail || 'Registration failed');
    }
    const data = await res.json();
    localStorage.setItem('vegaintel_token', data.access_token);
    localStorage.setItem('vegaintel_user', JSON.stringify(data.user));
    return data;
  },

  async getMe(): Promise<any> {
    const res = await fetch(`${API_BASE}/auth/me`, {
      headers: { ...getAuthHeader() },
    });
    if (!res.ok) throw new Error('Session expired');
    return res.json();
  },

  logout(): void {
    localStorage.removeItem('vegaintel_token');
    localStorage.removeItem('vegaintel_user');
  },

  getCurrentUser(): any | null {
    const saved = localStorage.getItem('vegaintel_user');
    if (!saved) return null;
    try {
      return JSON.parse(saved);
    } catch {
      return null;
    }
  },

  // Overview Stats
  async getOverviewStats(): Promise<OverviewStats> {
    const res = await fetch(`${API_BASE}/overview/stats`, {
      headers: { ...getAuthHeader() },
    });
    if (!res.ok) throw new Error('Failed to fetch overview stats');
    return res.json();
  },

  // CVEs
  async getCVEs(params?: { q?: string; severity?: string; has_poc?: boolean }): Promise<{ total: number; items: CVE[] }> {
    const query = new URLSearchParams();
    if (params?.q) query.append('q', params.q);
    if (params?.severity) query.append('severity', params.severity);
    if (params?.has_poc !== undefined) query.append('has_poc', String(params.has_poc));
    const res = await fetch(`${API_BASE}/cves/?${query.toString()}`, {
      headers: { ...getAuthHeader() },
    });
    if (!res.ok) throw new Error('Failed to fetch CVEs');
    return res.json();
  },

  async getCVEDetail(cveId: string): Promise<{ cve: CVE; associated_iocs: IOC[]; pocs: PoCReference[]; exploiting_actors: string[] }> {
    const res = await fetch(`${API_BASE}/cves/${cveId}`, {
      headers: { ...getAuthHeader() },
    });
    if (!res.ok) throw new Error(`Failed to fetch CVE ${cveId}`);
    return res.json();
  },

  // IOCs
  async getIOCs(params?: {
    q?: string;
    ioc_type?: string;
    source?: string;
    time_range?: string;
    min_confidence?: number;
    threat_type?: string;
    status_filter?: string;
    limit?: number;
  }): Promise<{ total: number; time_range: string; items: IOC[] }> {
    const query = new URLSearchParams();
    if (params?.q) query.append('q', params.q);
    if (params?.ioc_type) query.append('ioc_type', params.ioc_type);
    if (params?.source) query.append('source', params.source);
    if (params?.time_range) query.append('time_range', params.time_range);
    if (params?.min_confidence) query.append('min_confidence', String(params.min_confidence));
    if (params?.threat_type) query.append('threat_type', params.threat_type);
    if (params?.status_filter) query.append('status_filter', params.status_filter);
    if (params?.limit) query.append('limit', String(params.limit));
    const res = await fetch(`${API_BASE}/iocs/?${query.toString()}`, {
      headers: { ...getAuthHeader() },
    });
    if (!res.ok) throw new Error('Failed to fetch IOCs');
    return res.json();
  },

  async getTodayNewIOCs(): Promise<{ date: string; total_new_today: number; items: IOC[] }> {
    const res = await fetch(`${API_BASE}/iocs/today`, {
      headers: { ...getAuthHeader() },
    });
    if (!res.ok) throw new Error("Failed to fetch today's new IOCs");
    return res.json();
  },

  async requestIOC(payload: {
    ioc: string;
    ioc_type?: string;
    notes?: string;
    target_cve?: string;
    target_malware?: string;
    tags?: string[];
  }): Promise<any> {
    const res = await fetch(`${API_BASE}/iocs/request`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...getAuthHeader(),
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to submit IOC' }));
      throw new Error(err.detail || 'Failed to submit IOC');
    }
    return res.json();
  },

  async fetchIOCsByCVE(cveId: string): Promise<any> {
    const res = await fetch(`${API_BASE}/iocs/fetch-by-cve`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...getAuthHeader(),
      },
      body: JSON.stringify({ cve_id: cveId }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to fetch IOCs for CVE' }));
      throw new Error(err.detail || 'Failed to fetch IOCs for CVE');
    }
    return res.json();
  },

  async getIOCDetail(fingerprint: string): Promise<any> {
    const res = await fetch(`${API_BASE}/iocs/detail?fingerprint=${encodeURIComponent(fingerprint)}`, {
      headers: { ...getAuthHeader() },
    });
    if (!res.ok) throw new Error(`Failed to fetch IOC detail for ${fingerprint}`);
    return res.json();
  },

  // APT & Malware & PoCs
  async getAPTGroups(params?: { q?: string }): Promise<{ total: number; items: APTGroup[] }> {
    const query = new URLSearchParams();
    if (params?.q) query.append('q', params.q);
    const res = await fetch(`${API_BASE}/apt/?${query.toString()}`, {
      headers: { ...getAuthHeader() },
    });
    if (!res.ok) throw new Error('Failed to fetch APT groups');
    return res.json();
  },

  async getAPTDetail(groupId: string): Promise<{ group: APTGroup; associated_infrastructure: IOC[]; targeted_cves: CVE[] }> {
    const res = await fetch(`${API_BASE}/apt/${groupId}`, {
      headers: { ...getAuthHeader() },
    });
    if (!res.ok) throw new Error(`Failed to fetch APT group ${groupId}`);
    return res.json();
  },

  async getMalware(params?: { q?: string; malware_type?: string }): Promise<{ total: number; items: MalwareFamily[] }> {
    const query = new URLSearchParams();
    if (params?.q) query.append('q', params.q);
    if (params?.malware_type) query.append('malware_type', params.malware_type);
    const res = await fetch(`${API_BASE}/malware/?${query.toString()}`, {
      headers: { ...getAuthHeader() },
    });
    if (!res.ok) throw new Error('Failed to fetch malware');
    return res.json();
  },

  async getMalwareDetail(malwareId: string): Promise<{ malware: MalwareFamily; associated_iocs: IOC[] }> {
    const res = await fetch(`${API_BASE}/malware/${malwareId}`, {
      headers: { ...getAuthHeader() },
    });
    if (!res.ok) throw new Error(`Failed to fetch malware ${malwareId}`);
    return res.json();
  },

  async getPoCs(params?: { cve_id?: string; source?: string }): Promise<{ total: number; items: PoCReference[]; advisory: string }> {
    const query = new URLSearchParams();
    if (params?.cve_id) query.append('cve_id', params.cve_id);
    if (params?.source) query.append('source', params.source);
    const res = await fetch(`${API_BASE}/pocs/?${query.toString()}`, {
      headers: { ...getAuthHeader() },
    });
    if (!res.ok) throw new Error('Failed to fetch PoCs');
    return res.json();
  },

  async getFeedStatuses(): Promise<{ feeds: FeedStatus[] }> {
    const res = await fetch(`${API_BASE}/feeds/status`, {
      headers: { ...getAuthHeader() },
    });
    if (!res.ok) throw new Error('Failed to fetch feed statuses');
    return res.json();
  },

  async getIngestionJobs(): Promise<{ total: number; jobs: IngestionJob[] }> {
    const res = await fetch(`${API_BASE}/feeds/jobs`, {
      headers: { ...getAuthHeader() },
    });
    if (!res.ok) throw new Error('Failed to fetch ingestion jobs');
    return res.json();
  },

  async triggerSync(): Promise<{ status: string; message: string }> {
    const res = await fetch(`${API_BASE}/feeds/sync`, {
      method: 'POST',
      headers: { ...getAuthHeader() },
    });
    if (!res.ok) throw new Error('Failed to trigger sync');
    return res.json();
  },

  async getCorrelationGraph(params?: { focus_cve?: string; focus_ioc?: string }): Promise<any> {
    const query = new URLSearchParams();
    if (params?.focus_cve) query.append('focus_cve', params.focus_cve);
    if (params?.focus_ioc) query.append('focus_ioc', params.focus_ioc);
    const res = await fetch(`${API_BASE}/correlation/graph?${query.toString()}`, {
      headers: { ...getAuthHeader() },
    });
    if (!res.ok) throw new Error('Failed to fetch correlation graph');
    return res.json();
  }
};
