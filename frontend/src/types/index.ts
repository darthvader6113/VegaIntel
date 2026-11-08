export interface OverviewStats {
  metrics: {
    total_canonical_iocs: number;
    total_sightings: number;
    duplicates_prevented: number;
    deduplication_ratio_pct: number;
    monitored_cves: number;
    critical_cves: number;
    active_threat_actors: number;
    malware_families: number;
    poc_references: number;
  };
  ioc_type_distribution: { type: string; count: number }[];
  feed_statuses: FeedStatus[];
  recent_sightings: Sighting[];
  ingestion_trend?: {
    date: string;
    day: string;
    iocs: number;
    attacks: number;
  }[];
}

export interface IOC {
  fingerprint: string;
  ioc_type: string;
  ioc_value: string;
  first_seen: string;
  last_seen: string;
  sighting_count: number;
  unique_sources_count: number;
  sources: string[];
  overall_confidence: number;
  threat_types: string[];
  tags: string[];
  associated_cves?: string[];
  associated_apt_groups?: string[];
  associated_malware?: string[];
  status: string;
}

export interface Sighting {
  sighting_id: string;
  ioc_fingerprint: string;
  source: string;
  observed_at: string;
  raw_payload: Record<string, any>;
  feed_confidence: number;
  associated_cve?: string;
  associated_malware?: string;
  evidence_notes: string;
}

export interface CVE {
  cve_id: string;
  description: string;
  cvss_score: number;
  cvss_vector?: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  published_date?: string;
  cwe_ids: string[];
  references: string[];
  has_poc: boolean;
  associated_ioc_count: number;
}

export interface APTGroup {
  group_id: string;
  name: string;
  aliases: string[];
  origin_country?: string;
  description: string;
  target_sectors: string[];
  techniques: string[];
  associated_malware: string[];
  associated_cves: string[];
  infrastructure_count: number;
}

export interface MalwareFamily {
  malware_id: string;
  name: string;
  malware_type: string;
  description: string;
  aliases: string[];
  associated_apt_groups: string[];
  associated_cves: string[];
  sample_hashes: string[];
  known_c2_servers: string[];
}

export interface PoCReference {
  poc_id: string;
  cve_id: string;
  source: string;
  title: string;
  url: string;
  author: string;
  reliability: string;
  description: string;
  discovered_date?: string;
  advisory: string;
}

export interface FeedStatus {
  feed_name: string;
  category: string;
  status: "HEALTHY" | "DEGRADED" | "SYNCING" | "ERROR";
  last_successful_sync?: string;
  last_error?: string;
  total_records_ingested: number;
  unique_iocs_contributed: number;
  endpoint_url?: string;
}

export interface IngestionJob {
  job_id: string;
  source: string;
  started_at: string;
  completed_at?: string;
  status: "SUCCESS" | "FAILED" | "RUNNING";
  records_processed: number;
  new_iocs_created: number;
  sightings_added: number;
  duplicates_prevented: number;
  error_message?: string;
}

