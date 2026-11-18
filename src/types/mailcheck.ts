export type CheckSeverity = 'ok' | 'warn' | 'error' | 'info' | 'pending';

export interface PtrCheck {
  ip: string;
  hostnames: string[];
  fcrdnsMatch: boolean;
}

export interface MxRecordResult {
  exchange: string;
  priority: number;
  ipv4: string[];
  ipv6: string[];
  ptr: PtrCheck[];
  latencyMs: number;
}

export interface MxModuleResult {
  status: CheckSeverity;
  summary: string;
  records: MxRecordResult[];
  fallbackA: string[];
  durationMs: number;
  error?: string;
}

export interface SpfMechanism {
  raw: string;
  qualifier: '+' | '-' | '~' | '?';
  type: string;
  value: string;
  causesLookup: boolean;
}

export interface SpfLookupNode {
  domain: string;
  depth: number;
  lookups: number;
}

export interface SpfModuleResult {
  status: CheckSeverity;
  summary: string;
  record: string | null;
  allRecords: string[];
  mechanisms: SpfMechanism[];
  allQualifier: string | null;
  lookupCount: number;
  lookupLimit: number;
  lookupChain: SpfLookupNode[];
  durationMs: number;
  issues: string[];
}

export interface DkimSelectorResult {
  selector: string;
  fqdn: string;
  found: boolean;
  record: string | null;
  version: string | null;
  keyType: string | null;
  keyBits: number | null;
  publicKeyPreview: string | null;
  flags: string[];
  revoked: boolean;
  status: CheckSeverity;
  note: string;
}

export interface DkimModuleResult {
  status: CheckSeverity;
  summary: string;
  testedSelectors: string[];
  foundCount: number;
  selectors: DkimSelectorResult[];
  durationMs: number;
}

export interface DmarcModuleResult {
  status: CheckSeverity;
  summary: string;
  record: string | null;
  policy: string | null;
  subdomainPolicy: string | null;
  pct: number | null;
  adkim: string | null;
  aspf: string | null;
  rua: string[];
  ruf: string[];
  fo: string | null;
  mtaSts: {
    found: boolean;
    record: string | null;
    id: string | null;
  };
  tlsRpt: {
    found: boolean;
    record: string | null;
    rua: string[];
  };
  durationMs: number;
  issues: string[];
}

export interface TlsDetails {
  protocol: string | null;
  cipher: string | null;
  subject: string | null;
  issuer: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  authorized: boolean | null;
}

export interface PortCheckResult {
  port: number;
  service: string;
  protocol: 'SMTP' | 'SMTPS' | 'Submission' | 'IMAP' | 'IMAPS' | 'POP3S';
  state: 'open' | 'closed' | 'timeout' | 'error';
  status: CheckSeverity;
  latencyMs: number | null;
  banner: string | null;
  ehloCapabilities: string[];
  startTlsSupported: boolean;
  tlsActive: boolean;
  tlsInfo: TlsDetails | null;
  note: string;
}

export interface PortsModuleResult {
  status: CheckSeverity;
  summary: string;
  targetHost: string | null;
  targetIp: string | null;
  openCount: number;
  ports: PortCheckResult[];
  durationMs: number;
}

export interface BlacklistEntryResult {
  id: string;
  name: string;
  zone: string;
  queryType: 'ip' | 'domain';
  queryTarget: string;
  state: 'clean' | 'listed' | 'blocked_resolver' | 'error';
  status: CheckSeverity;
  returnCode: string | null;
  txtReason: string | null;
  latencyMs: number;
}

export interface BlacklistModuleResult {
  status: CheckSeverity;
  summary: string;
  checkedIp: string | null;
  checkedDomain: string;
  listedCount: number;
  totalChecked: number;
  entries: BlacklistEntryResult[];
  durationMs: number;
}

export interface RecommendationItem {
  id: string;
  module: 'MX' | 'SPF' | 'DKIM' | 'DMARC' | 'Ports' | 'Blacklists';
  severity: 'error' | 'warn' | 'info';
  title: string;
  description: string;
  suggestedRecord?: string;
}

export interface FullCheckReport {
  id: string;
  input: string;
  domain: string;
  customHost: string | null;
  customSelectors: string[];
  startedAt: string;
  completedAt: string | null;
  totalDurationMs: number | null;
  mx: MxModuleResult | null;
  spf: SpfModuleResult | null;
  dkim: DkimModuleResult | null;
  dmarc: DmarcModuleResult | null;
  ports: PortsModuleResult | null;
  blacklists: BlacklistModuleResult | null;
  recommendations: RecommendationItem[];
}
