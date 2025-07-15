
export type RiskLevel = 'safe' | 'warning' | 'suspicious' | 'critical' | 'unknown';

export interface WellKnownPortDetail {
  name: string;
  risk: RiskLevel;
  description: string;
}

export interface Connection {
  protocol: string;
  localAddress: string;
  foreignAddress: string;
  state: string;
  pid?: string | null;
  raw: string;
  format: string;
  recvQ?: string;
  sendQ?: string;
  risk: RiskLevel;
  issues: string[];
  recommendations: string[]; // Kept for consistency, though might not be per-connection
  portInfo?: WellKnownPortDetail;
}

export interface ListeningPort {
  port: string | null;
  service: string;
  risk: RiskLevel;
  address: string;
  protocol: string;
}

export interface IPAnalysisDetail {
  ip: string;
  connections: number;
  ports: Set<string | null>;
  isPublic: boolean;
  risk: RiskLevel; // Simplified risk for IP, could be more complex
}

export interface Recommendation {
  type: 'critical' | 'warning';
  title: string;
  description: string;
  services?: string;
}

export interface AnalysisSummary {
  safe: number;
  warning: number;
  suspicious: number;
  critical: number;
}

export interface DetailedPortUsageStats {
  port: string;
  service: string;
  protocol: string;
  count: number; // Number of connections/listeners using this port
  risk: RiskLevel;
  description: string;
}

export interface LocalServiceDetail {
  port: string | null;
  protocol: string;
  serviceName: string;
  description: string;
  risk: RiskLevel;
  associatedPids?: string[];
  connectionCount: number;
  rawExampleLines: string[];
  aiInsight?: string | null;
  isFetchingAiInsight?: boolean;
}

export interface AnalysisResults {
  totalConnections: number;
  format: string;
  listeningPorts: ListeningPort[];
  localServicesOnLoopback: LocalServiceDetail[]; // New field
  suspiciousConnections: Connection[]; // Contains all connections with risk > safe
  establishedConnections: Connection[]; // Raw established connections
  warnings: string[]; // Generic warnings, currently not heavily used by provided logic
  summary: AnalysisSummary;
  portAnalysis: Record<string, any>; // Placeholder for detailed port analysis
  ipAnalysis: Record<string, IPAnalysisDetail>;
  recommendations: Recommendation[];
  allLocalPortsActivity: DetailedPortUsageStats[];
  allForeignPortsActivity: DetailedPortUsageStats[];
  error?: string;
}

// Props for UI components
export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'default' | 'destructive' | 'outline' | 'secondary' | 'ghost' | 'link';
  size?: 'default' | 'sm' | 'lg' | 'icon';
}

export interface CardProps extends React.HTMLAttributes<HTMLDivElement> {}
export interface CardHeaderProps extends React.HTMLAttributes<HTMLDivElement> {}
export interface CardTitleProps extends React.HTMLAttributes<HTMLHeadingElement> {}
export interface CardDescriptionProps extends React.HTMLAttributes<HTMLParagraphElement> {}
export interface CardContentProps extends React.HTMLAttributes<HTMLDivElement> {}

export interface AlertProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: 'default' | 'destructive';
}
export interface AlertTitleProps extends React.HTMLAttributes<HTMLHeadingElement> {}
export interface AlertDescriptionProps extends React.HTMLAttributes<HTMLParagraphElement> {}

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: 'default' | 'secondary' | 'destructive' | 'outline';
}

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  variant?: 'default' | 'error';
}

// Threat Intelligence Types
export interface ThreatIntelEntry {
  id: string;
  ip: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  source: string;
  dateAdded: Date;
  tags: string[];
}

export interface ThreatIntelList {
  id: string;
  name: string;
  description: string;
  entries: ThreatIntelEntry[];
  isActive: boolean;
  dateCreated: Date;
  dateModified: Date;
}

// For file object from input
export interface UploadedFile extends File {}

// For Timeline Feature
export interface HistoricalAnalysis {
  id: string;
  name: string;
  timestamp: Date;
  results: AnalysisResults;
}

export interface TimelineEntry {
  snapshotId: string;
  snapshotName: string;
  snapshotTimestamp: Date;
  ipFound: boolean;
  connectionsToIp: Connection[]; // Connections where selected IP is foreign
  connectionsFromIp: Connection[]; // Connections where selected IP is local (e.g. IP is listening)
  summary?: {
      localPortsInvolved: string[]; // Local ports on your machine connecting to/from this IP
      foreignPortsOnSelectedIp: string[]; // Ports on the selected IP that were connected to
      allPortsInvolvedWithIp: string[]; // All ports (local or foreign on IP) associated with this IP
      connectionStates: string[];
      risk: RiskLevel;
      connectionCount: number; // Total connections involving this IP in this snapshot
  }
}

// For Overview Tab's "Top Listening Port Activity"
export interface ConnectedIpDetail {
  ip: string;
  connectionCountToPort: number; // Number of connections from this IP to the parent listening port
  risk: RiskLevel; // Highest risk assessed for connections from this IP to the port
  isPublic: boolean;
  states: string[]; // Observed connection states from this IP to the port (e.g., ['ESTABLISHED', 'TIME_WAIT'])
}

export interface OverviewPortActivityData {
  port: string; // e.g., "80"
  protocol: string; // e.g., "TCP"
  listenerAddress: string; // The specific address string it's listening on, e.g., "0.0.0.0:80" or "127.0.0.1:5432"
  service: string; // Service name, e.g., "HTTP"
  description: string; // Well-known port description
  risk: RiskLevel; // Risk of the listening port itself

  activeInboundConnectionsCount: number; // Total number of active connections to this listening port
  connectedIpDetails: ConnectedIpDetail[]; // Details of unique IPs connecting to this listening port

  // For AI insights for this specific listening port context
  aiContextualInsight?: string | null;
  isFetchingAiContextualInsight?: boolean;
}

// For Risk Matrix Tab
export interface RiskMatrixCell {
  id: string; // unique key, e.g. `${localAddress}-${foreignAddress}-${protocol}`
  localAddress: string;
  localIP: string | null;
  localPort: string | null;
  foreignAddress: string;
  foreignIP: string | null;
  foreignPort: string | null;
  protocol: string;
  risk: RiskLevel;
  connectionCount: number;
  states: Set<string>;
  issues: string[];
  aggregatedPIDs: Set<string>; // New: Store all unique PIDs for this aggregated interaction
  isListenerInteraction: boolean; // New: True if this represents a local listening port
  aiInsight?: string | null; // New: For cell-specific AI insights
  isFetchingAiInsight?: boolean; // New: For cell-specific AI insights
}
