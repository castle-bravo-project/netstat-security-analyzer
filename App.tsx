
import React, { useState, useMemo, useCallback, ChangeEvent, useEffect } from 'react';
import { Button } from './components/ui/Button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './components/ui/Card';
import { Alert, AlertDescription, AlertTitle } from './components/ui/Alert';
import { Badge } from './components/ui/Badge';
import { Input } from './components/ui/Input';
import type { UploadedFile, AnalysisResults, Connection, RiskLevel, WellKnownPortDetail, Recommendation, ListeningPort, IPAnalysisDetail, DetailedPortUsageStats, HistoricalAnalysis, TimelineEntry, OverviewPortActivityData, ConnectedIpDetail, LocalServiceDetail, RiskMatrixCell, ThreatIntelList, ThreatIntelEntry } from './types';
import { 
  Upload, 
  FileText, 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  Download,
  Eye,
  Search,
  Server,
  Activity,
  ChevronDown,
  ChevronUp,
  Sparkles,
  Lightbulb, 
  Network,
  BarChart3, 
  ListTree,
  Globe, 
  History, 
  Trash2,  
  Loader2, 
  EyeOff, 
  Info,
  ArrowRightLeft,
  Gauge, 
  ShieldAlert, 
  ShieldCheck, 
  TrendingUp, 
  RadioTower,
  HardDrive, 
  TableProperties, 
  MessageSquareWarning,
  FileDown, // New icon for HTML report
  HelpCircle, // Icon for Help Tab
  BookOpen, // Alternative or supplemental for help
  Settings, // Icon for Settings Tab
  Key, // Icon for API key
  Save, // Icon for save action
  Eye, // Icon for show/hide password
  EyeOff, // Icon for show/hide password
  Shield as ShieldIcon, // Icon for threat intel
  Plus, // Icon for add
  Trash, // Icon for delete
  Edit, // Icon for edit
  Upload as UploadIcon, // Icon for import
  Download as DownloadIcon, // Icon for export
  AlertCircle, // Icon for threat severity
  Tag // Icon for tags
} from 'lucide-react';
import { GoogleGenAI, GenerateContentResponse } from "@google/genai";

// Safely access API_KEY from process.env
let apiKeyFromEnv: string | undefined;
try {
  if (typeof process !== 'undefined' && typeof process.env !== 'undefined') {
    apiKeyFromEnv = process.env.API_KEY;
  }
} catch (e) {
  console.warn("Error accessing process.env.API_KEY. AI features might be affected.", e);
}

type OverallRiskCategory = 'minimal' | 'low' | 'medium' | 'high' | 'critical';
interface OverallRiskContext {
  level: OverallRiskCategory;
  description: string;
  colorClass: string; // Tailwind class for app UI
  textColorClass: string; // Tailwind class for app UI
  icon: JSX.Element;
  detailedMessage: string;
  htmlReportBoxClass?: string; // Specific CSS class for HTML report
}

const CRITICAL_THREAT_INTEL_IPS: ReadonlySet<string> = new Set([
  "81.19.208.112", "45.146.54.61", "185.220.101.188", "169.150.219.149", "209.141.45.189",
  "5.189.140.45", "163.125.203.239", "195.80.150.186", "172.98.33.101", "181.41.206.140",
  "216.24.212.177", "154.16.192.215", "156.146.45.112", "80.246.28.92", "91.132.22.237",
  "157.97.134.73", "146.70.52.202", "185.153.177.33", "95.181.238.95", "172.94.87.70",
  "36.104.198.27", "193.43.135.246", "102.129.153.107", "134.19.179.155", "140.228.24.215",
  "2.56.252.242", "217.146.90.10", "79.142.197.173", "84.53.229.249", "31.170.22.21",
  "175.10.18.144", "116.98.116.44", "156.146.56.118", "154.16.192.31", "46.166.191.25",
  "37.120.210.219", "173.239.218.3", "81.162.64.120", "37.19.199.65", "37.120.233.252",
  "120.229.32.100", "94.134.181.133", "140.228.24.171", "68.235.48.108", "101.71.38.244",
  "91.90.44.25", "136.158.10.127", "178.249.214.137", "84.17.46.192", "193.32.249.163",
  "95.174.65.157", "136.144.35.232", "140.228.24.24", "172.98.92.52", "172.98.33.77",
  "219.100.37.240", "194.61.41.27", "45.8.68.59", "84.17.46.220", "185.225.234.37",
  "154.47.24.79", "5.182.32.55", "196.240.54.6", "84.247.59.197", "162.221.207.99",
  "213.152.187.230", "66.115.189.171", "112.132.249.170", "102.129.252.137", "84.17.46.27",
  "51.79.240.216", "109.202.99.41", "217.138.192.219", "191.96.106.164", "185.199.103.89",
  "194.156.136.42", "102.129.145.79", "185.202.220.45", "138.199.62.3", "37.19.221.32",
  "212.102.46.213", "162.216.47.203", "195.181.172.204", "223.252.34.57", "154.16.192.112",
  "46.166.191.29", "138.199.60.166", "181.214.94.104", "212.7.202.204", "192.109.205.223",
  "156.146.60.135", "223.73.64.230", "178.249.214.10", "172.98.87.242", "192.99.4.116",
  "138.199.60.10", "117.5.152.164", "223.252.34.41", "191.101.31.235", "45.132.225.245",
  "149.57.16.187", "77.81.142.13", "185.236.42.52", "45.87.214.100", "185.65.134.167",
  "85.95.179.59", "185.107.80.201", "85.194.207.76", "46.166.191.26", "185.218.127.161",
  "157.97.121.221", "217.138.252.205", "193.37.253.60", "172.93.177.172", "179.6.164.5",
  "95.111.230.250", "181.41.206.225", "77.234.43.189", "83.220.239.26", "31.206.121.191",
  "136.144.17.183", "156.146.60.79", "193.37.33.137", "84.17.52.84", "213.21.209.40",
  "157.254.225.137", "157.97.134.109", "193.176.31.125", "149.34.253.149", "185.220.101.154",
  "216.24.212.146", "181.214.150.104", "154.16.192.57", "185.203.122.184", "178.249.214.138",
  "193.176.31.60", "172.93.207.197", "178.239.163.110", "181.214.166.146", "194.61.41.74",
  "159.253.173.154", "45.8.68.39", "154.6.89.152", "189.201.145.130", "188.213.34.5",
  "213.152.176.252", "192.166.244.244", "149.57.16.156", "213.232.87.230", "157.97.134.156",
  "176.100.43.56", "169.150.232.188", "79.142.69.236", "91.90.126.84", "89.238.186.122",
  "192.145.116.249", "185.153.176.212", "143.244.48.4", "181.41.206.181", "79.173.88.48",
  "46.166.191.27", "149.36.49.174", "191.96.206.23", "172.93.207.45", "185.203.218.159",
  "185.220.100.251", "157.97.134.45", "169.150.196.18", "77.40.62.85", "178.249.214.130",
  "154.6.95.8", "181.41.202.137", "154.16.192.188", "185.23.214.43", "81.19.208.84",
  "37.19.217.245", "106.8.130.229", "165.231.182.146", "193.56.116.217", "37.19.196.102",
  "2.63.249.198", "85.174.203.197", "159.48.55.5", "103.231.88.22", "161.129.70.219",
  "102.129.235.75", "146.70.97.248", "154.6.83.17", "77.222.107.192", "191.101.41.30",
  "178.214.246.84", "188.126.94.109", "185.107.44.212", "37.19.200.26", "43.225.189.87",
  "59.173.200.234", "5.182.110.23", "191.96.255.138", "95.181.238.12", "163.125.203.248",
  "138.199.24.6", "138.199.10.10", "37.120.246.135", "193.19.205.174", "185.107.44.18",
  "146.70.34.90", "101.71.38.52", "174.240.251.6", "115.56.112.241", "192.145.117.51",
  "154.6.82.8", "188.191.238.51", "23.26.222.70", "185.236.42.26", "193.19.109.129",
  "156.146.57.44", "212.102.35.16", "45.133.180.10", "193.176.31.68", "185.177.124.148",
  "185.225.234.39", "136.144.42.155", "216.131.84.27", "185.162.184.14", "184.170.241.107",
  "176.113.72.213", "84.17.47.120", "45.134.140.142", "185.132.134.202", "45.91.23.141",
  "185.210.143.133", "45.85.144.247", "117.120.9.38", "213.87.160.4", "185.216.34.214",
  "146.70.65.145", "94.140.8.239", "185.229.59.129", "185.219.143.181", "185.77.217.75",
  "37.140.223.198", "79.142.69.160", "178.175.128.44", "172.98.92.62", "103.163.220.33",
  "59.153.220.18", "37.19.217.41", "94.140.8.217", "45.132.226.197", "82.180.149.203",
  "94.140.8.156", "191.96.37.164", "185.236.42.43", "157.97.121.109", "185.236.42.55",
  "181.214.218.187", "2.57.171.45", "154.28.188.136", "184.170.252.201", "94.46.24.59",
  "82.118.30.80", "192.166.244.241", "102.129.152.99", "169.150.204.4", "195.200.245.17",
  "212.102.39.154", "120.233.127.196", "173.239.254.196", "191.96.103.149", "194.233.98.20",
  "192.166.247.92", "178.72.71.22", "85.93.59.224", "191.96.168.75", "36.153.85.5",
  "185.189.114.94", "188.126.73.217", "109.70.150.100", "23.152.225.6", "138.199.29.231",
  "159.242.228.184", "38.242.7.253", "91.234.192.236", "184.170.242.25", "176.67.84.5",
  "125.201.224.54", "140.250.206.85", "185.15.38.89", "143.244.44.61", "192.166.246.12",
  "185.202.221.62", "89.37.173.42", "185.146.232.168", "73.93.39.154", "208.78.42.217",
  "82.102.23.158", "173.245.217.76", "71.19.251.161", "91.219.214.172", "45.130.203.200",
  "173.255.175.7", "172.58.139.95", "104.254.90.203", "196.196.232.10", "188.241.177.107",
  "23.129.64.250", "185.215.181.223", "199.59.243.222", "192.142.227.18", "91.90.126.79",
  "184.75.221.211", "157.97.134.116", "198.54.133.35", "194.32.122.23", "89.46.223.184",
  "173.244.49.17", "154.6.82.145", "185.213.82.115", "173.255.172.157", "23.152.225.11",
  "146.70.137.42", "216.73.160.236", "5.182.110.171", "216.24.212.16", "85.9.20.135",
  "85.9.20.149", "87.249.134.10", "213.152.161.170", "102.129.235.27", "45.144.113.48",
  "75.184.103.239", "5.182.110.124", "185.211.32.2", "191.96.36.105", "193.43.135.104",
  "85.24.253.49", "213.232.87.234", "37.19.221.83", "43.239.85.192", "178.17.170.169",
  "125.206.32.30", "84.17.37.157", "1.165.96.74", "193.176.31.78", "185.153.151.147",
  "185.206.225.235", "77.81.142.29", "102.129.143.60", "81.162.64.208", "159.242.228.94",
  "188.126.73.222", "195.200.221.44", "51.158.22.143", "121.228.196.44", "181.215.176.114",
  "85.203.34.137", "208.78.41.68", "107.189.5.217", "185.132.179.9", "212.102.53.84",
  "31.173.86.103", "200.105.82.83", "156.146.45.101", "188.241.177.252", "181.214.94.93",
  "172.98.80.125", "148.72.164.107", "86.48.12.211", "178.249.214.136", "194.187.251.155",
  "185.236.42.31", "143.244.42.95", "185.84.35.218", "156.146.46.204", "176.100.43.129",
  "185.21.216.197", "138.199.22.146", "216.73.161.122", "181.214.150.107", "85.9.20.248",
  "154.6.85.27", "58.221.37.66", "45.248.78.197", "185.65.134.165", "173.239.214.125",
  "180.248.3.85", "176.67.86.91", "212.102.47.9", "92.60.40.227", "212.102.47.84",
  "185.223.152.36", "185.153.179.59", "45.146.54.173", "136.144.35.124", "102.129.153.61",
  "212.102.40.77", "156.146.54.200", "157.97.134.163", "185.229.59.86", "143.244.42.104",
  "199.58.83.12", "5.62.43.111", "91.90.126.4", "178.255.168.226", "173.239.196.161",
  "178.255.154.106", "185.65.135.157", "188.214.152.69", "213.232.87.228", "62.182.82.10",
  "92.119.36.30", "185.254.75.55", "41.216.202.180", "80.78.26.147", "118.160.6.199",
  "185.153.179.17", "181.214.94.206", "122.177.111.205", "91.90.126.132", "185.216.74.10",
  "143.244.44.70", "103.204.169.244", "112.118.234.84", "37.140.254.21", "199.249.230.27",
  "188.170.76.124", "116.27.219.130", "163.125.203.246", "178.255.154.181", "91.218.89.89",
  "192.145.116.26", "212.188.11.146", "77.247.246.213", "154.6.95.147", "195.181.162.163",
  "91.90.120.135", "212.102.42.90"
]);

const riskOrderGlobal: RiskLevel[] = ['critical', 'suspicious', 'warning', 'safe', 'unknown'];

// Helper function to determine text color based on risk level for matrix
const getTextColorForRisk = (risk: RiskLevel): string => {
  switch (risk) {
    case 'critical':
      return 'text-red-700';
    case 'suspicious':
      return 'text-orange-700';
    case 'warning':
      return 'text-yellow-700';
    case 'safe':
    case 'unknown': // Group unknown with safe for this specific text coloring
      return 'text-gray-800';
    default:
      return 'text-gray-800'; // Default for any unspecified cases
  }
};

type HelpSectionKey = 'gettingOutput' | 'aboutTool' | 'understandingAnalysis' | 'usingAi' | 'interpretationTips' | 'disclaimer';

const App: React.FC = () => {
  const [file, setFile] = useState<UploadedFile | null>(null);
  const [latestAnalysisResults, setLatestAnalysisResults] = useState<AnalysisResults | null>(null);
  const [historicalAnalyses, setHistoricalAnalyses] = useState<HistoricalAnalysis[]>([]);

  // API Key state management
  const [userApiKey, setUserApiKey] = useState<string>(() => {
    try {
      return localStorage.getItem('gemini-api-key') || '';
    } catch (e) {
      console.warn("Error accessing localStorage for API key:", e);
      return '';
    }
  });
  const [isApiKeyValid, setIsApiKeyValid] = useState<boolean | null>(null);
  const [isValidatingApiKey, setIsValidatingApiKey] = useState<boolean>(false);
  const [tempApiKey, setTempApiKey] = useState<string>('');
  const [showApiKey, setShowApiKey] = useState<boolean>(false);

  // Threat Intelligence state management
  const [threatIntelLists, setThreatIntelLists] = useState<ThreatIntelList[]>(() => {
    try {
      const saved = localStorage.getItem('threat-intel-lists');
      return saved ? JSON.parse(saved, (key, value) => {
        if (key === 'dateAdded' || key === 'dateCreated' || key === 'dateModified') {
          return new Date(value);
        }
        return value;
      }) : [];
    } catch (e) {
      console.warn("Error loading threat intel lists from localStorage:", e);
      return [];
    }
  });
  const [selectedThreatList, setSelectedThreatList] = useState<string | null>(null);
  const [isAddingThreatList, setIsAddingThreatList] = useState<boolean>(false);
  const [isAddingThreatEntry, setIsAddingThreatEntry] = useState<boolean>(false);
  const [newThreatListName, setNewThreatListName] = useState<string>('');
  const [newThreatListDescription, setNewThreatListDescription] = useState<string>('');
  const [newThreatEntry, setNewThreatEntry] = useState<Partial<ThreatIntelEntry>>({
    ip: '',
    description: '',
    severity: 'medium',
    source: '',
    tags: []
  });

  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<string>('overallRisk');
  const [filterRisk, setFilterRisk] = useState<RiskLevel | 'all'>('all'); // For Risky Connections Tab
  const [searchTerm, setSearchTerm] = useState<string>(''); // For Risky Connections Tab
  const [expandedIssues, setExpandedIssues] = useState<Record<string, boolean>>({}); // Keyed by unique ID (index or string)

  const [aiInsights, setAiInsights] = useState<string | null>(null);
  const [isFetchingAiInsights, setIsFetchingAiInsights] = useState<boolean>(false);
  
  const [aiPortAnalysis, setAiPortAnalysis] = useState<string | null>(null);
  const [isFetchingAiPortAnalysis, setIsFetchingAiPortAnalysis] = useState<boolean>(false);

  const [aiIpInsights, setAiIpInsights] = useState<Record<string, string | null>>({});
  const [isFetchingAiIpInsights, setIsFetchingAiIpInsights] = useState<Record<string, boolean>>({});

  const [aiLocalServiceInsights, setAiLocalServiceInsights] = useState<Record<string, string | null>>({});
  const [isFetchingAiLocalServiceInsights, setIsFetchingAiLocalServiceInsights] = useState<Record<string, boolean>>({});

  const [selectedIpForTimeline, setSelectedIpForTimeline] = useState<string>('');
  const [timelineIpDisplay, setTimelineIpDisplay] = useState<string>('');
  
  const [overviewPortActivityDataState, setOverviewPortActivityDataState] = useState<OverviewPortActivityData[]>([]);
  const [expandedOverviewPortIPs, setExpandedOverviewPortIPs] = useState<Record<string, boolean>>({});
  
  const [overallRiskContextState, setOverallRiskContextState] = useState<OverallRiskContext | null>(null);

  // States for Risk Matrix Tab
  const [riskMatrixFilterRisk, setRiskMatrixFilterRisk] = useState<RiskLevel | 'all'>('all');
  const [riskMatrixSearchTerm, setRiskMatrixSearchTerm] = useState<string>('');
  const [aiRiskMatrixCellInsights, setAiRiskMatrixCellInsights] = useState<Record<string, string | null>>({});
  const [isFetchingAiRiskMatrixCellInsights, setIsFetchingAiRiskMatrixCellInsights] = useState<Record<string, boolean>>({});
  
  // State for Help Tab Accordion
  const [activeHelpSection, setActiveHelpSection] = useState<HelpSectionKey | null>(null);

  // API Key management functions
  const saveApiKey = (key: string) => {
    try {
      localStorage.setItem('gemini-api-key', key);
      setUserApiKey(key);
      setIsApiKeyValid(null); // Reset validation state
    } catch (e) {
      console.error("Error saving API key to localStorage:", e);
    }
  };

  const validateApiKey = async (key: string) => {
    if (!key.trim()) {
      setIsApiKeyValid(false);
      return false;
    }

    setIsValidatingApiKey(true);
    try {
      const testAi = new GoogleGenAI({ apiKey: key });
      // Make a simple test call to validate the key
      await testAi.models.generateContent({
        model: 'gemini-2.5-flash-preview-04-17',
        contents: 'Test',
      });
      setIsApiKeyValid(true);
      return true;
    } catch (error) {
      console.error("API key validation failed:", error);
      setIsApiKeyValid(false);
      return false;
    } finally {
      setIsValidatingApiKey(false);
    }
  };

  // Threat Intelligence management functions
  const saveThreatIntelLists = (lists: ThreatIntelList[]) => {
    try {
      localStorage.setItem('threat-intel-lists', JSON.stringify(lists));
      setThreatIntelLists(lists);
    } catch (e) {
      console.error("Error saving threat intel lists to localStorage:", e);
    }
  };

  const createThreatIntelList = () => {
    if (!newThreatListName.trim()) return;

    const newList: ThreatIntelList = {
      id: `list-${Date.now()}`,
      name: newThreatListName.trim(),
      description: newThreatListDescription.trim(),
      entries: [],
      isActive: true,
      dateCreated: new Date(),
      dateModified: new Date()
    };

    const updatedLists = [...threatIntelLists, newList];
    saveThreatIntelLists(updatedLists);
    setNewThreatListName('');
    setNewThreatListDescription('');
    setIsAddingThreatList(false);
    setSelectedThreatList(newList.id);
  };

  const deleteThreatIntelList = (listId: string) => {
    const updatedLists = threatIntelLists.filter(list => list.id !== listId);
    saveThreatIntelLists(updatedLists);
    if (selectedThreatList === listId) {
      setSelectedThreatList(null);
    }
  };

  const toggleThreatIntelList = (listId: string) => {
    const updatedLists = threatIntelLists.map(list =>
      list.id === listId
        ? { ...list, isActive: !list.isActive, dateModified: new Date() }
        : list
    );
    saveThreatIntelLists(updatedLists);
  };

  const addThreatIntelEntry = () => {
    if (!selectedThreatList || !newThreatEntry.ip?.trim()) return;

    const entry: ThreatIntelEntry = {
      id: `entry-${Date.now()}`,
      ip: newThreatEntry.ip!.trim(),
      description: newThreatEntry.description?.trim() || '',
      severity: newThreatEntry.severity || 'medium',
      source: newThreatEntry.source?.trim() || 'User Added',
      dateAdded: new Date(),
      tags: newThreatEntry.tags || []
    };

    const updatedLists = threatIntelLists.map(list =>
      list.id === selectedThreatList
        ? {
            ...list,
            entries: [...list.entries, entry],
            dateModified: new Date()
          }
        : list
    );

    saveThreatIntelLists(updatedLists);
    setNewThreatEntry({
      ip: '',
      description: '',
      severity: 'medium',
      source: '',
      tags: []
    });
    setIsAddingThreatEntry(false);
  };

  const deleteThreatIntelEntry = (listId: string, entryId: string) => {
    const updatedLists = threatIntelLists.map(list =>
      list.id === listId
        ? {
            ...list,
            entries: list.entries.filter(entry => entry.id !== entryId),
            dateModified: new Date()
          }
        : list
    );
    saveThreatIntelLists(updatedLists);
  };

  const validateIpAddress = (ip: string): boolean => {
    // Basic IP validation (supports IPv4 and CIDR notation)
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/(?:[0-9]|[1-2][0-9]|3[0-2]))?$/;
    return ipv4Regex.test(ip);
  };

  const checkIpAgainstThreatIntel = (ip: string): ThreatIntelEntry | null => {
    // First check hardcoded critical threat intel IPs
    if (CRITICAL_THREAT_INTEL_IPS.has(ip)) {
      return {
        id: `hardcoded-${ip}`,
        ip: ip,
        description: 'Known malicious IP from built-in threat intelligence',
        severity: 'critical',
        source: 'Built-in Threat Intel',
        dateAdded: new Date(),
        tags: ['malicious', 'built-in']
      };
    }

    // Then check custom threat intelligence lists
    for (const list of threatIntelLists) {
      if (!list.isActive) continue;

      for (const entry of list.entries) {
        if (entry.ip === ip || (entry.ip.includes('/') && isIpInCidr(ip, entry.ip))) {
          return entry;
        }
      }
    }
    return null;
  };

  const isIpInCidr = (ip: string, cidr: string): boolean => {
    if (!cidr.includes('/')) return ip === cidr;

    try {
      const [network, prefixLength] = cidr.split('/');
      const networkParts = network.split('.').map(Number);
      const ipParts = ip.split('.').map(Number);
      const prefix = parseInt(prefixLength);

      const networkInt = (networkParts[0] << 24) | (networkParts[1] << 16) | (networkParts[2] << 8) | networkParts[3];
      const ipInt = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
      const mask = (-1 << (32 - prefix)) >>> 0;

      return (networkInt & mask) === (ipInt & mask);
    } catch (e) {
      return false;
    }
  };

  const renderThreatIntelBadge = (ip: string) => {
    const threatMatch = checkIpAgainstThreatIntel(ip);
    if (!threatMatch) return null;

    const severityColors = {
      low: 'bg-yellow-100 text-yellow-800 border-yellow-300',
      medium: 'bg-orange-100 text-orange-800 border-orange-300',
      high: 'bg-red-100 text-red-800 border-red-300',
      critical: 'bg-red-200 text-red-900 border-red-400'
    };

    return (
      <div className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium border ${severityColors[threatMatch.severity]} ml-2`}>
        <ShieldIcon className="w-3 h-3 mr-1" />
        Threat Intel: {threatMatch.severity}
        {threatMatch.source !== 'Built-in Threat Intel' && (
          <span className="ml-1 text-xs opacity-75">({threatMatch.source})</span>
        )}
      </div>
    );
  };

  // Export/Import functions for threat intelligence
  const exportThreatIntelLists = () => {
    const dataStr = JSON.stringify(threatIntelLists, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `threat-intel-lists-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const importThreatIntelLists = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const importedData = JSON.parse(e.target?.result as string);

        // Validate the imported data structure
        if (Array.isArray(importedData)) {
          const validatedLists: ThreatIntelList[] = importedData.map((list: any) => ({
            ...list,
            id: list.id || `imported-${Date.now()}-${Math.random()}`,
            dateCreated: new Date(list.dateCreated || Date.now()),
            dateModified: new Date(list.dateModified || Date.now()),
            entries: (list.entries || []).map((entry: any) => ({
              ...entry,
              id: entry.id || `entry-${Date.now()}-${Math.random()}`,
              dateAdded: new Date(entry.dateAdded || Date.now())
            }))
          }));

          // Merge with existing lists (avoid duplicates by ID)
          const existingIds = new Set(threatIntelLists.map(list => list.id));
          const newLists = validatedLists.filter(list => !existingIds.has(list.id));
          const updatedLists = [...threatIntelLists, ...newLists];

          saveThreatIntelLists(updatedLists);
          alert(`Successfully imported ${newLists.length} threat intelligence lists.`);
        } else {
          alert('Invalid file format. Expected an array of threat intelligence lists.');
        }
      } catch (error) {
        console.error('Error importing threat intel lists:', error);
        alert('Error importing file. Please check the file format.');
      }
    };
    reader.readAsText(file);

    // Reset the input
    event.target.value = '';
  };

  // Get the effective API key (environment variable takes precedence, then user-entered key)
  const effectiveApiKey = apiKeyFromEnv || userApiKey;

  const ai = useMemo(() => {
    if (!effectiveApiKey) {
      console.warn("No API key available. AI features will be disabled.");
      return null;
    }
    return new GoogleGenAI({ apiKey: effectiveApiKey });
  }, [effectiveApiKey]);

  const handleFileUpload = (event: ChangeEvent<HTMLInputElement>) => {
    const uploadedFile = event.target.files?.[0];
    if (uploadedFile) {
      setFile(uploadedFile as UploadedFile);
    }
  };

  const clearCurrentFileSelection = () => {
    setFile(null);
    const fileInput = document.getElementById('file-upload') as HTMLInputElement;
    if (fileInput) {
        fileInput.value = ''; 
    }
  }

  const clearAllData = () => {
    setFile(null);
    setLatestAnalysisResults(null);
    setHistoricalAnalyses([]);
    setExpandedIssues({});
    setAiInsights(null);
    setAiPortAnalysis(null);
    setAiIpInsights({});
    setIsFetchingAiIpInsights({});
    setAiLocalServiceInsights({});
    setIsFetchingAiLocalServiceInsights({});
    setSelectedIpForTimeline('');
    setTimelineIpDisplay('');
    setOverviewPortActivityDataState([]);
    setExpandedOverviewPortIPs({});
    setOverallRiskContextState(null);
    setRiskMatrixFilterRisk('all');
    setRiskMatrixSearchTerm('');
    setAiRiskMatrixCellInsights({});
    setIsFetchingAiRiskMatrixCellInsights({});
    // Reset API key validation state but keep the saved key
    setIsApiKeyValid(null);
    setIsValidatingApiKey(false);
    const fileInput = document.getElementById('file-upload') as HTMLInputElement;
    if (fileInput) {
        fileInput.value = '';
    }
  };

  const parseNetstatData = useCallback((content: string): { connections: Connection[], format: string } => {
    const lines = content.split('\n');
    const connections: Connection[] = [];
    
    const formatPatterns = {
      windows: /^\s*(TCP|UDP)\s+/i,
      linux: /^\s*(tcp|udp|tcp6|udp6)\s+/i,
      macos: /^\s*(tcp4|udp4|tcp6|udp6|tcp|udp)\s+/i 
    };
    
    let detectedFormat = 'generic';
    for (const line of lines) {
      const trimmedLine = line.trim();
      if (formatPatterns.windows.test(trimmedLine)) {
        detectedFormat = 'windows';
        break;
      } else if (formatPatterns.linux.test(trimmedLine)) {
        detectedFormat = 'linux';
        break;
      } else if (formatPatterns.macos.test(trimmedLine)) { 
        detectedFormat = 'macos';
        break;
      }
    }
    
    for (const line of lines) {
      const trimmedLine = line.trim();
      let skipLine = false;

      if (!trimmedLine ||
          trimmedLine.toLowerCase().includes('proto') && (trimmedLine.toLowerCase().includes('address') || trimmedLine.toLowerCase().includes('state')) || 
          trimmedLine.toLowerCase().includes('active connections') ||
          trimmedLine.toLowerCase().includes('listening ports') ||
          trimmedLine.toLowerCase().includes('executing netstat') || 
          trimmedLine.match(/^----/) || 
          trimmedLine.toLowerCase().startsWith('client ip address:') 
         ) {
        skipLine = true;
      }
      
      if (!skipLine) {
        if (detectedFormat === 'windows' && !formatPatterns.windows.test(trimmedLine)) {
          skipLine = true;
        } else if (detectedFormat === 'linux' && !formatPatterns.linux.test(trimmedLine)) {
          skipLine = true;
        } else if (detectedFormat === 'macos' && !formatPatterns.macos.test(trimmedLine)) {
          skipLine = true;
        }
      }

      if (skipLine) {
        continue;
      }
      
      const parts = trimmedLine.split(/\s+/);
      if (parts.length < 3 && detectedFormat === 'windows' && parts[0].toUpperCase() !== 'UDP') continue; 
      if (parts.length < 3 && detectedFormat !== 'windows') continue;


      let connection: Omit<Connection, 'risk' | 'issues' | 'recommendations' | 'portInfo'> | null = null;
      
      if (detectedFormat === 'windows') {
        if (parts.length >= 3) { 
          connection = {
            protocol: parts[0].toUpperCase(),
            localAddress: parts[1],
            foreignAddress: parts[2],
            state: parts[3] || (parts[0].toUpperCase() === 'UDP' ? '' : 'UNKNOWN'), 
            pid: parts[4] || null, 
            raw: line,
            format: 'windows'
          };
        }
      } else if (detectedFormat === 'linux') {
        let protocol = parts[0].toLowerCase();
        if (protocol === 'tcp6') protocol = 'tcp';
        if (protocol === 'udp6') protocol = 'udp';
        
        const isUdpUnconn = protocol === 'udp' && (parts[1] || '').toUpperCase() === 'UNCONN'; // Check for Linux UDP "UNCONN" state
        let pidPartIndex = isUdpUnconn ? 6 : 6; // Account for different column structure with UNCONN

        if (parts.length >= (isUdpUnconn ? 5 : 6) ) { // Min parts for UNCONN is 5 (proto, Recv-Q, Send-Q, Local, Foreign) vs 6 for TCP (proto, R, S, L, F, State)
           connection = {
            protocol: protocol.toUpperCase(),
            recvQ: isUdpUnconn ? parts[2] : parts[1], 
            sendQ: isUdpUnconn ? parts[3] : parts[2],
            localAddress: isUdpUnconn ? parts[4] : parts[3],
            foreignAddress: isUdpUnconn ? parts[5] : parts[4],
            state: isUdpUnconn ? 'UNCONN' : (parts[5] || 'UNKNOWN'),
            // PID parsing can be tricky if program name has spaces
            pid: parts.slice(pidPartIndex).join(' ').replace(/-$/, '').trim() || null, 
            raw: line,
            format: 'linux'
          };
        }
      } else if (detectedFormat === 'macos') {
        let protocol = parts[0].toUpperCase();
        if (protocol.startsWith('TCP') || protocol.startsWith('UDP')) { 
            if (protocol.length > 3) protocol = protocol.substring(0,3); 
        }

        // macOS parsing can be complex, especially with IPv6 and varying columns
        // This is a simplified approach
        let localAddressIndex = 3;
        let foreignAddressIndex = 4;
        let stateIndex = 5;
        let pidPartIndex = -1; // Not always reliable or present in same way as Linux/Win
        
        // Adjust indices if Recv-Q/Send-Q are missing for some protocols/states
        if (parts[1] && parts[1].includes(':') || parts[1] && parts[1].includes('.')) { // Likely localAddress is earlier if no Recv-Q/Send-Q
             localAddressIndex = 1;
             foreignAddressIndex = 2;
             stateIndex = 3;
        } else if (parts[2] && parts[2].includes(':') || parts[2] && parts[2].includes('.')){ // if parts[1] is Recv-Q
             localAddressIndex = 2;
             foreignAddressIndex = 3;
             stateIndex = 4;
        }


        let state = parts[stateIndex] || (protocol === 'UDP' ? '' : 'UNKNOWN');
        // Try to find PID if it's the last part and numeric
        let potentialPid = parts[parts.length -1];
        if (potentialPid && /^\d+$/.test(potentialPid)) {
            pidPartIndex = parts.length -1;
            // if state was captured by PID, reset state
            if (state === potentialPid && protocol === 'TCP') state = 'UNKNOWN'; // A common misparse
        }


        connection = {
            protocol: protocol,
            recvQ: localAddressIndex > 1 ? parts[1] : undefined, 
            sendQ: localAddressIndex > 2 ? parts[2] : undefined,
            localAddress: parts[localAddressIndex], 
            foreignAddress: parts[foreignAddressIndex],
            state: state, 
            pid: pidPartIndex !== -1 ? parts[pidPartIndex] : null,
            raw: line,
            format: 'macos'
        };
      } else { 
        if (parts.length >= 4) { 
          connection = {
            protocol: parts[0].toUpperCase(),
            localAddress: parts[1],
            foreignAddress: parts[2],
            state: parts[3] || 'UNKNOWN',
            pid: parts[4] || null,
            raw: line,
            format: 'generic'
          };
        }
      }
      
      if (connection) {
        if (/^(TCP|UDP)$/i.test(connection.protocol)) {
            connections.push({ ...connection, risk: 'safe', issues: [], recommendations: [] });
        }
      }
    }
    return { connections, format: detectedFormat };
  }, []);

  const wellKnownPorts: Record<string, WellKnownPortDetail> = useMemo(() => ({
    '1': { name: 'TCPMUX', risk: 'critical', description: 'TCP Port Service Multiplexer (TCPMUX). Historic IANA assignment (TCP: Yes, UDP: Assigned). Rarely used legitimately; exposure can indicate misconfiguration or be an exploit vector.' },
    '7': { name: 'Echo', risk: 'unknown', description: 'Echo Protocol (TCP/UDP: Yes). Used for testing network connectivity. Can be abused for DDoS amplification (UDP).' },
    '9': { name: 'Discard', risk: 'unknown', description: 'Discard Protocol (TCP/UDP: Yes). Discards any data received. Can be abused for DDoS amplification (UDP CHARGEN/Discard). Some systems use UDP 9 for Wake-on-LAN (Unofficial).' },
    '13': { name: 'Daytime', risk: 'unknown', description: 'Daytime Protocol (TCP/UDP: Yes). Returns current date and time. Minor information disclosure risk.' },
    '19': { name: 'CHARGEN', risk: 'warning', description: 'Character Generator Protocol (TCP/UDP: Yes). Generates a stream of characters. Can be abused for DDoS amplification (UDP CHARGEN/Discard).' },
    '20': { name: 'FTP Data', risk: 'suspicious', description: 'File Transfer Protocol (FTP) Data Transfer (TCP: Yes, UDP: Assigned). Unencrypted data channel for FTP.' },
    '21': { name: 'FTP Control', risk: 'suspicious', description: 'File Transfer Protocol (FTP) Control/Command (TCP: Yes, UDP: Assigned). Unencrypted, transmits credentials in plaintext.' },
    '22': { name: 'SSH', risk: 'safe', description: 'Secure Shell (SSH) (TCP: Yes, UDP: Assigned). Encrypted remote login, file transfer (scp, sftp), and port forwarding.' },
    '23': { name: 'Telnet', risk: 'critical', description: 'Telnet (TCP: Yes, UDP: Assigned). Unencrypted text communications, including credentials. Highly insecure.' },
    '25': { name: 'SMTP', risk: 'warning', description: 'Simple Mail Transfer Protocol (SMTP) (TCP: Yes, UDP: Assigned). Used for email routing. Often unencrypted by default, can be abused for spam if open relay.' },
    '53': { name: 'DNS', risk: 'safe', description: 'Domain Name System (DNS) (TCP/UDP: Yes). Essential for resolving hostnames to IP addresses.' },
    '67': { name: 'BOOTP Server / DHCP', risk: 'safe', description: 'Bootstrap Protocol (BOOTP) Server / Dynamic Host Configuration Protocol (DHCP) (UDP: Yes). Used for assigning IP addresses and network configuration. Typically internal.' },
    '68': { name: 'BOOTP Client / DHCP', risk: 'safe', description: 'Bootstrap Protocol (BOOTP) Client / Dynamic Host Configuration Protocol (DHCP) (UDP: Yes). Used by clients to obtain IP addresses. Typically internal.' },
    '69': { name: 'TFTP', risk: 'warning', description: 'Trivial File Transfer Protocol (TFTP) (UDP: Yes). Simplified file transfer, no authentication. Often used for network booting or device configuration. Can be a security risk if exposed.' },
    '79': { name: 'Finger', risk: 'warning', description: 'Finger Protocol (TCP/UDP: Yes). Provides information about users on a system. Can disclose sensitive user information.' },
    '80': { name: 'HTTP', risk: 'warning', description: 'Hypertext Transfer Protocol (HTTP) (TCP: Yes, UDP: Yes for QUIC/HTTP3). Unencrypted web traffic. Vulnerable to eavesdropping and modification.' },
    '109': { name: 'POP2', risk: 'warning', description: 'Post Office Protocol version 2 (POP2) (TCP: Yes, UDP: Assigned). Older email retrieval protocol, often unencrypted.' },
    '110': { name: 'POP3', risk: 'warning', description: 'Post Office Protocol version 3 (POP3) (TCP: Yes, UDP: Assigned). Email retrieval, transmits credentials and messages in plaintext if not secured (use POP3S on 995).' },
    '111': { name: 'RPC Portmapper', risk: 'warning', description: 'ONC RPC (Portmapper/sunrpc) (TCP/UDP: Yes). Maps RPC services to ports. Can be queried to enumerate RPC services, potentially exposing vulnerabilities if services are insecure.' },
    '113': { name: 'Ident/Auth', risk: 'unknown', description: 'Identification Protocol (Ident) / Authentication Service (Auth) (TCP: Yes). Used by some services (e.g., IRC) to identify user of a connection. Can be spoofed or blocked.' },
    '123': { name: 'NTP', risk: 'safe', description: 'Network Time Protocol (NTP) (UDP: Yes). Used for time synchronization. Essential for logging and security systems. Can be abused for DDoS amplification if server is misconfigured.' },
    '135': { name: 'MS RPC EPMAP', risk: 'suspicious', description: 'Microsoft RPC Endpoint Mapper (EPMAP / DCE/RPC Locator) (TCP/UDP: Yes). Used by Windows services (DHCP, DNS, WINS, DCOM). Historically vulnerable and targeted if exposed externally.' },
    '137': { name: 'NetBIOS-NS', risk: 'suspicious', description: 'NetBIOS Name Service (TCP/UDP: Yes). Used for name registration and resolution in NetBIOS networks. Can leak system information and be targeted.' },
    '138': { name: 'NetBIOS-DGM', risk: 'suspicious', description: 'NetBIOS Datagram Service (UDP: Yes). Connectionless NetBIOS communication. Part of legacy Windows networking, often targeted.' },
    '139': { name: 'NetBIOS-SSN', risk: 'suspicious', description: 'NetBIOS Session Service (TCP: Yes). Used for connection-oriented NetBIOS services like file/printer sharing over SMB. Often targeted with SMB vulnerabilities.' },
    '143': { name: 'IMAP', risk: 'warning', description: 'Internet Message Access Protocol (IMAP) (TCP: Yes, UDP: Assigned). Email management on server. Transmits credentials/messages in plaintext if not secured (use IMAPS on 993).' },
    '161': { name: 'SNMP', risk: 'warning', description: 'Simple Network Management Protocol (SNMP) (UDP: Yes). Used for network device management. Default community strings (public/private) are a major risk if exposed.' },
    '162': { name: 'SNMPTRAP', risk: 'warning', description: 'Simple Network Management Protocol Trap (SNMPTRAP) (TCP/UDP: Yes). Used for devices to send unsolicited alerts to an SNMP manager. Ensure traps do not contain sensitive data if exposed.' },
    '389': { name: 'LDAP', risk: 'warning', description: 'Lightweight Directory Access Protocol (LDAP) (TCP/UDP: Yes). Used for accessing directory services. Can transmit data unencrypted; use LDAPS on 636.' },
    '443': { name: 'HTTPS', risk: 'safe', description: 'Hypertext Transfer Protocol Secure (HTTPS) (TCP: Yes, UDP: Yes for QUIC/HTTP3). Encrypted web communication using TLS/SSL.' },
    '445': { name: 'Microsoft-DS (SMB)', risk: 'suspicious', description: 'Microsoft Directory Services / Server Message Block (SMB) (TCP: Yes, UDP: Assigned). Used for file/printer sharing, Active Directory. Historically vulnerable (e.g., WannaCry, NotPetya) if exposed, especially to the internet.' },
    '465': { name: 'SMTPS (Implicit TLS)', risk: 'safe', description: 'Authenticated SMTP over TLS/SSL (URL Rendezvous Directory for Cisco SSM / Message Submission over TLS) (TCP: Yes). Secure email submission. Preferred over STARTTLS on port 587 by some clients.' },
    '500': { name: 'ISAKMP/IKE', risk: 'warning', description: 'Internet Security Association and Key Management Protocol (ISAKMP) / Internet Key Exchange (IKE) (UDP: Yes). Used for VPN key exchange (IPsec). Ensure strong ciphers and keys.' },
    '512': { name: 'rexec / comsat', risk: 'critical', description: 'Remote Process Execution (rexec) (TCP: Yes) / comsat biff client (UDP: Yes). Rexec is highly insecure. Comsat notifies users of new mail.' },
    '513': { name: 'rlogin / Who', risk: 'critical', description: 'Remote Login (rlogin) (TCP: Yes) / Who service (UDP: Yes). Rlogin is highly insecure. Who provides list of logged-in users.' },
    '514': { name: 'rsh / Syslog', risk: 'critical', description: 'Remote Shell (rsh/remsh) (TCP: Unofficial) / Syslog (UDP: Yes). Rsh is highly insecure. Syslog is used for system logging; UDP syslog can be spoofed.' },
    '515': { name: 'LPD', risk: 'warning', description: 'Line Printer Daemon (LPD) (TCP: Yes, UDP: Assigned). Network print service. Can be exploited if misconfigured.' },
    '548': { name: 'AFP', risk: 'warning', description: 'Apple Filing Protocol (AFP) (TCP: Yes, UDP: Assigned). File sharing for macOS. Ensure strong authentication and limit exposure.' },
    '587': { name: 'SMTP Submission (STARTTLS)', risk: 'safe', description: 'Email Message Submission (SMTP with STARTTLS) (TCP: Yes, UDP: Assigned). Standard port for email clients to submit mail to a server, typically secured with STARTTLS.' },
    '631': { name: 'IPP / CUPS', risk: 'warning', description: 'Internet Printing Protocol (IPP) (TCP/UDP: Yes). Used for network printing (e.g., CUPS). Ensure administrative interfaces are secured.' },
    '636': { name: 'LDAPS', risk: 'safe', description: 'Lightweight Directory Access Protocol over TLS/SSL (LDAPS) (TCP: Yes, UDP: Assigned). Secure directory access.' },
    '990': { name: 'FTPS Control', risk: 'safe', description: 'FTP over TLS/SSL (FTPS) Control (TCP: Yes). Secure (encrypted) FTP control channel.' },
    '992': { name: 'TelnetS', risk: 'warning', description: 'Telnet over TLS/SSL (TCP: Yes). Encrypted Telnet. While better than Telnet, SSH is generally preferred.' },
    '993': { name: 'IMAPS', risk: 'safe', description: 'Internet Message Access Protocol over TLS/SSL (IMAPS) (TCP: Yes, UDP: Assigned). Secure email management.' },
    '995': { name: 'POP3S', risk: 'safe', description: 'Post Office Protocol 3 over TLS/SSL (POP3S) (TCP: Yes). Secure email retrieval.' },
    '1080': { name: 'SOCKS Proxy', risk: 'warning', description: 'SOCKS Proxy (TCP: Yes). Network proxy protocol. Can be misused if open or misconfigured.' },
    '1433': { name: 'MSSQL Server', risk: 'suspicious', description: 'Microsoft SQL Server (MSSQL) Server (TCP/UDP: Yes). Database service. Critical target if exposed; ensure strong authentication, patching, and network restrictions.' },
    '1434': { name: 'MSSQL Monitor', risk: 'warning', description: 'Microsoft SQL Server (MSSQL) Monitor (UDP: Yes). Used to discover SQL Server instances. Can reveal information about database servers.' },
    '1723': { name: 'PPTP', risk: 'suspicious', description: 'Point-to-Point Tunneling Protocol (PPTP) (TCP/UDP: Yes). VPN protocol with known security weaknesses. Avoid if possible; use stronger VPN protocols like IPsec or OpenVPN.' },
    '3306': { name: 'MySQL', risk: 'warning', description: 'MySQL Database System (TCP/UDP: Yes). Database service. Ensure strong passwords, network restrictions, and regular patching.' },
    '3389': { name: 'RDP / WBT', risk: 'suspicious', description: 'Remote Desktop Protocol (RDP) / Windows Based Terminal (WBT) (TCP/UDP: Yes). Often targeted for unauthorized access if exposed, especially to the internet. Secure with VPN, strong passwords, MFA, and Network Level Authentication.' },
    '5060': { name: 'SIP', risk: 'warning', description: 'Session Initiation Protocol (SIP) (TCP/UDP: Yes). Used for VoIP signaling. Can be targeted for toll fraud or denial of service if unsecured.' },
    '5061': { name: 'SIPS', risk: 'safe', description: 'Session Initiation Protocol over TLS (SIPS) (TCP: Yes). Secure VoIP signaling.' },
    '5353': { name: 'mDNS', risk: 'unknown', description: 'Multicast DNS (mDNS) (UDP: Yes). Used for zero-configuration service discovery on local networks (e.g., Bonjour, Avahi). Generally safe on trusted networks but can leak host information.' },
    '5432': { name: 'PostgreSQL', risk: 'warning', description: 'PostgreSQL Database (TCP/UDP: Yes). Database service. Ensure strong passwords, network restrictions, and regular patching.' },
    '5900': { name: 'VNC', risk: 'suspicious', description: 'Virtual Network Computing (VNC) / Remote Frame Buffer (RFB) (TCP: Yes). Remote desktop, often unencrypted or weakly secured by default. Ensure strong passwords or use VNC over SSH.' },
    '5938': { name: 'TeamViewer', risk: 'warning', description: 'TeamViewer Remote Desktop (UDP: Unofficial). Remote desktop software. Ensure legitimate use, strong passwords, and 2FA. Manage unattended access carefully.' },
    '6379': { name: 'Redis', risk: 'warning', description: 'Redis Key-Value Store (TCP: Yes). In-memory data store. Ensure proper authentication (Redis 6+) and network configuration; can be exploited if exposed unauthenticated.' },
    '8080': { name: 'HTTP Alternate', risk: 'warning', description: 'HTTP Alternate (often used for web proxies or secondary web servers) (TCP: Yes). Similar risks to HTTP (Port 80) if unencrypted. Common for application servers like Tomcat.' },
    '27017': { name: 'MongoDB', risk: 'warning', description: 'MongoDB Database (TCP: Unofficial). NoSQL database. Ensure proper authentication, network configuration, and authorization; historically found exposed.' },
    '61000': { name: 'Expected Operational Port', risk: 'safe', description: 'Often used by specific applications for operational purposes. Verify its use aligns with expected software behavior on your system.' } 
  }), []);

  const extractIPPort = useCallback((address: string): [string | null, string | null] => {
    if (!address || address === '*' || address === '*.*' || address === '0.0.0.0:*' || address === '[::]:*') {
        return [address === '*.*' ? '*' : address.replace(':*', ''), null];
    }
    
    // Improved IPv6 parsing
    const ipv6Match = address.match(/^\[(.+)\]:(\*|\d+|[a-zA-Z0-9_-]+)$/);
    if (ipv6Match) {
        const ip = ipv6Match[1];
        const port = ipv6Match[2];
        if (port === '*' || isNaN(parseInt(port))) { // Handle '*' or service name
            const knownServicePort = Object.entries(wellKnownPorts).find(([_,val]) => val.name.toLowerCase() === port.toLowerCase());
            return [ip, knownServicePort ? knownServicePort[0] : (port === '*' ? null : port)]; // Keep service name if not number
        }
        return [ip, port];
    }
    
    // IPv4 and others
    const parts = address.split(':');
    if (parts.length > 1) { // Standard IP:Port or Hostname:Port
        const portCandidate = parts[parts.length - 1];
        const ipCandidate = parts.slice(0, -1).join(':');

        if (portCandidate === '*' || isNaN(parseInt(portCandidate))) {
             const knownServicePort = Object.entries(wellKnownPorts).find(([_,val]) => val.name.toLowerCase() === portCandidate.toLowerCase());
             return [ipCandidate || address, knownServicePort ? knownServicePort[0] : (portCandidate === '*' ? null : portCandidate)];
        }
        return [ipCandidate || address, portCandidate];
    }

    // Fallback for cases like "hostname.servicename" or just "servicename" or just "portnumber"
    // This part tries to separate IP/hostname from port/service based on last dot if port is not numeric
    const lastDotIndex = address.lastIndexOf('.');
    if (lastDotIndex > 0 && lastDotIndex < address.length -1) {
        const potentialIp = address.substring(0, lastDotIndex);
        const potentialPortOrService = address.substring(lastDotIndex + 1);
        
        if (isNaN(parseInt(potentialPortOrService))) { // It's a service name
            const knownServicePort = Object.entries(wellKnownPorts).find(([_,val]) => val.name.toLowerCase() === potentialPortOrService.toLowerCase());
            if (knownServicePort) return [potentialIp, knownServicePort[0]];
            return [address, null]; // Cannot determine port if service name not known
        } else { // It's a numeric port
            return [potentialIp, potentialPortOrService];
        }
    }

    // If address is just a number (port) or just a service name
    if (isNaN(parseInt(address))) {
        const knownServicePort = Object.entries(wellKnownPorts).find(([_,val]) => val.name.toLowerCase() === address.toLowerCase());
        return ['*', knownServicePort ? knownServicePort[0] : address]; // Use '*' for IP, keep service name
    } else {
        return ['*', address]; // Use '*' for IP
    }
  }, [wellKnownPorts]);


  const isPublicIP = useCallback((ip: string | null): boolean => {
    if (!ip || ip === '*' || ip === '0.0.0.0' || ip === '::') return false;
    
    const privateRanges = [
      /^10\./, /^172\.(1[6-9]|2[0-9]|3[01])\./, /^192\.168\./,
      /^127\./, /^169\.254\./,
      /^::1$/, /^fe80:/i, /^fc00:/i, /^fd00:/i,
      /^localhost$/i
    ];
    return !privateRanges.some(range => range.test(ip));
  }, []);


  const analyzeConnections = useCallback((connections: Connection[], format: string): AnalysisResults => {
    const results: AnalysisResults = {
      totalConnections: connections.length,
      format: format,
      listeningPorts: [],
      localServicesOnLoopback: [],
      suspiciousConnections: [],
      establishedConnections: [],
      warnings: [],
      summary: { safe: 0, warning: 0, suspicious: 0, critical: 0 },
      portAnalysis: {}, 
      ipAnalysis: {},
      recommendations: [],
      allLocalPortsActivity: [],
      allForeignPortsActivity: []
    };

    const localPortAgg: Record<string, DetailedPortUsageStats> = {};
    const foreignPortAgg: Record<string, DetailedPortUsageStats> = {};
    const localServicesMap: Map<string, LocalServiceDetail> = new Map();
    const threatIntelIssueMessage = "Connection involves an IP with validated Cyber Threat Intel.";

    connections.forEach(conn => {
      const analysis: Connection = { ...conn, risk: 'safe', issues: [], recommendations: [] };

      const [localIP, localPort] = extractIPPort(conn.localAddress);
      const [foreignIP, foreignPort] = extractIPPort(conn.foreignAddress);
      
      analysis.localAddress = `${localIP || '*'}:${localPort || '*'}`;
      analysis.foreignAddress = `${foreignIP || '*'}:${foreignPort || '*'}`;

      // Check against custom threat intelligence
      const localThreatMatch = localIP ? checkIpAgainstThreatIntel(localIP) : null;
      const foreignThreatMatch = foreignIP ? checkIpAgainstThreatIntel(foreignIP) : null;

      if (localThreatMatch) {
        analysis.risk = localThreatMatch.severity === 'low' ? 'warning' :
                       localThreatMatch.severity === 'medium' ? 'suspicious' : 'critical';
        const threatMessage = `Threat Intel Match (Local): ${localIP} - ${localThreatMatch.description || 'Known threat'} (${localThreatMatch.severity} severity, Source: ${localThreatMatch.source})`;
        if (!analysis.issues.includes(threatMessage)) {
            analysis.issues.push(threatMessage);
        }
      }
      if (foreignThreatMatch) {
        const threatRisk = foreignThreatMatch.severity === 'low' ? 'warning' :
                          foreignThreatMatch.severity === 'medium' ? 'suspicious' : 'critical';
        if (riskOrderGlobal.indexOf(threatRisk) < riskOrderGlobal.indexOf(analysis.risk)) {
          analysis.risk = threatRisk;
        }
        const threatMessage = `Threat Intel Match (Foreign): ${foreignIP} - ${foreignThreatMatch.description || 'Known threat'} (${foreignThreatMatch.severity} severity, Source: ${foreignThreatMatch.source})`;
        if (!analysis.issues.includes(threatMessage)) {
            analysis.issues.push(threatMessage);
        }
      }

      // Populate Local Services on Loopback (127.0.0.1)
      let serviceTargetPort: string | null = null;
      let serviceTargetProtocol: string | null = null;
      let isLoopbackServiceActivity = false;

      if (localIP === '127.0.0.1' && localPort && (conn.state === 'LISTEN' || conn.state === 'LISTENING')) {
        serviceTargetPort = localPort;
        serviceTargetProtocol = conn.protocol;
        isLoopbackServiceActivity = true;
      } else if (foreignIP === '127.0.0.1' && foreignPort && localIP === '127.0.0.1') { // Ensure the connection is purely local for this category
        serviceTargetPort = foreignPort; // If local is connecting to local
        serviceTargetProtocol = conn.protocol;
        isLoopbackServiceActivity = true;
      }


      if (isLoopbackServiceActivity && serviceTargetPort && serviceTargetProtocol) {
        const key = `${serviceTargetPort}-${serviceTargetProtocol}`;
        if (!localServicesMap.has(key)) {
          const wkPortInfo = wellKnownPorts[serviceTargetPort];
          localServicesMap.set(key, {
            port: serviceTargetPort,
            protocol: serviceTargetProtocol,
            serviceName: wkPortInfo?.name || 'Unknown',
            description: wkPortInfo?.description || 'Local service on loopback interface.',
            risk: wkPortInfo?.risk || 'unknown',
            associatedPids: [],
            connectionCount: 0,
            rawExampleLines: [],
            aiInsight: null,
            isFetchingAiInsight: false,
          });
        }
        const serviceDetail = localServicesMap.get(key)!;
        serviceDetail.connectionCount++;
        if (conn.pid && conn.pid.trim() !== '' && !serviceDetail.associatedPids?.includes(conn.pid)) {
          serviceDetail.associatedPids?.push(conn.pid.trim());
        }
        if (serviceDetail.rawExampleLines.length < 3) { // Store a few raw lines for context
            serviceDetail.rawExampleLines.push(conn.raw.trim());
        }
         // Inherit risk from well-known ports for local services
        const wkPortInfo = wellKnownPorts[serviceTargetPort];
        if (wkPortInfo && riskOrderGlobal.indexOf(wkPortInfo.risk) < riskOrderGlobal.indexOf(serviceDetail.risk)) {
            serviceDetail.risk = wkPortInfo.risk;
        }
      }


      if (localPort) {
        const key = `${localPort}:${conn.protocol}`;
        if (!localPortAgg[key]) {
          const wkPortInfo = wellKnownPorts[localPort];
          localPortAgg[key] = {
            port: localPort,
            protocol: conn.protocol,
            service: wkPortInfo?.name || 'Unknown',
            count: 0,
            risk: wkPortInfo?.risk || 'unknown',
            description: wkPortInfo?.description || 'No specific description for this port.'
          };
        }
        localPortAgg[key].count++;
        const currentWkRisk = wellKnownPorts[localPort]?.risk || 'unknown';
        if (riskOrderGlobal.indexOf(currentWkRisk) < riskOrderGlobal.indexOf(localPortAgg[key].risk)) {
            localPortAgg[key].risk = currentWkRisk;
        }
      }

      if (foreignPort) {
        const key = `${foreignPort}:${conn.protocol}`;
        if (!foreignPortAgg[key]) {
          const wkPortInfo = wellKnownPorts[foreignPort];
          foreignPortAgg[key] = {
            port: foreignPort,
            protocol: conn.protocol,
            service: wkPortInfo?.name || 'Unknown',
            count: 0,
            risk: wkPortInfo?.risk || 'unknown',
            description: wkPortInfo?.description || 'No specific description for this port.'
          };
        }
        foreignPortAgg[key].count++;
        const currentWkRisk = wellKnownPorts[foreignPort]?.risk || 'unknown';
         if (riskOrderGlobal.indexOf(currentWkRisk) < riskOrderGlobal.indexOf(foreignPortAgg[key].risk)) {
            foreignPortAgg[key].risk = currentWkRisk;
        }
      }

      if (localPort && wellKnownPorts[localPort]) {
        const portInfo = wellKnownPorts[localPort];
        analysis.portInfo = portInfo;
        const portRisk = portInfo.risk;
        if (riskOrderGlobal.indexOf(portRisk) < riskOrderGlobal.indexOf(analysis.risk)) {
          analysis.risk = portRisk;
        }
        if (portRisk !== 'safe' && portRisk !== 'unknown') {
             analysis.issues.push(`${portRisk.charAt(0).toUpperCase() + portRisk.slice(1)} risk service on local port ${localPort}: ${portInfo.name} (${portInfo.description}).`);
        }
      }
      
      const state = conn.state.toUpperCase();
      let isListener = false;
      let listenerSpecificRisk = analysis.risk; 

      const connProtocolUpper = conn.protocol.toUpperCase();
      if (connProtocolUpper === 'TCP') {
        if (state === 'LISTEN' || state === 'LISTENING') {
          isListener = true;
        }
      } else if (connProtocolUpper === 'UDP') {
        // For UDP, a listener might not have a foreign address or state, or state is empty/unknown.
        // Or if foreign address is wildcard like '*:*'
        const fa = conn.foreignAddress.toUpperCase(); 
        if (localPort && (fa === '*:*' || fa === '*' || fa.endsWith(':*') || state === '' || state === 'UNKNOWN' || state === 'UNCONN')) {
          isListener = true;
          if (localPort && wellKnownPorts[localPort]) {
             const portInfoRisk = wellKnownPorts[localPort].risk;
             if (riskOrderGlobal.indexOf(portInfoRisk) < riskOrderGlobal.indexOf(listenerSpecificRisk)) {
                 listenerSpecificRisk = portInfoRisk;
             }
          }
        }
      }

      if (isListener) {
        // This logic is for traditional listening ports, not the new local services tab specifically.
        // It correctly identifies services listening on any interface.
        if (localIP && (localIP === '0.0.0.0' || localIP === '::' || localIP === '*')) {
          if (listenerSpecificRisk === 'safe') {
            listenerSpecificRisk = 'warning';
          }
          const allInterfacesIssue = `Service on port ${localPort || 'unknown'} is listening on all interfaces (${localIP}). Ensure this is intentional and firewalled appropriately.`;
          if (!analysis.issues.some(issue => issue.includes("all interfaces"))) {
            analysis.issues.push(allInterfacesIssue);
          }
        }
        
        if (riskOrderGlobal.indexOf(listenerSpecificRisk) < riskOrderGlobal.indexOf(analysis.risk)) {
            analysis.risk = listenerSpecificRisk;
        }
        
        const localThreatMatch = localIP ? checkIpAgainstThreatIntel(localIP) : null;
        const threatRisk = localThreatMatch ?
          (localThreatMatch.severity === 'low' ? 'warning' :
           localThreatMatch.severity === 'medium' ? 'suspicious' : 'critical') : null;
        const finalListenerPortRisk = threatRisk && riskOrderGlobal.indexOf(threatRisk) < riskOrderGlobal.indexOf(analysis.risk) ? threatRisk : analysis.risk;

        results.listeningPorts.push({
          port: localPort,
          service: wellKnownPorts[localPort]?.name || (localPort && !isNaN(parseInt(localPort)) ? 'Unknown' : localPort || 'Unknown'), // Use port as service if name unknown
          risk: finalListenerPortRisk, 
          address: conn.localAddress, 
          protocol: conn.protocol
        });

      } else if (state === 'ESTABLISHED') {
        results.establishedConnections.push(conn); 
        const foreignThreatMatch = foreignIP ? checkIpAgainstThreatIntel(foreignIP) : null;
        if (foreignIP && isPublicIP(foreignIP) && !foreignThreatMatch) {
          if (analysis.risk === 'safe') analysis.risk = 'warning';
          analysis.issues.push(`Established connection to public IP: ${foreignIP}:${foreignPort}. Verify legitimacy.`);
        }
        if (foreignPort && wellKnownPorts[foreignPort] && !foreignThreatMatch) {
            const foreignPortInfo = wellKnownPorts[foreignPort];
            if (foreignPortInfo.risk === 'critical' || foreignPortInfo.risk === 'suspicious') {
                 if (riskOrderGlobal.indexOf(foreignPortInfo.risk) < riskOrderGlobal.indexOf(analysis.risk)) {
                     analysis.risk = foreignPortInfo.risk;
                 }
                 analysis.issues.push(`Connected to a ${foreignPortInfo.risk} risk service on remote port ${foreignPort}: ${foreignPortInfo.name}. This could be an outbound connection to a compromised or risky service.`);
            }
        }
      } else if (['SYN_SENT', 'SYN_RECV'].includes(state)) {
        if (analysis.risk === 'safe' || analysis.risk === 'warning') { 
            analysis.risk = 'suspicious';
        }
        analysis.issues.push(`Connection in potentially unstable state: ${state}. Could indicate scanning, connection attempts, or network issues.`);
      }
      
      if (foreignIP && foreignIP !== '*' && foreignIP !== '0.0.0.0' && foreignIP !== '::') {
        if (!results.ipAnalysis[foreignIP]) {
          const foreignThreatMatch = checkIpAgainstThreatIntel(foreignIP);
          const threatRisk = foreignThreatMatch ?
            (foreignThreatMatch.severity === 'low' ? 'warning' :
             foreignThreatMatch.severity === 'medium' ? 'suspicious' : 'critical') : null;
          const initialRisk = threatRisk || (isPublicIP(foreignIP) && analysis.risk === 'safe' ? 'warning' : analysis.risk);

          results.ipAnalysis[foreignIP] = {
            ip: foreignIP,
            connections: 0,
            ports: new Set<string | null>(),
            isPublic: isPublicIP(foreignIP),
            risk: initialRisk
          };
        }
        const ipDetail = results.ipAnalysis[foreignIP];
        ipDetail.connections++;
        ipDetail.ports.add(foreignPort);

        const foreignThreatMatch = checkIpAgainstThreatIntel(foreignIP);
        if (foreignThreatMatch) {
          const threatRisk = foreignThreatMatch.severity === 'low' ? 'warning' :
                            foreignThreatMatch.severity === 'medium' ? 'suspicious' : 'critical';
          if (riskOrderGlobal.indexOf(threatRisk) < riskOrderGlobal.indexOf(ipDetail.risk)) {
            ipDetail.risk = threatRisk;
          }
        } else if (riskOrderGlobal.indexOf(analysis.risk) < riskOrderGlobal.indexOf(ipDetail.risk)) {
          ipDetail.risk = analysis.risk;
        }
      }
      if (localIP && localIP !== '*' && localIP !== '0.0.0.0' && localIP !== '::' && !/^127\./.test(localIP) && !/^fe80:/i.test(localIP) && !isListener) {
        if (!results.ipAnalysis[localIP]) {
            const localThreatMatch = checkIpAgainstThreatIntel(localIP);
            const threatRisk = localThreatMatch ?
              (localThreatMatch.severity === 'low' ? 'warning' :
               localThreatMatch.severity === 'medium' ? 'suspicious' : 'critical') : null;

            results.ipAnalysis[localIP] = {
                ip: localIP,
                connections: 0,
                ports: new Set<string | null>(),
                isPublic: isPublicIP(localIP),
                risk: threatRisk || analysis.risk
            };
        }
        results.ipAnalysis[localIP].connections++;
        results.ipAnalysis[localIP].ports.add(localPort);

        const localThreatMatch = checkIpAgainstThreatIntel(localIP);
        if (localThreatMatch) {
          const threatRisk = localThreatMatch.severity === 'low' ? 'warning' :
                            localThreatMatch.severity === 'medium' ? 'suspicious' : 'critical';
          if (riskOrderGlobal.indexOf(threatRisk) < riskOrderGlobal.indexOf(results.ipAnalysis[localIP].risk)) {
            results.ipAnalysis[localIP].risk = threatRisk;
          }
        } else if (riskOrderGlobal.indexOf(analysis.risk) < riskOrderGlobal.indexOf(results.ipAnalysis[localIP].risk)) {
          results.ipAnalysis[localIP].risk = analysis.risk;
        }
      }
      
      // Final risk assessment already handled by individual threat intel checks above
      if (analysis.issues.length > 0 && analysis.risk === 'safe') {
        analysis.risk = 'warning';
      }
      
      results.summary[analysis.risk]++;

      if (analysis.risk !== 'safe') {
        results.suspiciousConnections.push(analysis);
      }
    });
    
    results.listeningPorts.sort((a, b) => {
        return riskOrderGlobal.indexOf(a.risk) - riskOrderGlobal.indexOf(b.risk) || (parseInt(a.port || "0") - parseInt(b.port || "0"));
    });
    
    results.suspiciousConnections.sort((a,b) => {
        const riskDiff = riskOrderGlobal.indexOf(a.risk) - riskOrderGlobal.indexOf(b.risk);
        if (riskDiff !== 0) return riskDiff;
        const [, portA] = extractIPPort(a.localAddress);
        const [, portB] = extractIPPort(b.localAddress);
        return (parseInt(portA || "0") - parseInt(portB || "0"));
    });

    results.allLocalPortsActivity = Object.values(localPortAgg).sort((a, b) => {
        const riskDiff = riskOrderGlobal.indexOf(a.risk) - riskOrderGlobal.indexOf(b.risk);
        if (riskDiff !== 0) return riskDiff;
        return b.count - a.count;
    });
    results.allForeignPortsActivity = Object.values(foreignPortAgg).sort((a, b) => {
        const riskDiff = riskOrderGlobal.indexOf(a.risk) - riskOrderGlobal.indexOf(b.risk);
        if (riskDiff !== 0) return riskDiff;
        return b.count - a.count;
    });

    results.localServicesOnLoopback = Array.from(localServicesMap.values()).sort((a,b) => {
      const riskDiff = riskOrderGlobal.indexOf(a.risk) - riskOrderGlobal.indexOf(b.risk);
      if (riskDiff !== 0) return riskDiff;
      return (parseInt(a.port || "0") - parseInt(b.port || "0"));
    });


    generateRecommendations(results, wellKnownPorts);
    return results;
  }, [extractIPPort, isPublicIP, wellKnownPorts]);

  const generateRecommendations = (results: AnalysisResults, localWellKnownPorts: Record<string, WellKnownPortDetail>) => {
    const recommendations: Recommendation[] = [];

    const criticalThreatIntelConnections = results.suspiciousConnections.filter(conn =>
        conn.issues.some(issue => issue.includes("Threat Intel Match"))
    );
    if (criticalThreatIntelConnections.length > 0) {
        const threatIPs = [...new Set(criticalThreatIntelConnections.map(c => {
            const [lIP] = extractIPPort(c.localAddress);
            const [fIP] = extractIPPort(c.foreignAddress);
            const localThreat = lIP ? checkIpAgainstThreatIntel(lIP) : null;
            const foreignThreat = fIP ? checkIpAgainstThreatIntel(fIP) : null;
            return localThreat ? lIP : fIP;
        }).filter(Boolean))];

        recommendations.push({
            type: 'critical',
            title: 'Block Connections to Known Malicious IPs',
            description: `Detected ${criticalThreatIntelConnections.length} connection(s) involving IPs on threat intelligence lists. These connections pose an immediate and severe risk. Block these IPs at your firewall immediately. Investigate systems involved for signs of compromise. IPs: ${threatIPs.join(', ')}`,
            services: [...new Set(criticalThreatIntelConnections.map(c => c.portInfo?.name || c.protocol))].join(', ')
        });
    }
    
    const highRiskListening = results.listeningPorts.filter(p => {
      const [ip] = extractIPPort(p.address);
      const threatMatch = ip ? checkIpAgainstThreatIntel(ip) : null;
      return ['critical', 'suspicious'].includes(p.risk) && !threatMatch;
    });
    if (highRiskListening.length > 0) {
      recommendations.push({
        type: 'critical',
        title: 'Secure or Disable High-Risk Listening Services (External Exposure)',
        description: `Found ${highRiskListening.length} high-risk services potentially exposed externally: ${highRiskListening.map(p => `${p.service} (Port ${p.port || 'N/A'}) on ${p.address}`).join(', ')}. Review their necessity. If essential, ensure they are firewalled, patched, and configured securely.`,
        services: highRiskListening.map(p => p.service).join(', ')
      });
    }

    const unencryptedServices = results.listeningPorts.filter(p => 
      p.port && (localWellKnownPorts[p.port]?.name === 'FTP' || localWellKnownPorts[p.port]?.name === 'Telnet' || localWellKnownPorts[p.port]?.name === 'HTTP')
    );
    if (unencryptedServices.length > 0) {
      recommendations.push({
        type: 'warning',
        title: 'Unencrypted Listening Services Detected',
        description: `Unencrypted services like ${unencryptedServices.map(p => `${p.service} (Port ${p.port || 'N/A'}) on ${p.address}`).join(', ')} transmit data in plaintext. Upgrade to secure alternatives if exposed.`,
        services: unencryptedServices.map(p => p.service).join(', ')
      });
    }
    
    const externalConnectionsCount = Object.values(results.ipAnalysis).filter(ip => {
      const threatMatch = checkIpAgainstThreatIntel(ip.ip);
      return ip.isPublic && !threatMatch;
    }).length;
    if (externalConnectionsCount > 10) { 
      recommendations.push({
        type: 'warning',
        title: 'Monitor Numerous External Connections',
        description: `Detected ${externalConnectionsCount} unique external IP addresses (excluding known threats). While not inherently malicious, a high number of external connections warrants monitoring. Ensure all are legitimate and expected. Investigate any unfamiliar IPs.`
      });
    }
    
    const servicesOnAllInterfaces = results.listeningPorts.filter(p => {
        const [ip] = extractIPPort(p.address);
        const threatMatch = ip ? checkIpAgainstThreatIntel(ip) : null;
        return (ip === '0.0.0.0' || ip === '::' || ip === '*') && !threatMatch;
    });
    if (servicesOnAllInterfaces.length > 0) {
        recommendations.push({
            type: 'warning',
            title: 'Services Listening on All Interfaces',
            description: `${servicesOnAllInterfaces.length} service(s) are listening on all network interfaces. This can increase exposure. Ensure this is intentional for services like ${servicesOnAllInterfaces.slice(0,3).map(p=>p.service).join(', ')} and that appropriate firewall rules are in place.`,
            services: servicesOnAllInterfaces.map(p => p.service).join(', ')
        });
    }

    if (results.summary.critical > 0 && criticalThreatIntelConnections.length === 0) { 
         recommendations.unshift({ 
            type: 'critical',
            title: `Address ${results.summary.critical} Critical Risk Item(s) Immediately`,
            description: `There are ${results.summary.critical} item(s) identified as critical risk. These require immediate attention. Review the 'Risky Connections' and 'Listening Ports' or 'Local Services' tabs for details.`
        });
    } else if (results.summary.suspicious > 0) { 
         recommendations.unshift({ 
            type: 'warning', 
            title: `Investigate ${results.summary.suspicious} Suspicious Item(s)`,
            description: `There are ${results.summary.suspicious} item(s) identified as suspicious. Review these in the relevant tabs.`
        });
    }
    
    results.recommendations = recommendations;
  };

  const calculateOverallRiskContext = useCallback((results: AnalysisResults | null): OverallRiskContext | null => {
    if (!results || results.error) return null;

    const { summary, listeningPorts } = results;
    const numCriticalListeners = listeningPorts.filter(p => p.risk === 'critical').length;
    const numSuspiciousListenersOnAllInterfaces = listeningPorts.filter(p =>
      (p.risk === 'critical' || p.risk === 'suspicious') &&
      (extractIPPort(p.address)[0] === '0.0.0.0' || extractIPPort(p.address)[0] === '::' || extractIPPort(p.address)[0] === '*')
    ).length;

    if (summary.critical > 0 || numCriticalListeners > 0) {
      return {
        level: 'critical',
        description: 'CRITICAL RISK',
        colorClass: 'bg-red-600',
        textColorClass: 'text-red-100',
        icon: <ShieldAlert className="w-16 h-16 text-red-100" />,
        detailedMessage: `Immediate attention required. ${summary.critical} critical connections/issues and ${numCriticalListeners} critical listening ports (exposed externally or on all interfaces) identified. These pose a severe threat.`,
        htmlReportBoxClass: 'overall-risk-critical'
      };
    }
    if (summary.suspicious > 3 || numSuspiciousListenersOnAllInterfaces > 0 || listeningPorts.filter(p => p.risk === 'suspicious').length > 2) {
      return {
        level: 'high',
        description: 'HIGH RISK',
        colorClass: 'bg-orange-500',
        textColorClass: 'text-orange-100',
        icon: <ShieldAlert className="w-16 h-16 text-orange-100" />,
        detailedMessage: `High risk profile. ${summary.suspicious} suspicious items or ${numSuspiciousListenersOnAllInterfaces > 0 ? numSuspiciousListenersOnAllInterfaces + " high-risk listeners on all interfaces" : listeningPorts.filter(p => p.risk === 'suspicious').length + " suspicious listening ports"}. Prioritize investigation.`,
        htmlReportBoxClass: 'overall-risk-high'
      };
    }
    if (summary.suspicious > 0 || summary.warning > 5) {
      return {
        level: 'medium',
        description: 'MEDIUM RISK',
        colorClass: 'bg-yellow-500',
        textColorClass: 'text-yellow-800', // Adjusted for better visibility on yellow-500
        icon: <AlertTriangle className="w-16 h-16 text-yellow-800" />,
        detailedMessage: `Medium risk. ${summary.suspicious} suspicious items and ${summary.warning} warnings detected. Review these findings.`,
        htmlReportBoxClass: 'overall-risk-medium'
      };
    }
    if (summary.warning > 0) {
      return {
        level: 'low',
        description: 'LOW RISK',
        colorClass: 'bg-yellow-400', 
        textColorClass: 'text-yellow-700',
        icon: <ShieldCheck className="w-16 h-16 text-yellow-700" />,
        detailedMessage: `Low risk. ${summary.warning} warnings identified. Review for optimal security hygiene.`,
        htmlReportBoxClass: 'overall-risk-low'
      };
    }
    return {
      level: 'minimal',
      description: 'MINIMAL RISK',
      colorClass: 'bg-green-500',
      textColorClass: 'text-green-100',
      icon: <ShieldCheck className="w-16 h-16 text-green-100" />,
      detailedMessage: 'Minimal risk detected based on the provided netstat data. Continue good security practices.',
      htmlReportBoxClass: 'overall-risk-minimal'
    };
  }, [extractIPPort]);


  useEffect(() => {
    if (latestAnalysisResults) {
      setOverallRiskContextState(calculateOverallRiskContext(latestAnalysisResults));
    } else {
      setOverallRiskContextState(null);
    }
  }, [latestAnalysisResults, calculateOverallRiskContext]);

  // Load current API key when settings tab is opened
  useEffect(() => {
    if (activeTab === 'settings' && !tempApiKey) {
      setTempApiKey(userApiKey);
    }
  }, [activeTab, userApiKey, tempApiKey]);


  const analyzeFile = useCallback(async () => {
    if (!file) return;
    setIsAnalyzing(true);
    setExpandedIssues({});
    setAiInsights(null); 
    setAiPortAnalysis(null);
    setAiLocalServiceInsights({});
    setIsFetchingAiLocalServiceInsights({});
    setOverviewPortActivityDataState([]); 
    setExpandedOverviewPortIPs({});
    setRiskMatrixFilterRisk('all');
    setRiskMatrixSearchTerm('');
    setAiRiskMatrixCellInsights({});
    setIsFetchingAiRiskMatrixCellInsights({});
    
    try {
      const content = await file.text();
      const { connections, format } = parseNetstatData(content);
      let results: AnalysisResults;

      if (connections.length === 0) {
        results = { 
          error: 'No valid netstat data found. Please ensure the file contains proper netstat output (e.g., from `netstat -an`, `ss -tulpn`). Check for empty lines or incorrect formatting. The parser might have skipped all lines if they did not match expected connection patterns.',
          totalConnections: 0, format: format, listeningPorts: [], localServicesOnLoopback: [], suspiciousConnections: [], establishedConnections: [], warnings: [], summary: { safe: 0, warning: 0, suspicious: 0, critical: 0 }, portAnalysis: {}, ipAnalysis: {}, recommendations: [], allLocalPortsActivity: [], allForeignPortsActivity: []
        };
      } else {
        results = analyzeConnections(connections, format);
      }
      
      const newHistoricalEntry: HistoricalAnalysis = {
        id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
        name: file.name,
        timestamp: new Date(),
        results: results,
      };

      setHistoricalAnalyses(prev => [...prev, newHistoricalEntry]);
      setLatestAnalysisResults(results);
      clearCurrentFileSelection(); 

    } catch (error) {
      console.error('Error analyzing file:', error);
      const errorResults: AnalysisResults = { 
        error: `Failed to analyze file. Ensure it's a plain text netstat output. Error: ${error instanceof Error ? error.message : String(error)}`,
        totalConnections: 0, format: 'unknown', listeningPorts: [], localServicesOnLoopback: [], suspiciousConnections: [], establishedConnections: [], warnings: [], summary: { safe: 0, warning: 0, suspicious: 0, critical: 0 }, portAnalysis: {}, ipAnalysis: {}, recommendations: [], allLocalPortsActivity: [], allForeignPortsActivity: []
      };
      setLatestAnalysisResults(errorResults); 
       const erroredHistoricalEntry: HistoricalAnalysis = { 
        id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
        name: file.name + " (Error)",
        timestamp: new Date(),
        results: errorResults,
      };
      setHistoricalAnalyses(prev => [...prev, erroredHistoricalEntry]);
      clearCurrentFileSelection();
    }
    setIsAnalyzing(false);
  }, [file, parseNetstatData, analyzeConnections]); 


  const loadSnapshot = (snapshotId: string) => {
    const snapshot = historicalAnalyses.find(h => h.id === snapshotId);
    if (snapshot) {
      setLatestAnalysisResults(snapshot.results);
      setAiInsights(null); 
      setAiPortAnalysis(null);
      setAiLocalServiceInsights({});
      setIsFetchingAiLocalServiceInsights({});
      setOverviewPortActivityDataState([]); 
      setExpandedOverviewPortIPs({});
      setRiskMatrixFilterRisk('all');
      setRiskMatrixSearchTerm('');
      setAiRiskMatrixCellInsights({});
      setIsFetchingAiRiskMatrixCellInsights({});
      setActiveTab('overallRisk'); 
    }
  };

  const removeSnapshot = (snapshotId: string) => {
    setHistoricalAnalyses(prev => prev.filter(h => h.id !== snapshotId));
    if (latestAnalysisResults && historicalAnalyses.find(h => h.id === snapshotId)?.results === latestAnalysisResults) {
      const remainingAnalyses = historicalAnalyses.filter(h => h.id !== snapshotId);
      if (remainingAnalyses.length > 0) {
        setLatestAnalysisResults(remainingAnalyses[remainingAnalyses.length - 1].results);
      } else {
        setLatestAnalysisResults(null);
        setOverviewPortActivityDataState([]);
      }
      setAiInsights(null);
      setAiPortAnalysis(null);
      setAiLocalServiceInsights({});
      setIsFetchingAiLocalServiceInsights({});
      setExpandedOverviewPortIPs({});
      setRiskMatrixFilterRisk('all');
      setRiskMatrixSearchTerm('');
      setAiRiskMatrixCellInsights({});
      setIsFetchingAiRiskMatrixCellInsights({});
    }
  };


  const fetchAiInsights = async () => {
    if (!latestAnalysisResults || !ai || !effectiveApiKey) {
      setAiInsights("AI insights cannot be generated. Ensure analysis is complete and API key is configured.");
      return;
    }
    setIsFetchingAiInsights(true);
    setAiInsights(null);

    const { summary, recommendations, listeningPorts, suspiciousConnections, totalConnections } = latestAnalysisResults;

    const criticalListening = listeningPorts.filter(p => p.risk === 'critical').map(p => `${p.service} (Port ${p.port || 'N/A'}, ${p.protocol} on ${p.address})`);
    const suspiciousListening = listeningPorts.filter(p => p.risk === 'suspicious').map(p => `${p.service} (Port ${p.port || 'N/A'}, ${p.protocol} on ${p.address})`);

    let prompt = `You are a cybersecurity assistant. Based on the following netstat analysis summary, provide a concise security briefing (around 150-250 words). 
Explain the overall security posture, highlight the 2-3 most important issues, and suggest general preventative measures. Format your response clearly with paragraphs.

Analysis Summary:
- Total Connections: ${totalConnections}
- Critical Risks Identified: ${summary.critical}
- Suspicious Risks Identified: ${summary.suspicious}
- Warnings Issued: ${summary.warning}

Key System Recommendations Provided:
${recommendations.slice(0, 3).map(rec => `- ${rec.title}: ${rec.description.substring(0,100)}...`).join('\n')}

Notable Externally Exposed Listening Ports:
- Critical Risk Ports: ${criticalListening.length > 0 ? criticalListening.join(', ') : 'None identified'}
- Suspicious Risk Ports: ${suspiciousListening.length > 0 ? suspiciousListening.join(', ') : 'None identified'}

Top 3 Riskiest Connections (if any, sorted by severity):
${suspiciousConnections
  .sort((a,b) => {
    const riskOrderInternal: RiskLevel[] = ['critical', 'suspicious', 'warning', 'safe', 'unknown'];
    return riskOrderInternal.indexOf(a.risk) - riskOrderInternal.indexOf(b.risk);
  })
  .slice(0,3)
  .map(c => `- ${c.protocol} ${c.localAddress} to ${c.foreignAddress} (State: ${c.state}, Risk: ${c.risk}, Issues: ${c.issues.join('. ').substring(0,100)}...)`)
  .join('\n') || 'No specific high-risk connections to highlight here.'}

Provide your briefing:`;

    try {
      const response: GenerateContentResponse = await ai.models.generateContent({
        model: 'gemini-2.5-flash-preview-04-17',
        contents: prompt,
      });
      setAiInsights(response.text);
    } catch (error) {
      console.error("Error fetching AI insights:", error);
      setAiInsights(`Failed to generate AI insights. ${error instanceof Error ? error.message : "An unknown error occurred."} Please ensure your API key is correctly configured and the Gemini API is accessible.`);
    } finally {
      setIsFetchingAiInsights(false);
    }
  };
  
  const fetchAiPortAnalysis = async () => {
    if (!latestAnalysisResults || !ai) {
        setAiPortAnalysis("AI port analysis requires completed analysis and API key.");
        return;
    }
    setIsFetchingAiPortAnalysis(true);
    setAiPortAnalysis(null);

    const { listeningPorts } = latestAnalysisResults; // These are externally exposed listeners
    if (listeningPorts.length === 0) {
        setAiPortAnalysis("No externally exposed listening ports found to analyze for this general overview. Check 'Local Services' for 127.0.0.1 activity.");
        setIsFetchingAiPortAnalysis(false);
        return;
    }

    const portDetails = listeningPorts.map(p => 
        `- Port ${p.port || 'N/A'} (${p.protocol}, Service: ${p.service}, Risk: ${p.risk}, Address: ${p.address}, Description: ${p.port && wellKnownPorts[p.port] ? wellKnownPorts[p.port].description : 'N/A'})`
    ).join('\n');

    const prompt = `You are a network security analyst. Based on the following list of *externally exposed* listening ports from a netstat output, provide a concise analysis (around 150-200 words).
Focus on:
1. Identifying the 2-3 most concerning ports/services from a security perspective (considering their exposure) and briefly explain why.
2. Commenting on the overall "port hygiene" regarding these exposed services (e.g., risky defaults, unencrypted services, services on all interfaces).
3. Offering 1-2 general security best practices for managing these *exposed* open ports.

Exposed Listening Ports:
${portDetails}

Provide your analysis:`;

    try {
        const response: GenerateContentResponse = await ai.models.generateContent({
            model: 'gemini-2.5-flash-preview-04-17',
            contents: prompt,
        });
        setAiPortAnalysis(response.text);
    } catch (error) {
        console.error("Error fetching AI port analysis:", error);
        setAiPortAnalysis(`Failed to generate AI port analysis. ${error instanceof Error ? error.message : "An unknown error occurred."}`);
    } finally {
        setIsFetchingAiPortAnalysis(false);
    }
  };


  const fetchAiLocalServiceIdentity = async (service: LocalServiceDetail) => {
    if (!ai || !effectiveApiKey || !latestAnalysisResults) {
      const key = `${service.port}-${service.protocol}`;
      setAiLocalServiceInsights(prev => ({...prev, [key]: "AI analysis requires API key and loaded results."}));
      return;
    }
    const key = `${service.port}-${service.protocol}`;
    setIsFetchingAiLocalServiceInsights(prev => ({...prev, [key]: true}));
    setAiLocalServiceInsights(prev => ({...prev, [key]: null}));

    const exampleLines = service.rawExampleLines.length > 0 ? service.rawExampleLines.join('\n') : 'No specific raw netstat lines captured for this aggregated service.';
    const osFormat = latestAnalysisResults.format || 'unknown';

    const prompt = `You are a system utility and cybersecurity expert. A netstat analysis on a user's machine shows activity involving local port ${service.port}/${service.protocol} (Service Name: ${service.serviceName}) on the loopback interface (127.0.0.1).
${service.connectionCount} connection(s) were observed involving this local service.
Associated PIDs from netstat lines (could be client or server PIDs): ${service.associatedPids && service.associatedPids.length > 0 ? service.associatedPids.join(', ') : 'None captured'}
Example netstat lines involving this port:
${exampleLines}

The netstat output format appears to be from a ${osFormat} system.

Based on this information:
1. What common applications or services typically use port ${service.port}/${service.protocol} on 127.0.0.1? (Mention a few examples if applicable)
2. What is the general purpose of such services? (e.g., local web server, database, IPC, browser helper)
3. Are there any common misconfigurations or security considerations for services running locally on this port, even if only on loopback? (e.g., default credentials, vulnerabilities in the local software, potential for abuse by local malware)
4. If this port activity is unexpected by the user, what general steps could they take to investigate what's using it on their ${osFormat} system? (Suggest 1-2 commands like \`lsof -i :${service.port}\` or \`netstat -abno\` with findstr for Windows, or Task Manager/Resource Monitor checks).

Provide a concise, helpful explanation, structured with clear points.`;

    try {
        const response: GenerateContentResponse = await ai.models.generateContent({
            model: 'gemini-2.5-flash-preview-04-17',
            contents: prompt,
        });
        setAiLocalServiceInsights(prev => ({...prev, [key]: response.text}));
    } catch (error) {
        console.error(`Error fetching AI local service identity for ${key}:`, error);
        setAiLocalServiceInsights(prev => ({...prev, [key]: `Failed to generate AI insights for ${service.port}/${service.protocol}. ${error instanceof Error ? error.message : "An unknown error occurred."}`}));
    } finally {
        setIsFetchingAiLocalServiceInsights(prev => ({...prev, [key]: false}));
    }
  };


  const fetchAiIpReputation = async (ipAddress: string, ipDetail?: IPAnalysisDetail) => {
    if (!ai) { 
        setAiIpInsights(prev => ({...prev, [ipAddress]: "AI IP analysis requires API key."}));
        return;
    }
    setIsFetchingAiIpInsights(prev => ({...prev, [ipAddress]: true}));
    setAiIpInsights(prev => ({...prev, [ipAddress]: null}));

    let foreignPorts = "N/A";
    let localPortDetailsForContext = "N/A"; 
    let foreignPortServices = "N/A";

    const targetIpDetail = ipDetail || (latestAnalysisResults?.ipAnalysis && latestAnalysisResults.ipAnalysis[ipAddress]);

    if (targetIpDetail) {
        foreignPorts = Array.from(targetIpDetail.ports).join(', ') || 'N/A';
        foreignPortServices = Array.from(targetIpDetail.ports).map(p => {
            if (p) {
                const serviceName = wellKnownPorts[p] ? wellKnownPorts[p].name : 'Unknown Service';
                return `Port ${p} (${serviceName})`;
            }
            return 'Port N/A (Unknown Service)';
        }).join(', ') || 'N/A';
    }
    
    if (latestAnalysisResults) {
        const relatedConnections = latestAnalysisResults.establishedConnections
            .concat(latestAnalysisResults.suspiciousConnections)
            .filter(c => {
                const [forIP] = extractIPPort(c.foreignAddress); 
                return forIP === ipAddress; 
            });

        localPortDetailsForContext = relatedConnections.map(c => {
            const [, localPort] = extractIPPort(c.localAddress);
            const serviceName = localPort && wellKnownPorts[localPort] ? wellKnownPorts[localPort].name : 'Unknown Service';
            return `Port ${localPort || 'N/A'} on your system (${serviceName})`;
        }).filter((value, index, self) => self.indexOf(value) === index).join(', ') || 'N/A';
    }


    const prompt = `Provide a security and reputation analysis for the IP address: ${ipAddress}.

This IP was observed in network connections.
Context from the local system's perspective (if available):
- The local system connected TO this IP address (${ipAddress}) on these remote ports: ${foreignPorts} (services: ${foreignPortServices}).
- These connections originated FROM the following local ports on the system: ${localPortDetailsForContext}.

Using Google Search for up-to-date information, please provide:
1.  Geolocation (City, Country). If the IP is geolocated to China or Russia, explicitly state this and note that connections to/from these regions often warrant heightened scrutiny due to geopolitical factors and potential state-sponsored activities. Consider this a significant factor towards a 'suspicious' or 'warning' assessment in your overall analysis unless strong mitigating evidence is present for this specific IP.
2.  ASN (Autonomous System Number) and ISP.
3.  Any known malicious activity, or if it's listed on common blocklists (mention sources if possible).
4.  General reputation (e.g., known cloud provider, CDN, residential, Tor exit node, etc.).
5.  Based on the ports involved (if known), its geolocation, and general reputation, are there specific security concerns for a system having connected to this IP?

Keep the response concise and well-structured with clear headings for each point.`;

    try {
        const response: GenerateContentResponse = await ai.models.generateContent({
            model: "gemini-2.5-flash-preview-04-17",
            contents: prompt,
            config: {
                tools: [{googleSearch: {}}],
            },
        });
        let insightText = response.text;
        const groundingChunks = response.candidates?.[0]?.groundingMetadata?.groundingChunks;
        if (groundingChunks && groundingChunks.length > 0) {
            insightText += "\n\nInformation Sources (from Google Search):";
            groundingChunks.forEach(chunk => {
                if(chunk.web) {
                    insightText += `\n- ${chunk.web.title}: ${chunk.web.uri}`;
                }
            });
        }
        setAiIpInsights(prev => ({...prev, [ipAddress]: insightText}));
    } catch (error) {
        console.error(`Error fetching AI IP reputation for ${ipAddress}:`, error);
        setAiIpInsights(prev => ({...prev, [ipAddress]: `Failed to generate AI insights for ${ipAddress}. ${error instanceof Error ? error.message : "An unknown error occurred."}`}));
    } finally {
        setIsFetchingAiIpInsights(prev => ({...prev, [ipAddress]: false}));
    }
  };

  const fetchAiPortContextualAnalysis = async (portData: OverviewPortActivityData) => {
    if (!ai || !effectiveApiKey) {
        const updatedData = overviewPortActivityDataState.map(p => 
            p.listenerAddress === portData.listenerAddress && p.protocol === portData.protocol && p.port === portData.port
            ? { ...p, aiContextualInsight: "AI analysis requires API key.", isFetchingAiContextualInsight: false }
            : p
        );
        setOverviewPortActivityDataState(updatedData);
        return;
    }

    setOverviewPortActivityDataState(prevData => prevData.map(p => 
        p.listenerAddress === portData.listenerAddress && p.protocol === portData.protocol && p.port === portData.port
        ? { ...p, isFetchingAiContextualInsight: true, aiContextualInsight: null }
        : p
    ));

    const connectedIpContext = portData.connectedIpDetails.map(ipInfo => 
        `- IP: ${ipInfo.ip} (${ipInfo.isPublic ? 'Public' : 'Private'}), Connections: ${ipInfo.connectionCountToPort}, States: ${ipInfo.states.join(', ')}, Assessed Risk from this IP to port: ${ipInfo.risk}`
    ).join('\n');

    const prompt = `You are a cybersecurity analyst. Analyze the following listening port based on its context:

Port: ${portData.port} (${portData.protocol})
Service: ${portData.service} (${portData.description})
Risk Assessed by Tool for this Listening Port: ${portData.risk}
Listening Address: ${portData.listenerAddress} (Note: This is an EXTERNALLY exposed listener, not 127.0.0.1)

This port has ${portData.activeInboundConnectionsCount} active inbound connections from ${portData.connectedIpDetails.length} unique IP addresses:
${portData.connectedIpDetails.length > 0 ? connectedIpContext : "No active inbound connections observed."}

Based on this information:
1.  Briefly explain the typical legitimate use of the ${portData.service} service on port ${portData.port}/${portData.protocol} when exposed externally.
2.  What are the common security concerns or vulnerabilities associated with this service/port, especially when exposed via ${portData.listenerAddress}?
3.  Considering it's listening on "${portData.listenerAddress}" and the list of connected IPs (note their public/private status, connection counts, and states), what is your assessment of the current security posture for this specific port? Highlight any specific IPs or connection patterns that are noteworthy or suspicious.
4.  Provide 2-3 actionable recommendations to secure this port and service in this specific context. If an IP or pattern is particularly risky, mention it.

Keep your analysis concise, structured, and actionable (around 200-300 words). Format with clear paragraphs or bullet points for readability.`;

    try {
        const response: GenerateContentResponse = await ai.models.generateContent({
            model: 'gemini-2.5-flash-preview-04-17',
            contents: prompt,
        });
        setOverviewPortActivityDataState(prevData => prevData.map(p => 
            p.listenerAddress === portData.listenerAddress && p.protocol === portData.protocol && p.port === portData.port
            ? { ...p, aiContextualInsight: response.text, isFetchingAiContextualInsight: false }
            : p
        ));
    } catch (error) {
        console.error(`Error fetching AI contextual analysis for port ${portData.port}:`, error);
        const errorMsg = `Failed to generate AI analysis for port ${portData.port}. ${error instanceof Error ? error.message : "An unknown error occurred."}`;
        setOverviewPortActivityDataState(prevData => prevData.map(p => 
             p.listenerAddress === portData.listenerAddress && p.protocol === portData.protocol && p.port === portData.port
            ? { ...p, aiContextualInsight: errorMsg, isFetchingAiContextualInsight: false }
            : p
        ));
    }
};

const fetchAiRiskMatrixCellInsight = async (cell: RiskMatrixCell) => {
    if (!ai || !effectiveApiKey) {
        setAiRiskMatrixCellInsights(prev => ({...prev, [cell.id]: "AI analysis requires API key."}));
        return;
    }
    setIsFetchingAiRiskMatrixCellInsights(prev => ({...prev, [cell.id]: true}));
    setAiRiskMatrixCellInsights(prev => ({...prev, [cell.id]: null}));

    const osFormat = latestAnalysisResults?.format || 'unknown';
    const aggregatedPIDsString = Array.from(cell.aggregatedPIDs).join(', ') || 'N/A';

    const prompt = `You are a network security analyst. An aggregated network interaction from a ${osFormat} system's netstat output shows the following:

- Local Endpoint: ${cell.localAddress} (IP: ${cell.localIP || 'N/A'}, Port: ${cell.localPort || 'N/A'})
- Foreign Endpoint: ${cell.foreignAddress} (IP: ${cell.foreignIP || 'N/A'}, Port: ${cell.foreignPort || 'N/A'})
- Protocol: ${cell.protocol}
- Overall Assessed Risk for this interaction: ${cell.risk}
- Number of individual connections aggregated: ${cell.connectionCount}
- Observed Connection States: ${Array.from(cell.states).join(', ')}
- Aggregated PIDs involved (if any): ${aggregatedPIDsString}
- Key Issues noted for connections in this group: ${cell.issues.length > 0 ? cell.issues.join('; ') : 'None specifically noted for the group.'}
- This interaction represents a local listening port: ${cell.isListenerInteraction ? 'Yes' : 'No'}

Based on this aggregated information:
1. What does this specific interaction pattern (Local &harr; Foreign) potentially signify? Consider the protocol, ports, states, and if it's a listener.
2. Why might this aggregated interaction be flagged with a "${cell.risk}" risk level? Explain based on the provided details.
3. If this interaction is concerning, what are 1-2 specific investigation steps a user could take on their ${osFormat} system, particularly considering the aggregated PIDs (${aggregatedPIDsString}) and the nature of the communication?
4. Are there any immediate security recommendations based *solely* on this aggregated interaction cell's data?

Keep your response concise and focused on this specific interaction pair.`;

    try {
        const response: GenerateContentResponse = await ai.models.generateContent({
            model: 'gemini-2.5-flash-preview-04-17',
            contents: prompt,
        });
        setAiRiskMatrixCellInsights(prev => ({...prev, [cell.id]: response.text}));
    } catch (error) {
        console.error(`Error fetching AI insight for risk matrix cell ${cell.id}:`, error);
        setAiRiskMatrixCellInsights(prev => ({...prev, [cell.id]: `Failed to generate AI insights for this interaction. ${error instanceof Error ? error.message : "An unknown error occurred."}`}));
    } finally {
        setIsFetchingAiRiskMatrixCellInsights(prev => ({...prev, [cell.id]: false}));
    }
};

  const escapeHtml = (unsafe: string | null | undefined): string => {
    if (unsafe === null || typeof unsafe === 'undefined') return '';
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
  };

  const getRiskHtmlBadge = (risk: RiskLevel): string => {
    const riskBadgeClasses: Record<RiskLevel, string> = {
      critical: 'badge-critical',
      suspicious: 'badge-suspicious',
      warning: 'badge-warning',
      safe: 'badge-safe',
      unknown: 'badge-unknown',
    };
    return `<span class="badge ${riskBadgeClasses[risk] || 'badge-unknown'}">${escapeHtml(risk.charAt(0).toUpperCase() + risk.slice(1))}</span>`;
  };

  const getRiskColorClassForHtml = (risk: RiskLevel): string => {
    const riskColorClasses: Record<RiskLevel, string> = {
        critical: 'risk-critical-text',
        suspicious: 'risk-suspicious-text',
        warning: 'risk-warning-text',
        safe: 'risk-safe-text',
        unknown: 'risk-unknown-text',
    };
    return riskColorClasses[risk] || 'risk-unknown-text';
  };


  const generateHtmlReportContent = (
    results: AnalysisResults, 
    overallRiskCtx: OverallRiskContext | null,
    fileNameInput: string | null
  ): string => {
    const reportDate = new Date().toLocaleString();
    const currentFilename = fileNameInput || historicalAnalyses.find(h => h.results === results)?.name || 'N/A';
    
    // Top 5 or fewer items
    const topRecommendations = results.recommendations.slice(0, 5);
    const topListeningPorts = results.listeningPorts
        .filter(p => ['critical', 'suspicious', 'warning'].includes(p.risk))
        .sort((a,b) => riskOrderGlobal.indexOf(a.risk) - riskOrderGlobal.indexOf(b.risk))
        .slice(0, 5);
    const topSuspiciousConnections = results.suspiciousConnections
        .sort((a,b) => riskOrderGlobal.indexOf(a.risk) - riskOrderGlobal.indexOf(b.risk))
        .slice(0, 5);
    const criticalIpConnections = results.suspiciousConnections.filter(conn => conn.issues.some(issue => issue.includes("Cyber Threat Intel")));

    const inlineCss = `
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol"; line-height: 1.6; color: #333; margin: 0; padding: 0; background-color: #f4f7f6; }
    .container { max-width: 900px; margin: 20px auto; background-color: #fff; padding: 25px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
    h1, h2, h3 { color: #2c3e50; margin-top: 0; }
    h1 { font-size: 2em; border-bottom: 2px solid #3498db; padding-bottom: 10px; margin-bottom: 20px; text-align: center;}
    h2 { font-size: 1.6em; border-bottom: 1px solid #eee; padding-bottom: 8px; margin-top: 30px; margin-bottom: 15px; color: #3498db; }
    h3 { font-size: 1.3em; margin-top: 25px; margin-bottom: 10px; color: #2980b9; }
    p { margin-bottom: 10px; }
    ul, ol { margin-bottom: 15px; padding-left: 20px; }
    li { margin-bottom: 5px; }
    .badge { display: inline-block; padding: 0.25em 0.6em; font-size: 0.8em; font-weight: 600; line-height: 1; text-align: center; white-space: nowrap; vertical-align: baseline; border-radius: 0.375rem; color: #fff; }
    .badge-critical { background-color: #e74c3c; }
    .badge-suspicious { background-color: #f39c12; }
    .badge-warning { background-color: #f1c40f; color: #333; }
    .badge-safe { background-color: #2ecc71; }
    .badge-unknown { background-color: #95a5a6; }
    .section { margin-bottom: 25px; padding: 15px; border: 1px solid #e0e0e0; border-radius: 5px; background-color: #fdfdfd; }
    .recommendation { border-left-width: 4px; border-left-style: solid; padding: 10px 15px; margin-bottom: 10px; border-radius: 4px; background-color: #f9f9f9;}
    .recommendation-critical { border-left-color: #e74c3c; }
    .recommendation-warning { border-left-color: #f1c40f; }
    .recommendation-title { font-weight: bold; margin-bottom: 5px; }
    .monospace { font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace; font-size: 0.9em; background-color: #f0f0f0; padding: 2px 4px; border-radius: 3px; word-break: break-all; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 0.9em;}
    th { background-color: #f2f2f2; font-weight: bold; }
    .risk-critical-text { color: #c0392b; font-weight: bold; }
    .risk-suspicious-text { color: #d35400; font-weight: bold; }
    .risk-warning-text { color: #b7950b; } /* Darker yellow for text */
    .risk-safe-text { color: #27ae60; }
    .risk-unknown-text { color: #7f8c8d; }
    .overall-risk-box { padding: 20px; margin-bottom: 20px; border-radius: 5px; text-align: center; color: #fff; }
    .overall-risk-critical { background-color: #e74c3c; }
    .overall-risk-high { background-color: #f39c12; }
    .overall-risk-medium { background-color: #f1c40f; color: #333; }
    .overall-risk-low { background-color: #2ecc71; }
    .overall-risk-minimal { background-color: #1abc9c; }
    .overall-risk-description { font-size: 1.8em; font-weight: bold; margin-bottom: 10px; }
    .overall-risk-message { font-size: 1em; }
    .footer { text-align: center; margin-top: 30px; font-size: 0.9em; color: #777; }
    .meta-info { text-align: center; font-size: 0.9em; color: #555; margin-bottom: 20px; }
    .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px;}
    .summary-item { background-color: #f9f9f9; padding: 15px; border-radius: 5px; border: 1px solid #eee; text-align: center;}
    .summary-item .value { font-size: 1.5em; font-weight: bold; display: block; margin-bottom: 5px; }
    .summary-item .label { font-size: 0.9em; color: #555; }
    .value-critical { color: #e74c3c; }
    .value-suspicious { color: #f39c12; }
    .value-warning { color: #f1c40f; }
    .value-safe { color: #2ecc71; }
    .value-total { color: #3498db; }
    `;

    return `
      <!DOCTYPE html>
      <html lang="en">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Netstat Analysis Report - ${escapeHtml(currentFilename)}</title>
          <style>${inlineCss}</style>
      </head>
      <body>
          <div class="container">
              <h1>Netstat Security Analyzer - Report</h1>
              <div class="meta-info">
                  <p><strong>Report Generated:</strong> ${escapeHtml(reportDate)}</p>
                  <p><strong>Original File:</strong> ${escapeHtml(currentFilename)}</p>
                  <p><strong>Detected OS Format:</strong> ${escapeHtml(results.format.toUpperCase())}</p>
              </div>

              ${overallRiskCtx ? `
              <div class="section overall-risk-box ${escapeHtml(overallRiskCtx.htmlReportBoxClass || '')}">
                  <div class="overall-risk-description">${escapeHtml(overallRiskCtx.description)}</div>
                  <div class="overall-risk-message">${escapeHtml(overallRiskCtx.detailedMessage)}</div>
              </div>
              ` : '<p class="section">Overall risk assessment not available.</p>'}

              <div class="section">
                  <h2>Analysis Summary</h2>
                  <div class="summary-grid">
                      <div class="summary-item">
                          <span class="value value-total">${results.totalConnections}</span>
                          <span class="label">Total Connections</span>
                      </div>
                      <div class="summary-item">
                          <span class="value value-critical">${results.summary.critical}</span>
                          <span class="label">Critical Issues</span>
                      </div>
                      <div class="summary-item">
                          <span class="value value-suspicious">${results.summary.suspicious}</span>
                          <span class="label">Suspicious Issues</span>
                      </div>
                      <div class="summary-item">
                          <span class="value value-warning">${results.summary.warning}</span>
                          <span class="label">Warnings</span>
                      </div>
                      <div class="summary-item">
                          <span class="value value-safe">${results.summary.safe}</span>
                          <span class="label">Safe Items</span>
                      </div>
                  </div>
              </div>

              ${topRecommendations.length > 0 ? `
              <div class="section">
                  <h2>Top Security Recommendations</h2>
                  ${topRecommendations.map(rec => `
                      <div class="recommendation recommendation-${rec.type}">
                          <div class="recommendation-title ${getRiskColorClassForHtml(rec.type as RiskLevel)}">${escapeHtml(rec.title)}</div>
                          <p>${escapeHtml(rec.description)}</p>
                          ${rec.services ? `<p><strong>Affected Services:</strong> <span class="monospace">${escapeHtml(rec.services)}</span></p>` : ''}
                      </div>
                  `).join('')}
              </div>
              ` : ''}
              
              ${topListeningPorts.length > 0 ? `
              <div class="section">
                  <h2>Top Risky Externally Exposed Listening Ports</h2>
                  <table>
                      <thead>
                          <tr><th>Risk</th><th>Port/Protocol</th><th>Service</th><th>Address</th><th>Description</th></tr>
                      </thead>
                      <tbody>
                          ${topListeningPorts.map(p => `
                              <tr>
                                  <td>${getRiskHtmlBadge(p.risk)}</td>
                                  <td><span class="monospace">${escapeHtml(p.port)}/${escapeHtml(p.protocol)}</span></td>
                                  <td>${escapeHtml(p.service)}</td>
                                  <td><span class="monospace">${escapeHtml(p.address)}</span></td>
                                  <td>${escapeHtml(p.port && wellKnownPorts[p.port] ? wellKnownPorts[p.port].description : 'N/A')}</td>
                              </tr>
                          `).join('')}
                      </tbody>
                  </table>
              </div>
              ` : '<div class="section"><p>No significantly risky listening ports identified for top listing.</p></div>'}

              ${topSuspiciousConnections.length > 0 ? `
              <div class="section">
                  <h2>Top Risky Connections</h2>
                  <table>
                      <thead>
                          <tr><th>Risk</th><th>Protocol</th><th>Local Address</th><th>Foreign Address</th><th>State</th><th>PID</th><th>Issues</th></tr>
                      </thead>
                      <tbody>
                          ${topSuspiciousConnections.map(c => `
                              <tr>
                                  <td>${getRiskHtmlBadge(c.risk)}</td>
                                  <td>${escapeHtml(c.protocol)}</td>
                                  <td><span class="monospace">${escapeHtml(c.localAddress)}</span></td>
                                  <td><span class="monospace">${escapeHtml(c.foreignAddress)}</span></td>
                                  <td>${escapeHtml(c.state)}</td>
                                  <td><span class="monospace">${escapeHtml(c.pid) || 'N/A'}</span></td>
                                  <td>${escapeHtml(c.issues.slice(0,2).join(', '))} ${c.issues.length > 2 ? '...' : ''}</td>
                              </tr>
                          `).join('')}
                      </tbody>
                  </table>
              </div>
              ` : '<div class="section"><p>No significantly risky connections identified for top listing.</p></div>'}
              
              ${criticalIpConnections.length > 0 ? `
              <div class="section">
                  <h2>Critical Threat Intelligence IP Matches</h2>
                   <p>The following connections involve IPs found on a critical threat intelligence list and require immediate investigation:</p>
                  <table>
                      <thead>
                          <tr><th>Local Address</th><th>Foreign Address</th><th>Protocol</th><th>Details</th></tr>
                      </thead>
                      <tbody>
                          ${criticalIpConnections.map(c => `
                              <tr>
                                  <td><span class="monospace">${escapeHtml(c.localAddress)}</span></td>
                                  <td><span class="monospace">${escapeHtml(c.foreignAddress)}</span></td>
                                  <td>${escapeHtml(c.protocol)}</td>
                                  <td>${escapeHtml(c.issues.find(issue => issue.includes("Cyber Threat Intel")) || 'Critical IP Match')}</td>
                              </tr>
                          `).join('')}
                      </tbody>
                  </table>
              </div>
              ` : ''}

              <div class="footer">
                  <p>This report was automatically generated. For educational and informational purposes only.</p>
                  <p>Netstat Security Analyzer &copy; ${new Date().getFullYear()}</p>
              </div>
          </div>
      </body>
      </html>
    `;
  };

  const exportHtmlReport = () => {
    if (!latestAnalysisResults || latestAnalysisResults.error || !overallRiskContextState) {
        alert("Cannot generate HTML report: No valid analysis results or overall risk context available.");
        return;
    }
    
    const currentFileName = file?.name || historicalAnalyses.find(h => h.results === latestAnalysisResults)?.name || 'report';
    const htmlContent = generateHtmlReportContent(latestAnalysisResults, overallRiskContextState, currentFileName);
    
    const blob = new Blob([htmlContent], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `netstat-analysis-${currentFileName.split('.')[0]}-${new Date().toISOString().split('T')[0]}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const exportReport = () => {
    if (!latestAnalysisResults || latestAnalysisResults.error) return;
    
    const report = {
      timestamp: new Date().toISOString(),
      filename: historicalAnalyses.find(h => h.results === latestAnalysisResults)?.name || file?.name || 'unknown',
      format: latestAnalysisResults.format,
      summary: latestAnalysisResults.summary,
      totalConnections: latestAnalysisResults.totalConnections,
      recommendations: latestAnalysisResults.recommendations,
      listeningPorts: latestAnalysisResults.listeningPorts, // Traditional listeners
      localServicesOnLoopback: latestAnalysisResults.localServicesOnLoopback, // New local services
      allLocalPortsActivity: latestAnalysisResults.allLocalPortsActivity,
      allForeignPortsActivity: latestAnalysisResults.allForeignPortsActivity,
      suspiciousConnections: latestAnalysisResults.suspiciousConnections.map(conn => ({
        protocol: conn.protocol,
        localAddress: conn.localAddress,
        foreignAddress: conn.foreignAddress,
        state: conn.state,
        pid: conn.pid,
        risk: conn.risk,
        issues: conn.issues,
        portInfo: conn.portInfo
      })),
      ipAnalysis: Object.values(latestAnalysisResults.ipAnalysis).map(ip => ({...ip, ports: Array.from(ip.ports)}))
    };
    
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `netstat-analysis-${(historicalAnalyses.find(h => h.results === latestAnalysisResults)?.name || file?.name || 'report').split('.')[0]}-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const getRiskBadge = (risk: RiskLevel | OverallRiskCategory) => {
    const riskStyles: Record<RiskLevel | OverallRiskCategory, { badgeClass: string, icon: JSX.Element, textClass?: string }> = {
      safe: { badgeClass: "border-green-600", icon: <CheckCircle className="w-3 h-3 mr-1 text-green-600" />, textClass: "text-green-700" },
      warning: { badgeClass: "border-yellow-600", icon: <AlertTriangle className="w-3 h-3 mr-1 text-yellow-600" />, textClass: "text-yellow-700" },
      suspicious: { badgeClass: "border-orange-600", icon: <Eye className="w-3 h-3 mr-1 text-orange-600" />, textClass: "text-orange-700" },
      critical: { badgeClass: "bg-red-600 border-red-700", icon: <XCircle className="w-3 h-3 mr-1 text-white" />, textClass: "text-white" },
      unknown: { badgeClass: "border-gray-400", icon: <AlertTriangle className="w-3 h-3 mr-1 text-gray-500" />, textClass: "text-gray-600" },
      minimal: { badgeClass: "border-green-500 bg-green-50", icon: <ShieldCheck className="w-3 h-3 mr-1 text-green-600" />, textClass: "text-green-700 font-semibold" },
      low: { badgeClass: "border-yellow-500 bg-yellow-50", icon: <ShieldCheck className="w-3 h-3 mr-1 text-yellow-600" />, textClass: "text-yellow-700 font-semibold" }, 
      medium: { badgeClass: "border-orange-500 bg-orange-50", icon: <AlertTriangle className="w-3 h-3 mr-1 text-orange-600" />, textClass: "text-orange-700 font-semibold" },
      high: { badgeClass: "border-red-500 bg-red-50", icon: <ShieldAlert className="w-3 h-3 mr-1 text-red-600" />, textClass: "text-red-700 font-semibold" },
    };
    const style = riskStyles[risk] || riskStyles.unknown;
    return (
      <Badge variant={(risk === 'critical' || risk === 'high') ? 'destructive' : 'outline'} className={`${style.badgeClass} ${style.textClass} whitespace-nowrap`}>
        {style.icon}{String(risk).charAt(0).toUpperCase() + String(risk).slice(1)}
      </Badge>
    );
  };
  
  const getRiskColorIndicator = (risk: RiskLevel | OverallRiskCategory): string => {
    const colors: Record<RiskLevel | OverallRiskCategory, string> = {
      safe: 'bg-green-500',
      warning: 'bg-yellow-500',
      suspicious: 'bg-orange-500',
      critical: 'bg-red-600',
      unknown: 'bg-gray-400',
      minimal: 'bg-green-500',
      low: 'bg-yellow-400',
      medium: 'bg-orange-500',
      high: 'bg-red-500' 
    };
    return colors[risk] || colors.unknown;
  };

  const getRiskBarColor = (risk: RiskLevel): string => {
    const colors: Record<RiskLevel, string> = {
      safe: 'bg-green-500',
      warning: 'bg-yellow-400',
      suspicious: 'bg-orange-500',
      critical: 'bg-red-600',
      unknown: 'bg-gray-400'
    };
    return colors[risk] || colors.unknown;
  };


  const toggleIssueExpansion = (id: string) => { // Changed index to id (string) for more robust keying
    setExpandedIssues(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const filteredConnections = useMemo(() => { // For "Risky Connections" tab
    if (!latestAnalysisResults?.suspiciousConnections) return [];
    
    let filtered = latestAnalysisResults.suspiciousConnections;
    
    if (filterRisk !== 'all') {
      filtered = filtered.filter(conn => conn.risk === filterRisk);
    }
    
    if (searchTerm) {
      const lowerSearchTerm = searchTerm.toLowerCase();
      filtered = filtered.filter(conn => 
        conn.localAddress.toLowerCase().includes(lowerSearchTerm) ||
        conn.foreignAddress.toLowerCase().includes(lowerSearchTerm) ||
        conn.protocol.toLowerCase().includes(lowerSearchTerm) ||
        (conn.pid && conn.pid.toLowerCase().includes(lowerSearchTerm)) ||
        (conn.portInfo?.name && conn.portInfo.name.toLowerCase().includes(lowerSearchTerm)) ||
        conn.state.toLowerCase().includes(lowerSearchTerm) ||
        conn.issues.some(issue => issue.toLowerCase().includes(lowerSearchTerm))
      );
    }
    return filtered;
  }, [latestAnalysisResults, filterRisk, searchTerm]);


  const riskMatrixCells = useMemo((): RiskMatrixCell[] => {
    if (!latestAnalysisResults || latestAnalysisResults.error) return [];

    const matrixMap = new Map<string, RiskMatrixCell>();

    const allConnections = [
        ...(latestAnalysisResults.establishedConnections || []),
        ...(latestAnalysisResults.suspiciousConnections || [])
    ].filter((conn, index, self) => // Deduplicate based on raw line to avoid double counting if a connection is in both established and suspicious
        index === self.findIndex(c => c.raw === conn.raw)
    );
    
    allConnections.forEach(conn => {
        const [localIP, localPort] = extractIPPort(conn.localAddress);
        const [foreignIP, foreignPort] = extractIPPort(conn.foreignAddress);
        const id = `${conn.localAddress}-${conn.foreignAddress}-${conn.protocol}`;

        if (!matrixMap.has(id)) {
            matrixMap.set(id, {
                id,
                localAddress: conn.localAddress,
                localIP,
                localPort,
                foreignAddress: conn.foreignAddress,
                foreignIP,
                foreignPort,
                protocol: conn.protocol,
                risk: conn.risk,
                connectionCount: 1,
                states: new Set([conn.state]),
                issues: [...conn.issues],
                aggregatedPIDs: conn.pid ? new Set([conn.pid]) : new Set(),
                isListenerInteraction: false, // Default to false, will be overridden by listener processing
                aiInsight: null,
                isFetchingAiInsight: false,
            });
        } else {
            const entry = matrixMap.get(id)!;
            entry.connectionCount++;
            entry.states.add(conn.state);
            conn.issues.forEach(issue => {
                if (!entry.issues.includes(issue)) entry.issues.push(issue);
            });
            if (conn.pid) {
                entry.aggregatedPIDs.add(conn.pid);
            }
            if (riskOrderGlobal.indexOf(conn.risk) < riskOrderGlobal.indexOf(entry.risk)) {
                entry.risk = conn.risk;
            }
        }
    });
    
    latestAnalysisResults.listeningPorts.forEach(lp => {
        const [localIP, localPort] = extractIPPort(lp.address);
        const foreignAddressGeneric = (lp.protocol === 'UDP' && (lp.address.includes(':') || localIP?.includes(':'))) ? '[::]:*' : '*:*';
        const foreignIPGeneric = (lp.protocol === 'UDP' && (lp.address.includes(':') || localIP?.includes(':'))) ? '::' : '*';
        const id = `${lp.address}-${foreignAddressGeneric}-${lp.protocol}-LISTEN`;

        if (!matrixMap.has(id)) {
            matrixMap.set(id, {
                id,
                localAddress: lp.address,
                localIP,
                localPort,
                foreignAddress: foreignAddressGeneric,
                foreignIP: foreignIPGeneric,
                foreignPort: null, // Listeners don't have a specific foreign port in this context
                protocol: lp.protocol,
                risk: lp.risk,
                connectionCount: 1, 
                states: new Set(['LISTEN']),
                issues: [], 
                aggregatedPIDs: new Set(), // Listeners usually don't have PIDs in the same way active conns do from netstat lines
                isListenerInteraction: true,
                aiInsight: null,
                isFetchingAiInsight: false,
            });
        } else { 
            const entry = matrixMap.get(id)!;
            entry.connectionCount++; 
             if (riskOrderGlobal.indexOf(lp.risk) < riskOrderGlobal.indexOf(entry.risk)) {
                entry.risk = lp.risk;
            }
            entry.isListenerInteraction = true; // Ensure it's marked as listener
        }
    });

    return Array.from(matrixMap.values()).sort((a, b) => {
        const riskDiff = riskOrderGlobal.indexOf(a.risk) - riskOrderGlobal.indexOf(b.risk);
        if (riskDiff !== 0) return riskDiff;
        if (a.isListenerInteraction !== b.isListenerInteraction) return a.isListenerInteraction ? -1 : 1; // Listeners first
        if (a.connectionCount !== b.connectionCount) return b.connectionCount - a.connectionCount; // Higher count first
        if (a.localAddress !== b.localAddress) return a.localAddress.localeCompare(b.localAddress);
        return a.foreignAddress.localeCompare(b.foreignAddress);
    });
}, [latestAnalysisResults, extractIPPort]);

const filteredRiskMatrixCells = useMemo(() => {
    if (!riskMatrixCells) return [];
    let filtered = riskMatrixCells;

    if (riskMatrixFilterRisk !== 'all') {
        filtered = filtered.filter(cell => cell.risk === riskMatrixFilterRisk);
    }

    if (riskMatrixSearchTerm) {
        const lowerSearch = riskMatrixSearchTerm.toLowerCase();
        filtered = filtered.filter(cell =>
            cell.localAddress.toLowerCase().includes(lowerSearch) ||
            cell.foreignAddress.toLowerCase().includes(lowerSearch) ||
            cell.protocol.toLowerCase().includes(lowerSearch) ||
            Array.from(cell.aggregatedPIDs).some(pid => pid.toLowerCase().includes(lowerSearch)) ||
            Array.from(cell.states).some(s => s.toLowerCase().includes(lowerSearch)) ||
            cell.issues.some(issue => issue.toLowerCase().includes(lowerSearch))
        );
    }
    return filtered;
}, [riskMatrixCells, riskMatrixFilterRisk, riskMatrixSearchTerm]);

const riskMatrixSummary = useMemo(() => {
    if (!riskMatrixCells) return { totalPairs: 0, criticalPairs: 0, suspiciousPairs: 0, listenerInteractions: 0 };
    return {
        totalPairs: riskMatrixCells.length,
        criticalPairs: riskMatrixCells.filter(c => c.risk === 'critical').length,
        suspiciousPairs: riskMatrixCells.filter(c => c.risk === 'suspicious').length,
        listenerInteractions: riskMatrixCells.filter(c => c.isListenerInteraction).length,
    };
}, [riskMatrixCells]);


  const portInsightsSummary = useMemo(() => {
    if (!latestAnalysisResults || !latestAnalysisResults.listeningPorts) return null;

    const { listeningPorts } = latestAnalysisResults; // These are traditional listeners
    const riskyOpenPorts = listeningPorts.filter(p => p.risk === 'critical' || p.risk === 'suspicious');
    const unencryptedServices = listeningPorts.filter(p => p.port && (wellKnownPorts[p.port]?.name === 'FTP' || wellKnownPorts[p.port]?.name === 'Telnet' || wellKnownPorts[p.port]?.name === 'HTTP'));
    
    const servicesOnAllInterfaces = listeningPorts.filter(p => {
        const [ip] = extractIPPort(p.address);
        return ip === '0.0.0.0' || ip === '::' || ip === '*';
    });
    
    const uniqueTcpPorts = new Set(listeningPorts.filter(p => p.protocol === 'TCP' && p.port).map(p => p.port)).size;
    const uniqueUdpPorts = new Set(listeningPorts.filter(p => p.protocol === 'UDP' && p.port).map(p => p.port)).size;

    return {
        riskyOpenPorts,
        unencryptedServices,
        servicesOnAllInterfaces,
        totalListening: listeningPorts.length, // Total traditional listeners
        uniqueTcpPorts,
        uniqueUdpPorts
    };
  }, [latestAnalysisResults, wellKnownPorts, extractIPPort]);

  const overviewPortActivityData = useMemo((): OverviewPortActivityData[] => {
    if (!latestAnalysisResults || !latestAnalysisResults.listeningPorts) {
        setOverviewPortActivityDataState([]); 
        return [];
    }
    
    const activityData = latestAnalysisResults.listeningPorts.map((lp): OverviewPortActivityData => {
        const portInfo = lp.port ? wellKnownPorts[lp.port] : null;
        const connectedIpMap: Record<string, ConnectedIpDetail> = {};
        let activeInboundConnectionsCount = 0;

        const allRelevantConnections = latestAnalysisResults.establishedConnections.concat(
             latestAnalysisResults.suspiciousConnections.filter(sc => !latestAnalysisResults.establishedConnections.find(ec => ec.raw === sc.raw))
        );

        allRelevantConnections.forEach(conn => {
            const [, connLocalPort] = extractIPPort(conn.localAddress);
            const [connForeignIP] = extractIPPort(conn.foreignAddress);

            if (lp.port === connLocalPort && lp.protocol === conn.protocol) {
                 const listenerIPForCheck = extractIPPort(lp.address)[0]; 
                 const connLocalIPForCheck = extractIPPort(conn.localAddress)[0]; 

                 let matchesListener = false;
                 if (lp.address === conn.localAddress) { 
                     matchesListener = true;
                 } else if (listenerIPForCheck === '0.0.0.0' && !connLocalIPForCheck?.includes(':')) { 
                     matchesListener = true; 
                 } else if (listenerIPForCheck === '::' && connLocalIPForCheck?.includes(':')) {   
                     matchesListener = true; 
                 } else if (listenerIPForCheck === '*') { 
                     matchesListener = true; 
                 } else if (listenerIPForCheck === connLocalIPForCheck) { 
                     matchesListener = true;
                 }

                if (matchesListener && connForeignIP && connForeignIP !== '*' && connForeignIP !== '0.0.0.0' && connForeignIP !== '::') { 
                    activeInboundConnectionsCount++;
                    if (!connectedIpMap[connForeignIP]) {
                        connectedIpMap[connForeignIP] = {
                            ip: connForeignIP,
                            connectionCountToPort: 0,
                            risk: 'safe', 
                            isPublic: isPublicIP(connForeignIP),
                            states: []
                        };
                    }
                    const ipDetail = connectedIpMap[connForeignIP];
                    ipDetail.connectionCountToPort++;
                    if (!ipDetail.states.includes(conn.state)) {
                        ipDetail.states.push(conn.state);
                    }
                    let connectionRisk = conn.risk; 
                    const threatMatch = checkIpAgainstThreatIntel(connForeignIP);
                    if (threatMatch) {
                        connectionRisk = threatMatch.severity === 'low' ? 'warning' :
                                        threatMatch.severity === 'medium' ? 'suspicious' : 'critical';
                    } else {
                        if (conn.portInfo && riskOrderGlobal.indexOf(conn.portInfo.risk) < riskOrderGlobal.indexOf(connectionRisk)) {
                            connectionRisk = conn.portInfo.risk;
                        }
                        if (isPublicIP(connForeignIP) && connectionRisk === 'safe') {
                            connectionRisk = 'warning';
                        }
                    }

                    if (riskOrderGlobal.indexOf(connectionRisk) < riskOrderGlobal.indexOf(ipDetail.risk)) {
                        ipDetail.risk = connectionRisk;
                    }
                }
            }
        });

        return {
            port: lp.port || 'N/A',
            protocol: lp.protocol,
            listenerAddress: lp.address,
            service: lp.service || portInfo?.name || 'Unknown',
            description: portInfo?.description || 'No specific description for this port.',
            risk: lp.risk,
            activeInboundConnectionsCount,
            connectedIpDetails: Object.values(connectedIpMap).sort((a,b) => {
                const riskDiff = riskOrderGlobal.indexOf(a.risk) - riskOrderGlobal.indexOf(b.risk);
                if (riskDiff !== 0) return riskDiff;
                return b.connectionCountToPort - a.connectionCountToPort;
            }),
            aiContextualInsight: null,
            isFetchingAiContextualInsight: false,
        };
    });

    activityData.sort((a, b) => {
        const riskDiff = riskOrderGlobal.indexOf(a.risk) - riskOrderGlobal.indexOf(b.risk);
        if (riskDiff !== 0) return riskDiff;
        return b.activeInboundConnectionsCount - a.activeInboundConnectionsCount;
    });
    
    setOverviewPortActivityDataState(activityData); 
    return activityData;

  }, [latestAnalysisResults, wellKnownPorts, extractIPPort, isPublicIP]);
  
  const localPortUsageSummary = useMemo(() => {
    if (!latestAnalysisResults) return { totalUnique: 0, listeningCount: 0, riskyCount: 0, top3Active: [] };
    return {
      totalUnique: latestAnalysisResults.allLocalPortsActivity.length,
      listeningCount: latestAnalysisResults.listeningPorts.length, // traditional listeners
      riskyCount: latestAnalysisResults.allLocalPortsActivity.filter(p => p.risk === 'critical' || p.risk === 'suspicious').length,
      top3Active: latestAnalysisResults.allLocalPortsActivity.slice(0, 3).map(p => `${p.port}/${p.protocol} (${p.count})`)
    };
  }, [latestAnalysisResults]);

  const foreignPortUsageSummary = useMemo(() => {
    if (!latestAnalysisResults) return { totalUnique: 0, riskyCount: 0, top3Active: [] };
    return {
      totalUnique: latestAnalysisResults.allForeignPortsActivity.length,
      riskyCount: latestAnalysisResults.allForeignPortsActivity.filter(p => p.risk === 'critical' || p.risk === 'suspicious').length,
      top3Active: latestAnalysisResults.allForeignPortsActivity.slice(0, 3).map(p => `${p.port}/${p.protocol} (${p.count})`)
    };
  }, [latestAnalysisResults]);


  const riskOrderForSort: RiskLevel[] = useMemo(() => ['critical', 'suspicious', 'warning', 'safe', 'unknown'], []);

  const riskSummaryCards = useMemo(() => {
    if (!latestAnalysisResults) return [];
    return [
      { title: 'Total Issues', value: latestAnalysisResults.summary.critical + latestAnalysisResults.summary.suspicious + latestAnalysisResults.summary.warning, icon: Server , classes: 'from-slate-500 to-slate-600' },
      { title: 'Critical', value: latestAnalysisResults.summary.critical, icon: XCircle, classes: 'from-red-500 to-red-600' },
      { title: 'Suspicious', value: latestAnalysisResults.summary.suspicious, icon: Eye, classes: 'from-orange-500 to-orange-600' },
      { title: 'Warnings', value: latestAnalysisResults.summary.warning, icon: AlertTriangle, classes: 'from-yellow-500 to-yellow-600' },
      { title: 'Safe Items', value: latestAnalysisResults.summary.safe, icon: CheckCircle, classes: 'from-green-500 to-green-600' },
    ];
  }, [latestAnalysisResults]);

  const externalIpList = useMemo(() => {
    if (!latestAnalysisResults || !latestAnalysisResults.ipAnalysis) return [];
    return Object.values(latestAnalysisResults.ipAnalysis)
      .filter(ip => ip.isPublic)
      .sort((a,b) => riskOrderForSort.indexOf(a.risk) - riskOrderForSort.indexOf(b.risk) || b.connections - a.connections);
  }, [latestAnalysisResults, riskOrderForSort]);

  const ipTimeline = useMemo((): TimelineEntry[] => {
    if (!timelineIpDisplay || historicalAnalyses.length === 0) return [];

    const targetIP = timelineIpDisplay;
    const entries: TimelineEntry[] = [];

    historicalAnalyses.forEach(snapshot => {
        if (snapshot.results.error) return; 

        // Consider local services on loopback as potential "listeners" if the target IP is 127.0.0.1
        let relevantLocalServicesAsConnections: Connection[] = [];
        if (targetIP === '127.0.0.1') {
            relevantLocalServicesAsConnections = snapshot.results.localServicesOnLoopback.map((ls: LocalServiceDetail): Connection => ({
                protocol: ls.protocol,
                localAddress: `127.0.0.1:${ls.port}`,
                foreignAddress: "*:*", 
                state: "LISTEN_LOOPBACK", // Custom state to differentiate
                pid: ls.associatedPids?.join(', ') || null, 
                raw: `Local Service: ${ls.protocol} 127.0.0.1:${ls.port} (${ls.serviceName})`,
                format: snapshot.results.format,
                risk: ls.risk,
                issues: [], 
                recommendations: [],
                portInfo: ls.port ? wellKnownPorts[ls.port] : undefined,
            }));
        }


        const connectionsInvolvingIp = snapshot.results.establishedConnections
            .concat(snapshot.results.suspiciousConnections)
            .concat(snapshot.results.listeningPorts.map((lp: ListeningPort): Connection => ({ // Add traditional listeners
                protocol: lp.protocol,
                localAddress: lp.address,
                foreignAddress: "*:*", 
                state: "LISTEN", 
                pid: null, 
                raw: `Listening: ${lp.protocol} ${lp.address} (Port: ${lp.port || 'N/A'})`,
                format: snapshot.results.format,
                risk: lp.risk,
                issues: [],
                recommendations: [],
                portInfo: lp.port ? wellKnownPorts[lp.port] : undefined,
            })))
            .concat(relevantLocalServicesAsConnections) // Add local services if target is 127.0.0.1
            .filter((conn, index, self) => 
                index === self.findIndex((c) => (
                    c.raw === conn.raw && c.localAddress === conn.localAddress && c.foreignAddress === conn.foreignAddress && c.state === conn.state
                ))
            )
            .filter(conn => {
                const [localIP] = extractIPPort(conn.localAddress);
                const [foreignIP] = extractIPPort(conn.foreignAddress);
                return localIP === targetIP || foreignIP === targetIP;
            });

        if (connectionsInvolvingIp.length > 0) {
            const localPortsInvolved = new Set<string>();
            const foreignPortsOnSelectedIp = new Set<string>();
            const allPortsInvolved = new Set<string>();
            const connectionStates = new Set<string>();
            let highestRisk: RiskLevel = 'safe';
            
            connectionsInvolvingIp.forEach(conn => {
                const [localIP, localPort] = extractIPPort(conn.localAddress);
                const [foreignIP, foreignPort] = extractIPPort(conn.foreignAddress);

                if (localIP === targetIP && localPort) { 
                    allPortsInvolved.add(localPort); 
                } else if (localPort) { 
                     localPortsInvolved.add(localPort);
                     allPortsInvolved.add(localPort);
                }

                if (foreignIP === targetIP && foreignPort) { 
                    foreignPortsOnSelectedIp.add(foreignPort); 
                    allPortsInvolved.add(foreignPort);
                }
                
                connectionStates.add(conn.state);
                const threatMatch = checkIpAgainstThreatIntel(targetIP);
                if (threatMatch) {
                    const threatRisk = threatMatch.severity === 'low' ? 'warning' :
                                      threatMatch.severity === 'medium' ? 'suspicious' : 'critical';
                    if (riskOrderForSort.indexOf(threatRisk) < riskOrderForSort.indexOf(highestRisk)) {
                        highestRisk = threatRisk;
                    }
                } else if (riskOrderForSort.indexOf(conn.risk) < riskOrderForSort.indexOf(highestRisk)) {
                    highestRisk = conn.risk;
                }
            });

            entries.push({
                snapshotId: snapshot.id,
                snapshotName: snapshot.name,
                snapshotTimestamp: snapshot.timestamp,
                ipFound: true,
                connectionsToIp: connectionsInvolvingIp.filter(c => extractIPPort(c.foreignAddress)[0] === targetIP && !c.state.startsWith("LISTEN")), 
                connectionsFromIp: connectionsInvolvingIp.filter(c => extractIPPort(c.localAddress)[0] === targetIP && c.state.startsWith("LISTEN")), 
                summary: {
                    localPortsInvolved: Array.from(localPortsInvolved), 
                    foreignPortsOnSelectedIp: Array.from(foreignPortsOnSelectedIp), 
                    allPortsInvolvedWithIp: Array.from(allPortsInvolved), 
                    connectionStates: Array.from(connectionStates),
                    risk: highestRisk,
                    connectionCount: connectionsInvolvingIp.length,
                }
            });
        } else {
            entries.push({
                snapshotId: snapshot.id,
                snapshotName: snapshot.name,
                snapshotTimestamp: snapshot.timestamp,
                ipFound: false,
                connectionsToIp: [],
                connectionsFromIp: []
            });
        }
    });
    return entries.sort((a,b) => b.snapshotTimestamp.getTime() - a.snapshotTimestamp.getTime()); 
  }, [timelineIpDisplay, historicalAnalyses, extractIPPort, riskOrderForSort, wellKnownPorts]);

  const toggleOverviewPortIPsExpansion = (key: string) => {
    setExpandedOverviewPortIPs(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const riskDistributionForBar = useMemo(() => {
    if (!latestAnalysisResults || latestAnalysisResults.error || !latestAnalysisResults.summary) return [];
    const { summary, totalConnections } = latestAnalysisResults;
    if (totalConnections === 0) return [];
    
    const order: RiskLevel[] = ['critical', 'suspicious', 'warning', 'safe'];
    return order.map(risk => ({
        risk,
        count: summary[risk],
        percentage: totalConnections > 0 ? (summary[risk] / totalConnections) * 100 : 0,
        color: getRiskBarColor(risk)
    })).filter(item => item.count > 0); 
  }, [latestAnalysisResults]);

  const topRiskyListeningPorts = useMemo(() => { // Traditional external listeners
    if (!latestAnalysisResults || latestAnalysisResults.error) return [];
    return latestAnalysisResults.listeningPorts
        .filter(p => p.risk === 'critical' || p.risk === 'suspicious')
        .slice(0, 5);
  }, [latestAnalysisResults]);

  const topRiskyConnections = useMemo(() => {
     if (!latestAnalysisResults || latestAnalysisResults.error) return [];
     return latestAnalysisResults.suspiciousConnections
        .filter(c => c.risk === 'critical' || c.risk === 'suspicious') 
        .slice(0,5);
  },[latestAnalysisResults]);

  const toggleHelpSection = (sectionKey: HelpSectionKey) => {
    setActiveHelpSection(prev => prev === sectionKey ? null : sectionKey);
  };
  
  const renderHelpAccordionItem = (
    key: HelpSectionKey, 
    title: string, 
    IconComponent: React.ElementType, 
    children: React.ReactNode
  ) => (
    <div className="border border-gray-200 rounded-lg overflow-hidden">
      <button
        onClick={() => toggleHelpSection(key)}
        className="w-full flex justify-between items-center p-4 bg-gray-50 hover:bg-gray-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 transition-colors"
        aria-expanded={activeHelpSection === key}
        aria-controls={`help-content-${key}`}
      >
        <span className="flex items-center text-lg font-semibold text-gray-700">
          <IconComponent className="w-5 h-5 mr-3 text-blue-600" />
          {title}
        </span>
        {activeHelpSection === key ? <ChevronUp className="w-5 h-5 text-gray-600" /> : <ChevronDown className="w-5 h-5 text-gray-600" />}
      </button>
      {activeHelpSection === key && (
        <div id={`help-content-${key}`} className="p-5 bg-white border-t border-gray-200 prose prose-sm max-w-none text-gray-700">
          {children}
        </div>
      )}
    </div>
  );


  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-100 to-blue-100 p-4 selection:bg-blue-200">
      <div className="max-w-7xl mx-auto">
        <header className="text-center mb-8 py-6">
          <div className="flex items-center justify-center mb-3">
            <Shield className="w-12 h-12 text-blue-600 mr-3 drop-shadow-md" />
            <h1 className="text-4xl font-extrabold text-gray-800 tracking-tight">Netstat Security Analyzer</h1>
          </div>
          <p className="text-lg text-gray-600">Upload your netstat output for an in-depth security posture analysis.</p>
        </header>

        <Card className="mb-6 shadow-xl overflow-hidden">
          <CardHeader className="bg-gray-50 border-b">
            <CardTitle className="flex items-center text-xl text-gray-700">
              <Upload className="w-6 h-6 mr-3 text-blue-600" />
              Upload Netstat Output File
            </CardTitle>
            <CardDescription>
              Supports standard netstat output from Windows, Linux, and macOS. Analyze multiple files to build a timeline.
            </CardDescription>
          </CardHeader>
          <CardContent className="pt-6">
            <div className="space-y-4">
              <div className={`border-2 border-dashed rounded-lg p-8 text-center hover:border-blue-500 transition-colors duration-200 ease-in-out ${file ? 'border-blue-400 bg-blue-50/30' : 'border-gray-300'}`}>
                <FileText className={`w-16 h-16 mx-auto mb-4 ${file ? 'text-blue-500' : 'text-gray-400'}`} />
                <input
                  type="file"
                  accept=".txt,.log,.out,text/plain"
                  onChange={handleFileUpload}
                  className="hidden"
                  id="file-upload"
                  aria-label="Upload netstat file"
                />
                <label
                  htmlFor="file-upload"
                  className="cursor-pointer text-blue-600 hover:text-blue-800 font-semibold text-lg py-2 px-4 rounded-md hover:bg-blue-100 transition-colors"
                >
                  {file ? `Selected: ${file.name}` : "Click to select netstat output file"}
                </label>
                <p className="text-sm text-gray-500 mt-2">
                  Max file size: 10MB. Common commands: <code>netstat -an</code> (Win), <code>ss -tulpn</code> / <code>netstat -tulnp</code> (Lin).
                </p>
              </div>
              
              {file && (
                <div className="flex flex-col sm:flex-row items-center justify-between p-4 bg-blue-50 rounded-lg border border-blue-200 shadow-sm">
                  <div className="flex items-center mb-3 sm:mb-0">
                    <FileText className="w-5 h-5 text-blue-700 mr-2 flex-shrink-0" />
                    <span className="font-medium text-blue-900 truncate" title={file.name}>
                      {file.name} ({(file.size / 1024).toFixed(1)} KB)
                    </span>
                  </div>
                  <div className="flex space-x-2">
                    <Button onClick={analyzeFile} disabled={isAnalyzing || !file} className="bg-blue-600 hover:bg-blue-700 disabled:bg-blue-300">
                      {isAnalyzing ? (
                        <>
                          <Activity className="w-4 h-4 mr-2 animate-spin" />
                          Analyzing...
                        </>
                      ) : (
                        <>
                          <Shield className="w-4 h-4 mr-2" />
                          Analyze & Add to History
                        </>
                      )}
                    </Button>
                    <Button variant="outline" onClick={clearCurrentFileSelection}>
                      Clear Selection
                    </Button>
                  </div>
                </div>
              )}
               <Button variant="destructive" size="sm" onClick={clearAllData} className="float-right mt-2">
                  <Trash2 className="w-4 h-4 mr-2" /> Clear All Data & History
                </Button>
            </div>
          </CardContent>
        </Card>

        {latestAnalysisResults?.error && activeTab !== 'timeline' && activeTab !== 'help' && ( 
          <Alert variant="destructive" className="mb-6 shadow-lg">
            <AlertTriangle className="h-5 w-5" />
            <AlertTitle>Analysis Error for Current View</AlertTitle>
            <AlertDescription>{latestAnalysisResults.error}</AlertDescription>
          </Alert>
        )}

        {latestAnalysisResults && !latestAnalysisResults.error && activeTab !== 'timeline' && activeTab !== 'overallRisk' && activeTab !== 'help' && (
          <div className="space-y-6">
             <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 mb-6">
              {riskSummaryCards.map(item => (
                <Card key={item.title} className={`bg-gradient-to-br ${item.classes} text-white shadow-lg`}>
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="text-3xl font-bold">{item.value}</div>
                        <div className="text-sm opacity-90">{item.title}</div>
                      </div>
                      <item.icon className="w-8 h-8 opacity-70" />
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        )}
        {!latestAnalysisResults && activeTab !== 'timeline' && activeTab !== 'help' && (
             <Card className="mb-6 shadow-lg">
                <CardContent className="p-10 text-center">
                    <FileText className="w-16 h-16 mx-auto text-gray-300 mb-4" />
                    <p className="text-xl text-gray-500">No analysis loaded.</p>
                    <p className="text-sm text-gray-400">Upload a file and click "Analyze & Add to History" to begin, or load a snapshot from the Timeline tab.</p>
                </CardContent>
            </Card>
        )}


        <Card className="shadow-lg mt-6">
            <CardHeader className="border-b bg-gray-50">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center">
                <div className="flex space-x-1 mb-3 sm:mb-0 border border-gray-200 rounded-md p-0.5 bg-white shadow-sm overflow-x-auto">
                {[
                    {id: 'overallRisk', label: 'Overall Risk', icon: Gauge},
                    {id: 'overview', label: 'Overview', icon: BarChart3}, 
                    {id: 'localServices', label: 'Local Services', icon: HardDrive},
                    {id: 'connections', label: 'Risky Conns', icon: AlertTriangle},
                    {id: 'riskMatrix', label: 'Risk Matrix', icon: TableProperties},
                    {id: 'portUsage', label: 'Port Usage', icon: ListTree},
                    {id: 'ipAnalysis', label: 'IP Analysis', icon: Globe},
                    {id: 'timeline', label: 'Timeline', icon: History},
                    {id: 'settings', label: 'Settings', icon: Settings},
                    {id: 'help', label: 'Help & FAQ', icon: HelpCircle}
                ].map(tab => (
                    <Button
                    key={tab.id}
                    variant={activeTab === tab.id ? 'default' : 'ghost'}
                    size="sm"
                    onClick={() => setActiveTab(tab.id)}
                    className={`${activeTab === tab.id ? 'bg-blue-600 text-white shadow' : 'text-gray-600 hover:bg-gray-200'} transition-all duration-150 whitespace-nowrap px-3 py-1.5`}
                    >
                    <tab.icon className="w-4 h-4 mr-1.5" />
                    {tab.label}
                    </Button>
                ))}
                </div>
                {latestAnalysisResults && !latestAnalysisResults.error && activeTab !== 'timeline' && activeTab !== 'help' && (
                  <div className="flex flex-col sm:flex-row sm:space-x-2 space-y-2 sm:space-y-0 mt-2 sm:mt-0">
                    <Button onClick={exportReport} variant="outline" size="sm" className="border-blue-500 text-blue-600 hover:bg-blue-50 hover:text-blue-700">
                        <Download className="w-4 h-4 mr-2" />
                        Export JSON
                    </Button>
                     <Button onClick={exportHtmlReport} variant="outline" size="sm" className="border-teal-500 text-teal-600 hover:bg-teal-50 hover:text-teal-700">
                        <FileDown className="w-4 h-4 mr-2" />
                        Generate HTML Report
                    </Button>
                  </div>
                )}
            </div>
            </CardHeader>

            <CardContent className="pt-6">

            {activeTab === 'overallRisk' && latestAnalysisResults && !latestAnalysisResults.error && overallRiskContextState && (
                <div className="space-y-8">
                    <Card className="shadow-xl border-t-4" style={{borderColor: getRiskColorIndicator(overallRiskContextState.level)}}>
                        <CardContent className="p-6 flex flex-col items-center text-center">
                            <div className={`w-32 h-32 rounded-full ${overallRiskContextState.colorClass} flex items-center justify-center mb-4 shadow-lg`}>
                                {overallRiskContextState.icon}
                            </div>
                            <h2 className={`text-3xl font-bold ${overallRiskContextState.textColorClass.replace('text-', 'text-gray-')}`}>{overallRiskContextState.description}</h2>
                            <p className="text-gray-600 mt-2 max-w-xl">{overallRiskContextState.detailedMessage}</p>
                        </CardContent>
                    </Card>

                    <Card>
                        <CardHeader>
                            <CardTitle className="text-xl">Risk Breakdown (Current View)</CardTitle>
                            <CardDescription>Distribution of identified items by risk level.</CardDescription>
                        </CardHeader>
                        <CardContent>
                            <div className="w-full h-8 flex rounded-full overflow-hidden shadow-inner bg-gray-200 my-2">
                                {riskDistributionForBar.map(item => (
                                    <div
                                        key={item.risk}
                                        className={`h-full flex items-center justify-center text-xs font-medium text-white ${item.color}`}
                                        style={{ width: `${item.percentage}%` }}
                                        title={`${item.risk.charAt(0).toUpperCase() + item.risk.slice(1)}: ${item.count} (${item.percentage.toFixed(1)}%)`}
                                    >
                                        {item.percentage > 10 ? `${item.percentage.toFixed(0)}%` : ''}
                                    </div>
                                ))}
                            </div>
                            <div className="flex justify-around mt-2 text-xs text-gray-600">
                                {riskDistributionForBar.map(item => (
                                    <div key={`${item.risk}-label`} className="flex items-center">
                                        <span className={`w-3 h-3 rounded-full mr-1.5 ${item.color}`}></span>
                                        {item.risk.charAt(0).toUpperCase() + item.risk.slice(1)}: {item.count}
                                    </div>
                                ))}
                            </div>
                        </CardContent>
                    </Card>
                    
                     <Card>
                        <CardHeader>
                            <CardTitle className="text-xl">Key Findings (Current View)</CardTitle>
                        </CardHeader>
                        <CardContent className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                            <Card className="bg-red-50 border-red-200">
                                <CardHeader><CardTitle className="text-red-700 text-lg">Critical ({latestAnalysisResults.summary.critical})</CardTitle></CardHeader>
                                <CardContent className="text-red-600 text-sm">Items requiring immediate attention.</CardContent>
                            </Card>
                            <Card className="bg-orange-50 border-orange-200">
                                <CardHeader><CardTitle className="text-orange-700 text-lg">Suspicious ({latestAnalysisResults.summary.suspicious})</CardTitle></CardHeader>
                                <CardContent className="text-orange-600 text-sm">Potentially harmful items needing investigation.</CardContent>
                            </Card>
                            <Card className="bg-yellow-50 border-yellow-200">
                                <CardHeader><CardTitle className="text-yellow-700 text-lg">Warnings ({latestAnalysisResults.summary.warning})</CardTitle></CardHeader>
                                <CardContent className="text-yellow-600 text-sm">Deviations from best practices or minor risks.</CardContent>
                            </Card>
                        </CardContent>
                    </Card>

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        <Card>
                            <CardHeader>
                                <CardTitle className="flex items-center text-gray-700"><RadioTower className="w-5 h-5 mr-2 text-orange-600"/>Top Risky Listening Ports (External)</CardTitle>
                            </CardHeader>
                            <CardContent>
                                {topRiskyListeningPorts.length > 0 ? (
                                    <ul className="space-y-2">
                                        {topRiskyListeningPorts.map((p, i) => (
                                            <li key={`risky-listen-${i}`} className="text-sm p-2 border rounded-md hover:bg-gray-50 flex justify-between items-center">
                                                <div>
                                                  <span className="font-semibold">{p.service} ({p.port}/{p.protocol})</span>
                                                  <span className="block text-xs text-gray-500">{p.address}</span>
                                                </div>
                                                {getRiskBadge(p.risk)}
                                            </li>
                                        ))}
                                    </ul>
                                ) : <p className="text-sm text-gray-500 italic">No critical or suspicious external listening ports found.</p>}
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader>
                                <CardTitle className="flex items-center text-gray-700"><TrendingUp className="w-5 h-5 mr-2 text-red-600"/>Top Risky Connections</CardTitle>
                            </CardHeader>
                            <CardContent>
                               {topRiskyConnections.length > 0 ? (
                                    <ul className="space-y-2">
                                        {topRiskyConnections.map((c, i) => (
                                            <li key={`risky-conn-${i}`} className="text-sm p-2 border rounded-md hover:bg-gray-50">
                                                <div className="flex justify-between items-center mb-1">
                                                  <span className="font-mono text-xs truncate max-w-[200px] sm:max-w-xs" title={`${c.localAddress} -> ${c.foreignAddress}`}>
                                                    {c.localAddress} &rarr; {c.foreignAddress}
                                                  </span>
                                                  {getRiskBadge(c.risk)}
                                                </div>
                                                <div className="text-xs text-gray-500">
                                                   <span>{c.protocol}, State: {c.state}</span>
                                                   {c.portInfo && <span className="ml-2">({c.portInfo.name})</span>}
                                                </div>
                                            </li>
                                        ))}
                                    </ul>
                                ) : <p className="text-sm text-gray-500 italic">No critical or suspicious active connections found.</p>}
                            </CardContent>
                        </Card>
                    </div>

                    {latestAnalysisResults.recommendations.length > 0 && (
                        <Card className="border-blue-200 bg-blue-50/30">
                            <CardHeader>
                                <CardTitle className="flex items-center text-blue-700"><Lightbulb className="w-6 h-6 mr-2"/>Top Security Recommendations</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <div className="space-y-3">
                                    {latestAnalysisResults.recommendations.slice(0,3).map((rec, index) => (
                                        <Alert key={`rec-overall-${index}`} className={`${rec.type === 'critical' ? 'border-red-300 bg-red-50' : 'border-yellow-300 bg-yellow-50'}`}>
                                            <AlertTitle className={`${rec.type === 'critical' ? 'text-red-800' : 'text-yellow-800'} font-semibold`}>
                                                {rec.title}
                                            </AlertTitle>
                                            <AlertDescription className={`${rec.type === 'critical' ? 'text-red-700' : 'text-yellow-700'} text-xs`}>
                                                {rec.description}
                                            </AlertDescription>
                                        </Alert>
                                    ))}
                                </div>
                            </CardContent>
                        </Card>
                    )}
                </div>
            )}
             {activeTab === 'overallRisk' && (!latestAnalysisResults || latestAnalysisResults.error) && (
                <div className="text-center py-10">
                    <Gauge className="w-16 h-16 text-gray-300 mx-auto mb-3" />
                    <p className="text-lg text-gray-500">No analysis loaded for Overall Risk assessment.</p>
                    <p className="text-sm text-gray-400">Upload a file or load a snapshot from the Timeline tab.</p>
                     {latestAnalysisResults?.error && <p className="text-red-500 mt-2">{latestAnalysisResults.error}</p>}
                </div>
            )}


            {activeTab === 'overview' && latestAnalysisResults && !latestAnalysisResults.error && (
                <div className="space-y-6">
                {ai && (
                <Card className="border-purple-200 bg-purple-50/30 shadow-md">
                    <CardHeader>
                    <CardTitle className="flex items-center text-purple-700">
                        <Sparkles className="w-6 h-6 mr-2" />
                        AI Security Briefing (Current View)
                    </CardTitle>
                    </CardHeader>
                    <CardContent>
                    {!aiInsights && !isFetchingAiInsights && (
                        <Button onClick={fetchAiInsights} disabled={!latestAnalysisResults || isFetchingAiInsights || !effectiveApiKey} className="bg-purple-600 hover:bg-purple-700 disabled:bg-purple-300">
                        <Sparkles className="w-4 h-4 mr-2" />
                        Get AI-Powered Insights
                        </Button>
                    )}
                    {isFetchingAiInsights && (
                        <div className="flex items-center text-purple-700">
                        <Activity className="w-5 h-5 mr-2 animate-spin" />
                        Generating briefing... This may take a moment.
                        </div>
                    )}
                    {aiInsights && !isFetchingAiInsights && (
                        <div className="prose prose-sm max-w-none text-gray-800 whitespace-pre-wrap p-2 bg-purple-50 rounded">
                            {aiInsights}
                        </div>
                    )}
                        <p className="text-xs text-gray-500 mt-3 italic">AI insights are for informational purposes and should be verified. {!effectiveApiKey && <span className="text-red-500 font-semibold">API key not configured; AI features disabled.</span>}</p>
                    </CardContent>
                </Card>
                )}
                
                {overviewPortActivityDataState.length > 0 && (
                    <Card className="border-sky-200 bg-sky-50/30 shadow-md">
                        <CardHeader>
                            <CardTitle className="flex items-center text-sky-700">
                                <RadioTower className="w-6 h-6 mr-2" />
                                Top Exposed Listening Port Activity (Current View)
                            </CardTitle>
                            <CardDescription>Externally exposed listening ports with active inbound connections, sorted by risk and connection count. Enhanced with AI context.</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-3">
                            {overviewPortActivityDataState.map((item) => {
                                const maxConnections = Math.max(...overviewPortActivityDataState.map(p => p.activeInboundConnectionsCount), 1);
                                const barWidthPercentage = Math.max(5, (item.activeInboundConnectionsCount / maxConnections) * 100);
                                const itemKey = `${item.port}-${item.protocol}-${item.listenerAddress}`;
                                const isExpanded = !!expandedOverviewPortIPs[itemKey];
                                
                                return (
                                    <Card key={itemKey} className="group border rounded-md overflow-hidden shadow-sm hover:shadow-lg transition-shadow">
                                        <div className="p-3">
                                            <div className="flex justify-between items-start mb-2">
                                                <div>
                                                    <div className="flex items-center">
                                                        <span className={`w-3 h-3 rounded-full mr-2 ${getRiskColorIndicator(item.risk)} flex-shrink-0`}></span>
                                                        <span className="font-semibold text-gray-800">
                                                            Port {item.port}/{item.protocol} ({item.service || 'Unknown'})
                                                        </span>
                                                    </div>
                                                    <p className="text-xs text-gray-500 ml-5 truncate" title={item.listenerAddress}>Listening on: {item.listenerAddress}</p>
                                                    <p className="text-xs text-gray-500 ml-5 truncate" title={item.description}>{item.description}</p>
                                                </div>
                                                <div className="flex flex-col items-end space-y-1">
                                                     {getRiskBadge(item.risk)}
                                                     <span className="text-xs text-gray-600 mt-1">
                                                        {item.activeInboundConnectionsCount} active connections
                                                     </span>
                                                </div>
                                            </div>
                                            
                                            {item.activeInboundConnectionsCount > 0 && (
                                              <div className="h-2 w-full bg-gray-200 rounded overflow-hidden my-1">
                                                  <div
                                                      className={`h-full rounded ${getRiskBarColor(item.risk)} transition-all duration-300 ease-in-out group-hover:opacity-80`}
                                                      style={{ width: `${barWidthPercentage}%` }}
                                                      title={`${item.activeInboundConnectionsCount} active connections`}
                                                  ></div>
                                              </div>
                                            )}

                                            <div className="mt-2 flex flex-wrap gap-2 items-center">
                                                {item.connectedIpDetails.length > 0 && (
                                                    <Button variant="outline" size="sm" onClick={() => toggleOverviewPortIPsExpansion(itemKey)} aria-expanded={isExpanded} className="text-xs">
                                                        {isExpanded ? <ChevronUp className="w-3 h-3 mr-1" /> : <ChevronDown className="w-3 h-3 mr-1" />}
                                                        Connected IPs ({item.connectedIpDetails.length})
                                                    </Button>
                                                )}
                                                {ai && effectiveApiKey && (
                                                    <Button
                                                        variant="outline"
                                                        size="sm"
                                                        onClick={() => fetchAiPortContextualAnalysis(item)}
                                                        disabled={item.isFetchingAiContextualInsight || !effectiveApiKey}
                                                        className="text-xs bg-purple-50 hover:bg-purple-100 border-purple-300 text-purple-700"
                                                    >
                                                        {item.isFetchingAiContextualInsight ? <Loader2 className="w-3 h-3 mr-1 animate-spin" /> : <Sparkles className="w-3 h-3 mr-1" />}
                                                        Get AI Context
                                                    </Button>
                                                )}
                                            </div>
                                        </div>

                                        {isExpanded && item.connectedIpDetails.length > 0 && (
                                            <div className="px-3 pb-3 border-t bg-gray-50/50">
                                                <h5 className="text-xs font-semibold text-gray-700 mt-2 mb-1">Connected IP Details:</h5>
                                                <div className="max-h-48 overflow-y-auto space-y-1 pr-1">
                                                    {item.connectedIpDetails.map(ipDetail => (
                                                        <div key={ipDetail.ip} className="text-xs p-1.5 bg-white rounded border border-gray-200 flex justify-between items-center">
                                                            <div>
                                                                <span className="font-mono text-gray-800">{ipDetail.ip}</span>
                                                                <span className={`ml-2 text-gray-500 ${ipDetail.isPublic ? 'font-semibold' : ''}`}>({ipDetail.isPublic ? 'Public' : 'Private'})</span>
                                                                <span className="ml-2 text-gray-500">x{ipDetail.connectionCountToPort}</span>
                                                                <span className="ml-2 text-gray-500 text-[0.65rem]">({ipDetail.states.join(', ') || 'N/A'})</span>
                                                            </div>
                                                            {getRiskBadge(ipDetail.risk)}
                                                        </div>
                                                    ))}
                                                </div>
                                            </div>
                                        )}
                                        
                                        {item.isFetchingAiContextualInsight && (
                                            <div className="p-3 border-t text-xs text-purple-700 flex items-center bg-purple-50/30">
                                                <Loader2 className="w-4 h-4 mr-2 animate-spin" /> Generating AI contextual analysis...
                                            </div>
                                        )}
                                        {item.aiContextualInsight && !item.isFetchingAiContextualInsight && (
                                            <div className="p-3 border-t bg-purple-50/30">
                                                <h5 className="text-xs font-semibold text-purple-800 mb-1 flex items-center"><Lightbulb className="w-3.5 h-3.5 mr-1 text-yellow-500" />AI Contextual Analysis:</h5>
                                                <pre className="whitespace-pre-wrap text-xs text-gray-700 bg-white p-2 rounded-md shadow-sm overflow-x-auto font-sans">
                                                    {item.aiContextualInsight}
                                                </pre>
                                            </div>
                                        )}
                                    </Card>
                                );
                            })}
                            {overviewPortActivityDataState.length === 0 && <p className="text-sm text-gray-500 italic text-center py-3">No exposed listening port activity with inbound connections to display.</p>}
                        </CardContent>
                    </Card>
                )}

                {portInsightsSummary && (
                    <Card className="border-teal-200 bg-teal-50/30 shadow-md">
                        <CardHeader>
                            <CardTitle className="flex items-center text-teal-700">
                                <Network className="w-6 h-6 mr-2" />
                                Key Port Observations (Exposed Listeners) (Current View)
                            </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-3 text-sm">
                            <div>
                                <h4 className="font-semibold text-teal-800">Potentially Risky Exposed Ports Open ({portInsightsSummary.riskyOpenPorts.length}):</h4>
                                {portInsightsSummary.riskyOpenPorts.length > 0 ? (
                                    <ul className="list-disc list-inside pl-4 text-gray-700 space-y-1">
                                        {portInsightsSummary.riskyOpenPorts.slice(0,5).map(p => ( 
                                            <li key={`${p.protocol}-${p.address}-${p.port}`}>
                                                Port {p.port || 'N/A'} ({p.protocol}, {p.service}) on {p.address} - {getRiskBadge(p.risk)}
                                                {p.port && wellKnownPorts[p.port] && <span className="block text-xs italic ml-4 text-gray-600">- {wellKnownPorts[p.port].description}</span>}
                                            </li>
                                        ))}
                                        {portInsightsSummary.riskyOpenPorts.length > 5 && <li>And {portInsightsSummary.riskyOpenPorts.length - 5} more...</li>}
                                    </ul>
                                ) : <p className="text-gray-600 italic">No critical or suspicious exposed listening ports found.</p>}
                            </div>
                            <div>
                                <h4 className="font-semibold text-teal-800">Unencrypted Exposed Services Detected ({portInsightsSummary.unencryptedServices.length}):</h4>
                                    {portInsightsSummary.unencryptedServices.length > 0 ? (
                                    <ul className="list-disc list-inside pl-4 text-gray-700 space-y-1">
                                        {portInsightsSummary.unencryptedServices.map(p => (
                                            <li key={`unenc-${p.protocol}-${p.address}-${p.port}`}>
                                                Port {p.port || 'N/A'} ({p.service}, {p.protocol}) on {p.address}
                                                {p.port && wellKnownPorts[p.port] && <span className="block text-xs italic ml-4 text-gray-600">- {wellKnownPorts[p.port].description}</span>}
                                            </li>
                                        ))}
                                    </ul>
                                ) : <p className="text-gray-600 italic">No common unencrypted services (FTP, Telnet, HTTP) detected among exposed listening ports.</p>}
                            </div>
                            <div>
                                <h4 className="font-semibold text-teal-800">Services Exposed on All Interfaces ({portInsightsSummary.servicesOnAllInterfaces.length}):</h4>
                                {portInsightsSummary.servicesOnAllInterfaces.length > 0 ? (
                                    <p className="text-gray-700">{portInsightsSummary.servicesOnAllInterfaces.length} service(s) are open to all network interfaces (e.g., 0.0.0.0). Review these for necessity and ensure they are firewalled.</p>
                                    ) : <p className="text-gray-600 italic">No services found listening on all interfaces.</p>}
                            </div>
                            <div className="grid grid-cols-2 gap-2 pt-2 border-t border-teal-200 mt-2">
                                <p><span className="font-medium">{portInsightsSummary.totalListening}</span> Total Exposed Listeners</p>
                                <p><span className="font-medium">{portInsightsSummary.uniqueTcpPorts}</span> Unique Exposed TCP</p>
                                <p><span className="font-medium">{portInsightsSummary.uniqueUdpPorts}</span> Unique Exposed UDP</p>
                            </div>

                            {ai && (
                                <div className="pt-4 border-t border-teal-200 mt-4">
                                    <h4 className="flex items-center font-semibold text-teal-800 mb-2">
                                        <Lightbulb className="w-5 h-5 mr-2 text-yellow-500" />
                                        AI-Powered General Exposed Port Analysis (Current View)
                                    </h4>
                                    {!aiPortAnalysis && !isFetchingAiPortAnalysis && (
                                        <Button onClick={fetchAiPortAnalysis} disabled={!latestAnalysisResults || isFetchingAiPortAnalysis || !effectiveApiKey || latestAnalysisResults.listeningPorts.length === 0} className="bg-teal-600 hover:bg-teal-700 text-white disabled:bg-teal-300">
                                            <Lightbulb className="w-4 h-4 mr-2" />
                                            Get AI General Exposed Port Insights
                                        </Button>
                                    )}
                                    {isFetchingAiPortAnalysis && (
                                        <div className="flex items-center text-teal-700">
                                            <Activity className="w-5 h-5 mr-2 animate-spin" />
                                            Analyzing exposed ports...
                                        </div>
                                    )}
                                    {aiPortAnalysis && !isFetchingAiPortAnalysis && (
                                        <div className="prose prose-sm max-w-none text-gray-800 whitespace-pre-wrap p-2 bg-teal-50 rounded">
                                            {aiPortAnalysis}
                                        </div>
                                    )}
                                    <p className="text-xs text-gray-500 mt-2 italic">AI insights analyze *externally exposed* listening ports. For 127.0.0.1 services, see 'Local Services' tab.</p>
                                </div>
                            )}
                        </CardContent>
                    </Card>
                )}

                {latestAnalysisResults.recommendations.length > 0 && (
                    <Card className="border-blue-200 bg-blue-50/30 shadow-md">
                    <CardHeader>
                        <CardTitle className="flex items-center text-blue-700">
                        <Shield className="w-6 h-6 mr-2" />
                        Key Security Recommendations (Current View)
                        </CardTitle>
                    </CardHeader>
                    <CardContent>
                        <div className="space-y-4">
                        {latestAnalysisResults.recommendations.map((rec, index) => (
                            <Alert key={index} className={`${rec.type === 'critical' ? 'border-red-300 bg-red-50 shadow-sm' : 'border-yellow-300 bg-yellow-50 shadow-sm'}`}>
                            <AlertTitle className={`${rec.type === 'critical' ? 'text-red-800' : 'text-yellow-800'} font-semibold`}>
                                {rec.title}
                            </AlertTitle>
                            <AlertDescription className={`${rec.type === 'critical' ? 'text-red-700' : 'text-yellow-700'}`}>
                                {rec.description}
                                {rec.services && <div className="mt-2 text-xs"><span className="font-semibold">Potentially Affected:</span> {rec.services}</div>}
                            </AlertDescription>
                            </Alert>
                        ))}
                        </div>
                    </CardContent>
                    </Card>
                )}

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <Card className="shadow-md">
                    <CardHeader>
                        <CardTitle className="text-lg">Scan Information (Current View)</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3 text-sm">
                        <div className="flex justify-between items-center"><span className="text-gray-600">Source File:</span> <Badge variant="secondary">{historicalAnalyses.find(h => h.results === latestAnalysisResults)?.name || "N/A"}</Badge></div>
                        <div className="flex justify-between items-center"><span className="text-gray-600">Detected Format:</span> <Badge variant="secondary">{latestAnalysisResults.format.toUpperCase()}</Badge></div>
                        <div className="flex justify-between items-center"><span className="text-gray-600">Total Connections Analyzed:</span> <span className="font-medium">{latestAnalysisResults.totalConnections}</span></div>
                        <div className="flex justify-between items-center"><span className="text-gray-600">Exposed Listening Ports:</span> <span className="font-medium">{latestAnalysisResults.listeningPorts.length}</span></div>
                        <div className="flex justify-between items-center"><span className="text-gray-600">Local Services (127.0.0.1):</span> <span className="font-medium">{latestAnalysisResults.localServicesOnLoopback.length}</span></div>
                        <div className="flex justify-between items-center"><span className="text-gray-600">Established Connections:</span> <span className="font-medium">{latestAnalysisResults.establishedConnections.length}</span></div>
                        <div className="flex justify-between items-center"><span className="text-gray-600">Unique External IPs:</span> <span className="font-medium">{Object.values(latestAnalysisResults.ipAnalysis).filter(ip => ip.isPublic).length}</span></div>
                    </CardContent>
                    </Card>

                    <Card className="shadow-md">
                    <CardHeader>
                        <CardTitle className="text-lg">Risk Distribution Summary (Current View)</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-2">
                        {Object.entries(latestAnalysisResults.summary)
                        .sort(([riskAKey, countA], [riskBKey, countB]) => { 
                            if (countA !== countB) return countB - countA;
                            return riskOrderGlobal.indexOf(riskAKey as RiskLevel) - riskOrderGlobal.indexOf(riskBKey as RiskLevel);
                        }) 
                        .map(([risk, count]) => (
                        <div key={risk} className="flex items-center justify-between py-1">
                            {getRiskBadge(risk as RiskLevel)}
                            <div className="text-right">
                            <span className="font-semibold text-gray-700">{count}</span>
                            <span className="text-xs text-gray-500 ml-2">
                                ({latestAnalysisResults.totalConnections > 0 ? ((count / latestAnalysisResults.totalConnections) * 100).toFixed(1) : 0}%)
                            </span>
                            </div>
                        </div>
                        ))}
                    </CardContent>
                    </Card>
                </div>
                </div>
            )}
            {activeTab === 'overview' && !latestAnalysisResults && (
                <div className="text-center py-10">
                    <BarChart3 className="w-16 h-16 text-gray-300 mx-auto mb-3" />
                    <p className="text-lg text-gray-500">No analysis loaded for overview.</p>
                    <p className="text-sm text-gray-400">Upload a file or load a snapshot from the Timeline tab.</p>
                </div>
            )}


            {activeTab === 'localServices' && latestAnalysisResults && !latestAnalysisResults.error && (
                <Card className="shadow-inner">
                <CardHeader>
                    <CardTitle className="flex items-center text-gray-700">
                    <HardDrive className="w-5 h-5 mr-2 text-indigo-600" />
                    Local Services (on 127.0.0.1) Analysis ({latestAnalysisResults.localServicesOnLoopback.length}) (Current View)
                    </CardTitle>
                    <CardDescription>Services operating on the loopback interface (127.0.0.1). Sorted by risk. Use AI to help identify them.</CardDescription>
                </CardHeader>
                <CardContent>
                    {latestAnalysisResults.localServicesOnLoopback.length > 0 ? (
                    <div className="space-y-4">
                        {latestAnalysisResults.localServicesOnLoopback.map((service) => {
                            const serviceKey = `${service.port}-${service.protocol}`;
                            return (
                                <Card key={serviceKey} className="border rounded-lg overflow-hidden shadow-sm">
                                    <div className="p-4">
                                        <div className="flex flex-col sm:flex-row justify-between items-start mb-2">
                                            <div className="flex items-center space-x-3 mb-2 sm:mb-0 flex-grow min-w-0">
                                                <div className={`w-3 h-3 rounded-full mr-1 ${getRiskColorIndicator(service.risk)} flex-shrink-0`}></div>
                                                <div className={`flex items-center justify-center w-12 h-10 rounded-md bg-indigo-100 text-indigo-700 font-bold text-sm flex-shrink-0`}>
                                                    {service.port || '?'}
                                                </div>
                                                <div className="flex-grow min-w-0">
                                                    <div className="font-semibold text-gray-800 truncate" title={service.serviceName}>
                                                        {service.serviceName} <span className="text-xs text-gray-500">({service.protocol})</span>
                                                    </div>
                                                    <div className="text-xs text-gray-600">On: 127.0.0.1</div>
                                                    <p className="text-xs text-gray-500 mt-0.5 truncate" title={service.description}>{service.description}</p>
                                                </div>
                                            </div>
                                            <div className="flex flex-col items-start sm:items-end space-y-1">
                                                {getRiskBadge(service.risk)}
                                                <span className="text-xs text-gray-500">Connections: {service.connectionCount}</span>
                                            </div>
                                        </div>
                                         {service.associatedPids && service.associatedPids.length > 0 && (
                                            <p className="text-xs text-gray-500 mb-2">Associated PIDs: <span className="font-mono bg-gray-100 px-1 rounded">{service.associatedPids.join(', ')}</span></p>
                                        )}

                                        {ai && effectiveApiKey && (
                                            <Button
                                                size="sm"
                                                variant="outline"
                                                onClick={() => fetchAiLocalServiceIdentity(service)}
                                                disabled={isFetchingAiLocalServiceInsights[serviceKey] || !effectiveApiKey}
                                                className="border-indigo-500 text-indigo-600 hover:bg-indigo-50 hover:text-indigo-700 whitespace-nowrap text-xs"
                                            >
                                                {isFetchingAiLocalServiceInsights[serviceKey] ? <Loader2 className="w-3 h-3 mr-1.5 animate-spin" /> : <Sparkles className="w-3 h-3 mr-1.5" />}
                                                Identify Service with AI
                                            </Button>
                                        )}
                                    </div>
                                    {isFetchingAiLocalServiceInsights[serviceKey] && (
                                        <div className="p-3 border-t border-gray-200 text-sm text-indigo-700 flex items-center bg-indigo-50/30">
                                            <Loader2 className="w-4 h-4 mr-2 animate-spin" /> Fetching AI insights for {service.port}/{service.protocol}...
                                        </div>
                                    )}
                                    {aiLocalServiceInsights[serviceKey] && !isFetchingAiLocalServiceInsights[serviceKey] && (
                                        <div className="p-4 border-t border-gray-200 bg-indigo-50/30">
                                            <h4 className="text-sm font-semibold text-indigo-800 mb-2 flex items-center">
                                                <Lightbulb className="w-4 h-4 mr-1.5 text-yellow-500" />
                                                AI Insights for {service.port}/{service.protocol}:
                                            </h4>
                                            <pre className="whitespace-pre-wrap text-xs text-gray-700 bg-white p-3 rounded-md shadow-sm overflow-x-auto font-sans">
                                                {aiLocalServiceInsights[serviceKey]}
                                            </pre>
                                        </div>
                                    )}
                                </Card>
                            )
                        })}
                    </div>
                    ) : <p className="text-gray-500 italic py-4 text-center">No local services (on 127.0.0.1) identified in the current analysis.</p>}
                     <p className="text-xs text-gray-500 mt-6 italic">AI-powered local service identification can help understand common software using these ports. Always verify critical findings.</p>
                </CardContent>
                </Card>
            )}
            {activeTab === 'localServices' && !latestAnalysisResults && (
                <div className="text-center py-10">
                    <HardDrive className="w-16 h-16 text-gray-300 mx-auto mb-3" />
                    <p className="text-lg text-gray-500">No analysis loaded for Local Services.</p>
                </div>
            )}


            {activeTab === 'connections' && latestAnalysisResults && !latestAnalysisResults.error && (
                <Card className="shadow-inner">
                <CardHeader>
                    <CardTitle className="flex items-center text-gray-700">
                    <AlertTriangle className="w-5 h-5 mr-2 text-orange-500" />
                    Connections Requiring Attention ({filteredConnections.length} / {latestAnalysisResults.suspiciousConnections.length}) (Current View)
                    </CardTitle>
                    <CardDescription>Network connections flagged due to potential security risks or noteworthy characteristics.</CardDescription>
                </CardHeader>
                <CardContent>
                    <div className="mb-6 p-4 bg-gray-50 rounded-lg border flex flex-col sm:flex-row gap-4 items-center sticky top-0 z-10 bg-opacity-95 backdrop-blur-sm">
                    <div className="flex-1 w-full sm:w-auto">
                        <label htmlFor="filterRisk" className="block text-sm font-medium text-gray-700 mb-1">Filter by Risk</label>
                        <select 
                        id="filterRisk"
                        value={filterRisk} 
                        onChange={(e) => setFilterRisk(e.target.value as RiskLevel | 'all')}
                        className="w-full p-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500"
                        aria-label="Filter connections by risk level"
                        >
                        <option value="all">All Flagged</option>
                        <option value="critical">Critical</option>
                        <option value="suspicious">Suspicious</option>
                        <option value="warning">Warning</option>
                        </select>
                    </div>
                    <div className="flex-1 w-full sm:w-auto">
                        <label htmlFor="searchTerm" className="block text-sm font-medium text-gray-700 mb-1">Search Connections</label>
                        <div className="relative">
                        <input 
                            type="text" 
                            id="searchTerm"
                            placeholder="IP, port, PID, state, issue..." 
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="w-full p-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 pl-10"
                            aria-label="Search risky connections"
                        />
                        <Search className="w-5 h-5 text-gray-400 absolute left-3 top-1/2 transform -translate-y-1/2" />
                        </div>
                    </div>
                    </div>

                    {filteredConnections.length > 0 ? (
                    <div className="space-y-4">
                        {filteredConnections.map((conn, index) => {
                            const uniqueConnId = `${conn.raw}-${index}`; // Create a unique ID for expansion state
                            return (
                                <Card key={uniqueConnId} className={`border rounded-lg overflow-hidden shadow-sm hover:shadow-md transition-shadow ${conn.risk === 'critical' ? 'border-red-300 bg-red-50/30' : conn.risk === 'suspicious' ? 'border-orange-300 bg-orange-50/30' : 'border-yellow-300 bg-yellow-50/30'}`}>
                                <div className="p-4">
                                <div className="grid grid-cols-1 md:grid-cols-4 gap-x-4 gap-y-2 items-start">
                                    <div className="md:col-span-3">
                                    <div className="font-mono text-xs sm:text-sm break-all mb-1">
                                        <span className={`font-semibold ${getRiskBarColor(conn.risk).replace('bg-','text-')} `}>{conn.protocol}</span>: {conn.localAddress} &harr; {conn.foreignAddress}
                                    </div>
                                    <div className="text-xs text-gray-500">
                                        State: <span className="font-medium text-gray-700">{conn.state}</span>
                                        {conn.pid && ` | PID: <span className="font-medium text-gray-700">${conn.pid}</span>`}
                                        {conn.portInfo && ` | Service: <span className="font-medium text-gray-700">${conn.portInfo.name}</span>`}
                                    </div>
                                    </div>
                                    <div className="flex flex-col md:items-end space-y-1 items-start mt-2 md:mt-0">
                                    {getRiskBadge(conn.risk)}
                                    {conn.issues && conn.issues.length > 0 && (
                                        <Button variant="ghost" size="sm" onClick={() => toggleIssueExpansion(uniqueConnId)} aria-expanded={!!expandedIssues[uniqueConnId]} className="text-blue-600 hover:bg-blue-100 h-8 px-2 mt-1">
                                        {expandedIssues[uniqueConnId] ? <ChevronUp className="w-4 h-4 mr-1" /> : <ChevronDown className="w-4 h-4 mr-1" />}
                                        {expandedIssues[uniqueConnId] ? 'Hide Issues' : 'Show Issues'} ({conn.issues.length})
                                        </Button>
                                    )}
                                    </div>
                                </div>
                                </div>
                                {expandedIssues[uniqueConnId] && conn.issues && conn.issues.length > 0 && (
                                <div className={`px-4 pb-4 pt-2 border-t bg-opacity-50 ${conn.risk === 'critical' ? 'bg-red-50' : conn.risk === 'suspicious' ? 'bg-orange-50' : 'bg-yellow-50'}`}>
                                    <h4 className="text-sm font-semibold text-gray-800 mb-2">Identified Issues:</h4>
                                    <ul className="list-disc list-inside space-y-1.5 text-xs text-gray-700">
                                    {conn.issues.map((issue, i) => <li key={i}>{issue}</li>)}
                                    </ul>
                                </div>
                                )}
                            </Card>
                            )
                        })}
                    </div>
                    ) : (
                    <div className="text-center py-10">
                        <Search className="w-16 h-16 text-gray-300 mx-auto mb-3" />
                        <p className="text-lg text-gray-500">No connections match your current filters in the current view.</p>
                        {latestAnalysisResults.suspiciousConnections.length === 0 && <p className="text-sm text-gray-400 mt-1">No connections were flagged as requiring attention in the initial analysis of the current view.</p>}
                    </div>
                    )}
                </CardContent>
                </Card>
            )}
             {activeTab === 'connections' && !latestAnalysisResults && (
                <div className="text-center py-10">
                    <AlertTriangle className="w-16 h-16 text-gray-300 mx-auto mb-3" />
                    <p className="text-lg text-gray-500">No analysis loaded for risky connections.</p>
                </div>
            )}

            {activeTab === 'riskMatrix' && latestAnalysisResults && !latestAnalysisResults.error && (
                <Card className="shadow-inner">
                    <CardHeader>
                        <CardTitle className="flex items-center text-gray-700">
                            <TableProperties className="w-5 h-5 mr-2 text-blue-500" />
                             Interaction Risk Matrix ({filteredRiskMatrixCells.length} / {riskMatrixCells.length}) (Current View)
                        </CardTitle>
                        <CardDescription>Detailed matrix of all unique network interactions (Local &harr; Foreign). Sorted by overall risk, with cell-specific AI insights.
                            <br/>
                            <span className="text-xs text-gray-500">
                                Summary: {riskMatrixSummary.totalPairs} unique pairs | 
                                {riskMatrixSummary.criticalPairs} critical | 
                                {riskMatrixSummary.suspiciousPairs} suspicious | 
                                {riskMatrixSummary.listenerInteractions} listener interactions.
                            </span>
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        <div className="mb-6 p-4 bg-gray-50 rounded-lg border flex flex-col sm:flex-row gap-4 items-center sticky top-0 z-10 bg-opacity-95 backdrop-blur-sm">
                            <div className="flex-1 w-full sm:w-auto">
                                <label htmlFor="riskMatrixFilterRisk" className="block text-sm font-medium text-gray-700 mb-1">Filter by Risk</label>
                                <select
                                    id="riskMatrixFilterRisk"
                                    value={riskMatrixFilterRisk}
                                    onChange={(e) => setRiskMatrixFilterRisk(e.target.value as RiskLevel | 'all')}
                                    className="w-full p-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500"
                                    aria-label="Filter matrix cells by risk level"
                                >
                                    <option value="all">All Interactions</option>
                                    <option value="critical">Critical</option>
                                    <option value="suspicious">Suspicious</option>
                                    <option value="warning">Warning</option>
                                    <option value="safe">Safe</option>
                                    <option value="unknown">Unknown</option>
                                </select>
                            </div>
                            <div className="flex-1 w-full sm:w-auto">
                                <label htmlFor="riskMatrixSearchTerm" className="block text-sm font-medium text-gray-700 mb-1">Search Matrix</label>
                                <div className="relative">
                                    <input
                                        type="text"
                                        id="riskMatrixSearchTerm"
                                        placeholder="IP, port, PID, state, issue..."
                                        value={riskMatrixSearchTerm}
                                        onChange={(e) => setRiskMatrixSearchTerm(e.target.value)}
                                        className="w-full p-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 pl-10"
                                        aria-label="Search risk matrix"
                                    />
                                    <Search className="w-5 h-5 text-gray-400 absolute left-3 top-1/2 transform -translate-y-1/2" />
                                </div>
                            </div>
                        </div>

                        {filteredRiskMatrixCells.length > 0 ? (
                            <div className="overflow-x-auto">
                                <table className="min-w-full divide-y divide-gray-200 text-sm">
                                    <thead className="bg-gray-100">
                                        <tr>
                                            <th scope="col" className="px-3 py-2.5 text-left font-semibold text-gray-600">Risk</th>
                                            <th scope="col" className="px-3 py-2.5 text-left font-semibold text-gray-600">Local Address</th>
                                            <th scope="col" className="px-3 py-2.5 text-left font-semibold text-gray-600">Foreign Address</th>
                                            <th scope="col" className="px-3 py-2.5 text-left font-semibold text-gray-600">Protocol</th>
                                            <th scope="col" className="px-3 py-2.5 text-left font-semibold text-gray-600">States</th>
                                            <th scope="col" className="px-3 py-2.5 text-left font-semibold text-gray-600">Count</th>
                                            <th scope="col" className="px-3 py-2.5 text-left font-semibold text-gray-600">PIDs</th>
                                            <th scope="col" className="px-3 py-2.5 text-left font-semibold text-gray-600">Issues</th>
                                            <th scope="col" className="px-3 py-2.5 text-left font-semibold text-gray-600">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody className="bg-white divide-y divide-gray-200">
                                        {filteredRiskMatrixCells.map((cell) => (
                                            <React.Fragment key={cell.id}>
                                            <tr className={`hover:bg-gray-50/50 ${cell.isListenerInteraction ? 'bg-blue-50/20' : ''} ${cell.risk === 'critical' ? 'bg-red-50/60 even:bg-red-100/40' : cell.risk === 'suspicious' ? 'bg-orange-50/60 even:bg-orange-100/40' : cell.risk === 'warning' ? 'bg-yellow-50/60 even:bg-yellow-100/40' : 'even:bg-gray-50/30'}`}>
                                                <td className="px-3 py-2.5 whitespace-nowrap">
                                                    <div className="flex items-center">
                                                        {getRiskBadge(cell.risk)}
                                                        {cell.isListenerInteraction && <MessageSquareWarning className="w-3.5 h-3.5 ml-1 text-blue-500" title="Represents a Listening Port Interaction" />}
                                                    </div>
                                                </td>
                                                <td className={`px-3 py-2.5 whitespace-nowrap font-mono text-xs ${getTextColorForRisk(cell.risk)}`} title={cell.localAddress}>{cell.localAddress}</td>
                                                <td className={`px-3 py-2.5 whitespace-nowrap font-mono text-xs ${getTextColorForRisk(cell.risk)}`} title={cell.foreignAddress}>{cell.foreignAddress}</td>
                                                <td className={`px-3 py-2.5 whitespace-nowrap ${getTextColorForRisk(cell.risk)}`}>{cell.protocol}</td>
                                                <td className="px-3 py-2.5 whitespace-nowrap">
                                                    {Array.from(cell.states).map(s => <Badge key={s} variant="secondary" className="mr-1 mb-1 text-xs">{s}</Badge>)}
                                                </td>
                                                <td className={`px-3 py-2.5 whitespace-nowrap text-center ${getTextColorForRisk(cell.risk)}`}>{cell.connectionCount}</td>
                                                <td className={`px-3 py-2.5 whitespace-nowrap font-mono text-xs max-w-[100px] truncate`} title={Array.from(cell.aggregatedPIDs).join(', ') || 'N/A'}>
                                                    {Array.from(cell.aggregatedPIDs).length > 0 ? (
                                                        <span className={getTextColorForRisk(cell.risk)}>{Array.from(cell.aggregatedPIDs).join(', ')}</span>
                                                    ) : (
                                                        <span className="text-gray-500">N/A</span>
                                                    )}
                                                </td>
                                                <td className={`px-3 py-2.5 max-w-xs truncate`}>
                                                    {cell.issues.length > 0 ? (
                                                        <span className={getTextColorForRisk(cell.risk)} title={cell.issues.join(', ')}>
                                                            {cell.issues[0].substring(0,30)}{cell.issues[0].length > 30 ? '...' : ''} {cell.issues.length > 1 ? ` (+${cell.issues.length-1})` : ''}
                                                        </span>
                                                    ) : (
                                                        <span className="text-gray-500">None</span>
                                                    )}
                                                </td>
                                                <td className="px-3 py-2.5 whitespace-nowrap">
                                                    {ai && effectiveApiKey && (
                                                        <Button
                                                            variant="ghost"
                                                            size="icon"
                                                            onClick={() => fetchAiRiskMatrixCellInsight(cell)}
                                                            disabled={isFetchingAiRiskMatrixCellInsights[cell.id] || !effectiveApiKey}
                                                            className="h-7 w-7 text-purple-600 hover:bg-purple-100"
                                                            title="Get AI Insight for this interaction"
                                                        >
                                                            {isFetchingAiRiskMatrixCellInsights[cell.id] ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5" />}
                                                        </Button>
                                                    )}
                                                </td>
                                            </tr>
                                            {isFetchingAiRiskMatrixCellInsights[cell.id] && (
                                                <tr>
                                                    <td colSpan={9} className="p-2 bg-purple-50/30 text-xs text-purple-700">
                                                        <div className="flex items-center">
                                                           <Loader2 className="w-3.5 h-3.5 mr-2 animate-spin" /> Fetching AI insight for {cell.localAddress} &harr; {cell.foreignAddress}...
                                                        </div>
                                                    </td>
                                                </tr>
                                            )}
                                            {aiRiskMatrixCellInsights[cell.id] && !isFetchingAiRiskMatrixCellInsights[cell.id] && (
                                                <tr>
                                                     <td colSpan={9} className="p-3 bg-purple-50/50 border-t border-purple-200">
                                                        <h5 className="text-xs font-semibold text-purple-800 mb-1 flex items-center">
                                                            <Lightbulb className="w-3.5 h-3.5 mr-1 text-yellow-500" />
                                                            AI Insight for {cell.localAddress} &harr; {cell.foreignAddress}:
                                                        </h5>
                                                        <pre className="whitespace-pre-wrap text-xs text-gray-700 bg-white p-2 rounded shadow-sm font-sans">
                                                            {aiRiskMatrixCellInsights[cell.id]}
                                                        </pre>
                                                    </td>
                                                </tr>
                                            )}
                                            </React.Fragment>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        ) : (
                             <div className="text-center py-10">
                                <Search className="w-16 h-16 text-gray-300 mx-auto mb-3" />
                                <p className="text-lg text-gray-500">No interactions match your current filters in the current view.</p>
                                {riskMatrixCells.length === 0 && <p className="text-sm text-gray-400 mt-1">No interaction data available in the current analysis.</p>}
                            </div>
                        )}
                        <p className="text-xs text-gray-500 mt-4 italic">AI insights for specific interactions can help contextualize aggregated findings. Listener interactions are highlighted.</p>
                    </CardContent>
                </Card>
            )}
             {activeTab === 'riskMatrix' && !latestAnalysisResults && (
                <div className="text-center py-10">
                    <TableProperties className="w-16 h-16 text-gray-300 mx-auto mb-3" />
                    <p className="text-lg text-gray-500">No analysis loaded for Risk Matrix.</p>
                </div>
            )}


            {activeTab === 'portUsage' && latestAnalysisResults && !latestAnalysisResults.error && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <Card className="shadow-inner">
                <CardHeader>
                    <CardTitle className="flex items-center text-gray-700">
                    <ListTree className="w-5 h-5 mr-2 text-green-500" />
                    Local Port Activity (Current View)
                    </CardTitle>
                    <CardDescription>
                        Usage of local ports ({localPortUsageSummary.totalUnique} unique). 
                        Includes {localPortUsageSummary.listeningCount} exposed listeners. 
                        Top active: {localPortUsageSummary.top3Active.join(', ') || 'N/A'}.
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    {latestAnalysisResults.allLocalPortsActivity.length > 0 ? (
                    <div className="max-h-[600px] overflow-y-auto space-y-2 pr-2">
                    {latestAnalysisResults.allLocalPortsActivity.map((p) => (
                        <Card key={`${p.port}-${p.protocol}-local`} className="p-3 border rounded-md text-sm hover:shadow-md transition-shadow">
                        <div className="flex justify-between items-center mb-1">
                            <div className="font-semibold text-gray-800">{p.port}/{p.protocol} ({p.service})</div>
                            {getRiskBadge(p.risk)}
                        </div>
                        <p className="text-xs text-gray-500 mb-1 truncate" title={p.description}>{p.description}</p>
                        <div className="text-xs text-gray-600">Usage Count: {p.count}</div>
                        </Card>
                    ))}
                    </div>
                    ) : <p className="text-gray-500 italic">No local port activity data found.</p>}
                </CardContent>
                </Card>

                <Card className="shadow-inner">
                <CardHeader>
                    <CardTitle className="flex items-center text-gray-700">
                    <ListTree className="w-5 h-5 mr-2 text-red-500" />
                    Foreign Port Activity (Current View)
                    </CardTitle>
                    <CardDescription>
                        Connections to foreign ports ({foreignPortUsageSummary.totalUnique} unique). 
                        {foreignPortUsageSummary.riskyCount} involve risky ports. 
                        Top connected: {foreignPortUsageSummary.top3Active.join(', ') || 'N/A'}.
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    {latestAnalysisResults.allForeignPortsActivity.length > 0 ? (
                     <div className="max-h-[600px] overflow-y-auto space-y-2 pr-2">
                    {latestAnalysisResults.allForeignPortsActivity.map((p) => (
                        <Card key={`${p.port}-${p.protocol}-foreign`} className="p-3 border rounded-md text-sm hover:shadow-md transition-shadow">
                        <div className="flex justify-between items-center mb-1">
                            <div className="font-semibold text-gray-800">{p.port}/{p.protocol} ({p.service})</div>
                            {getRiskBadge(p.risk)}
                        </div>
                        <p className="text-xs text-gray-500 mb-1 truncate" title={p.description}>{p.description}</p>
                        <div className="text-xs text-gray-600">Connection Count: {p.count}</div>
                        </Card>
                    ))}
                    </div>
                    ) : <p className="text-gray-500 italic">No foreign port activity data found.</p>}
                </CardContent>
                </Card>
            </div>
            )}
            {activeTab === 'portUsage' && !latestAnalysisResults && (
                <div className="text-center py-10">
                    <ListTree className="w-16 h-16 text-gray-300 mx-auto mb-3" />
                    <p className="text-lg text-gray-500">No analysis loaded for port usage.</p>
                </div>
            )}


            {activeTab === 'ipAnalysis' && latestAnalysisResults && !latestAnalysisResults.error && (
                <Card className="shadow-inner">
                    <CardHeader>
                        <CardTitle className="flex items-center text-gray-700">
                            <Globe className="w-5 h-5 mr-2 text-blue-500" />
                            External IP Analysis ({externalIpList.length} Unique Public IPs) (Current View)
                        </CardTitle>
                        <CardDescription>Details of unique external IP addresses involved in connections. Enhanced with AI reputation checks.</CardDescription>
                    </CardHeader>
                    <CardContent>
                        {externalIpList.length > 0 ? (
                            <div className="space-y-4">
                                {externalIpList.map(ipDetail => {
                                    const ipKey = ipDetail.ip;
                                    return (
                                    <Card key={ipKey} className="border rounded-lg overflow-hidden shadow-sm">
                                        <div className="p-4">
                                            <div className="flex flex-col sm:flex-row justify-between items-start mb-2">
                                                <div className="flex items-center space-x-3 mb-2 sm:mb-0">
                                                    <div className={`w-3 h-3 rounded-full mr-1 ${getRiskColorIndicator(ipDetail.risk)} flex-shrink-0`}></div>
                                                    <div className="font-mono text-gray-800 text-lg">{ipDetail.ip}</div>
                                                    {renderThreatIntelBadge(ipDetail.ip)}
                                                </div>
                                                 <div className="flex flex-col items-start sm:items-end space-y-1">
                                                    {getRiskBadge(ipDetail.risk)}
                                                    <span className="text-xs text-gray-500">Connections: {ipDetail.connections}</span>
                                                </div>
                                            </div>
                                            <p className="text-xs text-gray-600 mb-2">
                                                Ports: {Array.from(ipDetail.ports).slice(0,5).join(', ')} 
                                                {ipDetail.ports.size > 5 && ` (+${ipDetail.ports.size-5} more)`}
                                            </p>
                                            {ai && effectiveApiKey && (
                                            <Button
                                                size="sm"
                                                variant="outline"
                                                onClick={() => fetchAiIpReputation(ipDetail.ip, ipDetail)}
                                                disabled={isFetchingAiIpInsights[ipKey] || !effectiveApiKey}
                                                className="border-blue-500 text-blue-600 hover:bg-blue-50 hover:text-blue-700 whitespace-nowrap text-xs"
                                            >
                                                {isFetchingAiIpInsights[ipKey] ? <Loader2 className="w-3 h-3 mr-1.5 animate-spin" /> : <Sparkles className="w-3 h-3 mr-1.5" />}
                                                Get AI Reputation Analysis (with Search)
                                            </Button>
                                            )}
                                        </div>
                                        {isFetchingAiIpInsights[ipKey] && (
                                            <div className="p-3 border-t border-gray-200 text-sm text-blue-700 flex items-center bg-blue-50/30">
                                                <Loader2 className="w-4 h-4 mr-2 animate-spin" /> Fetching AI insights for {ipDetail.ip}...
                                            </div>
                                        )}
                                        {aiIpInsights[ipKey] && !isFetchingAiIpInsights[ipKey] && (
                                            <div className="p-4 border-t border-gray-200 bg-blue-50/30">
                                                <h4 className="text-sm font-semibold text-blue-800 mb-2 flex items-center">
                                                    <Lightbulb className="w-4 h-4 mr-1.5 text-yellow-500" />
                                                    AI Insights for {ipDetail.ip}:
                                                </h4>
                                                <pre className="whitespace-pre-wrap text-xs text-gray-700 bg-white p-3 rounded-md shadow-sm overflow-x-auto font-sans">
                                                    {aiIpInsights[ipKey]}
                                                </pre>
                                            </div>
                                        )}
                                    </Card>
                                )})}
                            </div>
                        ) : <p className="text-gray-500 italic text-center py-4">No external IP addresses found in the current analysis.</p>}
                        <p className="text-xs text-gray-500 mt-6 italic">AI-powered IP reputation uses Google Search and may take a moment. Always verify critical findings.</p>
                    </CardContent>
                </Card>
            )}
            {activeTab === 'ipAnalysis' && !latestAnalysisResults && (
                 <div className="text-center py-10">
                    <Globe className="w-16 h-16 text-gray-300 mx-auto mb-3" />
                    <p className="text-lg text-gray-500">No analysis loaded for IP analysis.</p>
                </div>
            )}
           

            {activeTab === 'timeline' && (
                <div className="space-y-6">
                    <Card className="shadow-inner">
                        <CardHeader>
                            <CardTitle className="flex items-center text-gray-700">
                                <History className="w-5 h-5 mr-2 text-purple-500" />
                                Analysis History & Timeline
                            </CardTitle>
                            <CardDescription>Review past analyses or track a specific IP's activity across snapshots.</CardDescription>
                        </CardHeader>
                        <CardContent>
                            {historicalAnalyses.length > 0 ? (
                                <div className="space-y-3 mb-6">
                                    <h3 className="text-md font-semibold text-gray-700 mb-1">Available Snapshots ({historicalAnalyses.length}):</h3>
                                    {historicalAnalyses.sort((a,b) => b.timestamp.getTime() - a.timestamp.getTime()).map(snap => (
                                        <div key={snap.id} className="p-3 border rounded-md flex flex-col sm:flex-row justify-between items-start sm:items-center bg-white hover:bg-gray-50/50 transition-colors">
                                           <div>
                                                <span className="font-medium text-gray-800">{snap.name}</span>
                                                <span className="text-xs text-gray-500 block sm:inline sm:ml-2">
                                                    {new Date(snap.timestamp).toLocaleString()}
                                                    {snap.results.error && <Badge variant="destructive" className="ml-2">Error</Badge>}
                                                </span>
                                            </div>
                                            <div className="flex space-x-2 mt-2 sm:mt-0">
                                                <Button size="sm" variant="outline" onClick={() => loadSnapshot(snap.id)} className="text-xs">
                                                    <Eye className="w-3.5 h-3.5 mr-1.5" /> Load Snapshot
                                                </Button>
                                                <Button size="sm" variant="ghost" onClick={() => removeSnapshot(snap.id)} className="text-red-500 hover:bg-red-100 text-xs">
                                                    <Trash2 className="w-3.5 h-3.5 mr-1.5" /> Remove
                                                </Button>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            ) : <p className="text-gray-500 italic mb-6 text-center py-3">No analysis history yet. Upload and analyze files to build a timeline.</p>}

                            <hr className="my-6"/>

                            <div>
                                <h3 className="text-md font-semibold text-gray-700 mb-2">Track IP Across Snapshots:</h3>
                                <div className="flex flex-col sm:flex-row gap-2 mb-4 items-end">
                                    <div className="flex-grow">
                                        <label htmlFor="timelineIp" className="block text-xs font-medium text-gray-600 mb-0.5">Enter IP Address:</label>
                                        <input 
                                            type="text" 
                                            id="timelineIp"
                                            placeholder="e.g., 192.168.1.100 or 127.0.0.1" 
                                            value={selectedIpForTimeline}
                                            onChange={(e) => setSelectedIpForTimeline(e.target.value)}
                                            className="p-2 border border-gray-300 rounded-md shadow-sm w-full focus:ring-purple-500 focus:border-purple-500"
                                        />
                                    </div>
                                    <Button onClick={() => setTimelineIpDisplay(selectedIpForTimeline)} disabled={!selectedIpForTimeline} className="bg-purple-600 hover:bg-purple-700 disabled:bg-purple-300">
                                        <Search className="w-4 h-4 mr-2" /> Track IP
                                    </Button>
                                </div>

                                {timelineIpDisplay && ipTimeline.length > 0 && (
                                    <div>
                                        <h4 className="text-sm font-semibold text-gray-700 my-3">Timeline for IP: <span className="font-mono text-purple-700">{timelineIpDisplay}</span> ({ipTimeline.filter(e => e.ipFound).length} snapshots found)</h4>
                                        <div className="space-y-4">
                                            {ipTimeline.map(entry => (
                                                <Card key={entry.snapshotId} className={`border rounded-lg ${entry.ipFound ? 'bg-purple-50/30 border-purple-200' : 'bg-gray-50 border-gray-200'}`}>
                                                    <CardHeader className="pb-3 pt-4 px-4">
                                                        <div className="flex justify-between items-center">
                                                          <CardTitle className="text-sm font-semibold text-purple-800">
                                                            {entry.snapshotName}
                                                          </CardTitle>
                                                          <span className="text-xs text-gray-500">{new Date(entry.snapshotTimestamp).toLocaleDateString()} {new Date(entry.snapshotTimestamp).toLocaleTimeString()}</span>
                                                        </div>
                                                    </CardHeader>
                                                    <CardContent className="px-4 pb-4 text-xs">
                                                        {!entry.ipFound ? (
                                                            <p className="italic text-gray-500">IP <span className="font-mono">{timelineIpDisplay}</span> not found in this snapshot.</p>
                                                        ) : (
                                                            <div className="space-y-1.5">
                                                                <div className="flex justify-between items-center">
                                                                    <span className="font-medium">Overall Risk Related to IP:</span> {getRiskBadge(entry.summary?.risk || 'unknown')}
                                                                </div>
                                                                <p><span className="font-medium">Total Connections involving IP:</span> {entry.summary?.connectionCount}</p>
                                                                {entry.connectionsFromIp.length > 0 && <div><span className="font-medium">Services Hosted/Listening on IP:</span> <span className="font-mono">{entry.connectionsFromIp.map(c => `${extractIPPort(c.localAddress)[1] || 'N/A'}/${c.protocol} (${c.portInfo?.name || 'Unknown'})`).join(', ')}</span></div>}
                                                                {entry.connectionsToIp.length > 0 && <div><span className="font-medium">Outbound Connections Made by IP:</span> {entry.connectionsToIp.length} (to various remote services)</div>}
                                                                
                                                                {entry.summary && (
                                                                <>
                                                                    <p><span className="font-medium">Ports on {timelineIpDisplay} involved:</span> {entry.summary.allPortsInvolvedWithIp.join(', ') || 'N/A'}</p>
                                                                    <p><span className="font-medium">Connection States:</span> {entry.summary.connectionStates.join(', ') || 'N/A'}</p>
                                                                </>
                                                                )}
                                                            </div>
                                                        )}
                                                    </CardContent>
                                                </Card>
                                            ))}
                                        </div>
                                    </div>
                                )}
                                {timelineIpDisplay && ipTimeline.length === 0 && historicalAnalyses.length > 0 && (
                                    <p className="text-gray-500 italic text-center py-3">No activity found for IP <span className="font-mono">{timelineIpDisplay}</span> in any snapshot.</p>
                                )}
                            </div>
                        </CardContent>
                    </Card>
                </div>
            )}

            {activeTab === 'settings' && (
                <div className="space-y-6">
                    <Card className="shadow-lg">
                        <CardHeader>
                            <CardTitle className="flex items-center">
                                <Key className="w-6 h-6 mr-2 text-blue-600" />
                                API Key Configuration
                            </CardTitle>
                            <CardDescription>
                                Configure your Google Gemini API key to enable AI-powered analysis features.
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <div className="space-y-2">
                                <label htmlFor="api-key-input" className="text-sm font-medium text-gray-700">
                                    Gemini API Key
                                </label>
                                <div className="relative">
                                    <Input
                                        id="api-key-input"
                                        type={showApiKey ? "text" : "password"}
                                        placeholder="Enter your Google Gemini API key..."
                                        value={tempApiKey}
                                        onChange={(e) => setTempApiKey(e.target.value)}
                                        variant={isApiKeyValid === false ? "error" : "default"}
                                        className="pr-20"
                                    />
                                    <div className="absolute inset-y-0 right-0 flex items-center space-x-1 pr-3">
                                        <Button
                                            type="button"
                                            variant="ghost"
                                            size="icon"
                                            onClick={() => setShowApiKey(!showApiKey)}
                                            className="h-8 w-8 text-gray-500 hover:text-gray-700"
                                        >
                                            {showApiKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                                        </Button>
                                    </div>
                                </div>
                                {isApiKeyValid === false && (
                                    <p className="text-sm text-red-600">
                                        Invalid API key. Please check your key and try again.
                                    </p>
                                )}
                                {isApiKeyValid === true && (
                                    <p className="text-sm text-green-600">
                                        API key is valid and ready to use.
                                    </p>
                                )}
                            </div>

                            <div className="flex space-x-3">
                                <Button
                                    onClick={async () => {
                                        const isValid = await validateApiKey(tempApiKey);
                                        if (isValid) {
                                            saveApiKey(tempApiKey);
                                        }
                                    }}
                                    disabled={!tempApiKey.trim() || isValidatingApiKey}
                                    className="bg-blue-600 hover:bg-blue-700"
                                >
                                    {isValidatingApiKey ? (
                                        <>
                                            <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                                            Validating...
                                        </>
                                    ) : (
                                        <>
                                            <Save className="w-4 h-4 mr-2" />
                                            Save & Validate
                                        </>
                                    )}
                                </Button>

                                <Button
                                    variant="outline"
                                    onClick={() => {
                                        setTempApiKey(userApiKey);
                                        setIsApiKeyValid(null);
                                    }}
                                >
                                    Load Current Key
                                </Button>

                                <Button
                                    variant="outline"
                                    onClick={() => {
                                        setTempApiKey('');
                                        setIsApiKeyValid(null);
                                    }}
                                >
                                    Clear
                                </Button>
                            </div>

                            <div className="bg-blue-50 p-4 rounded-lg">
                                <h4 className="font-semibold text-blue-900 mb-2">Current Status:</h4>
                                <div className="space-y-1 text-sm">
                                    <p>
                                        <span className="font-medium">Environment API Key:</span>
                                        <span className={apiKeyFromEnv ? "text-green-600" : "text-gray-500"}>
                                            {apiKeyFromEnv ? " ✓ Available" : " Not configured"}
                                        </span>
                                    </p>
                                    <p>
                                        <span className="font-medium">User API Key:</span>
                                        <span className={userApiKey ? "text-green-600" : "text-gray-500"}>
                                            {userApiKey ? " ✓ Configured" : " Not configured"}
                                        </span>
                                    </p>
                                    <p>
                                        <span className="font-medium">Effective API Key:</span>
                                        <span className={effectiveApiKey ? "text-green-600" : "text-red-600"}>
                                            {effectiveApiKey ? " ✓ Available (AI features enabled)" : " ✗ Not available (AI features disabled)"}
                                        </span>
                                    </p>
                                </div>
                            </div>

                            <Alert>
                                <Info className="w-4 h-4" />
                                <AlertTitle>How to get a Gemini API Key</AlertTitle>
                                <AlertDescription>
                                    <ol className="list-decimal list-inside space-y-1 mt-2">
                                        <li>Visit <a href="https://aistudio.google.com/app/apikey" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">Google AI Studio</a></li>
                                        <li>Sign in with your Google account</li>
                                        <li>Click "Create API Key" and select a project</li>
                                        <li>Copy the generated API key and paste it above</li>
                                    </ol>
                                    <p className="mt-2 text-sm text-gray-600">
                                        Your API key is stored locally in your browser and is never sent to our servers.
                                    </p>
                                </AlertDescription>
                            </Alert>
                        </CardContent>
                    </Card>

                    {/* Threat Intelligence Configuration */}
                    <Card className="shadow-lg">
                        <CardHeader>
                            <CardTitle className="flex items-center">
                                <ShieldIcon className="w-6 h-6 mr-2 text-red-600" />
                                Custom Threat Intelligence Lists
                            </CardTitle>
                            <CardDescription>
                                Add custom IP threat intelligence lists to enhance security analysis. IPs matching these lists will be flagged during analysis.
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            {/* Threat Intel Lists Management */}
                            <div className="flex justify-between items-center">
                                <h4 className="font-semibold text-gray-700">Threat Intelligence Lists</h4>
                                <div className="flex space-x-2">
                                    <Button
                                        onClick={exportThreatIntelLists}
                                        size="sm"
                                        variant="outline"
                                        disabled={threatIntelLists.length === 0}
                                        className="text-blue-600 hover:bg-blue-50"
                                    >
                                        <DownloadIcon className="w-4 h-4 mr-2" />
                                        Export
                                    </Button>
                                    <label className="cursor-pointer">
                                        <input
                                            type="file"
                                            accept=".json"
                                            onChange={importThreatIntelLists}
                                            className="hidden"
                                        />
                                        <span className="inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:opacity-50 disabled:pointer-events-none ring-offset-background border border-input hover:bg-accent hover:text-accent-foreground h-9 px-3 text-green-600 hover:bg-green-50">
                                            <UploadIcon className="w-4 h-4 mr-2" />
                                            Import
                                        </span>
                                    </label>
                                    <Button
                                        onClick={() => setIsAddingThreatList(true)}
                                        size="sm"
                                        className="bg-red-600 hover:bg-red-700"
                                    >
                                        <Plus className="w-4 h-4 mr-2" />
                                        Add List
                                    </Button>
                                </div>
                            </div>

                            {/* Add New Threat List Form */}
                            {isAddingThreatList && (
                                <div className="bg-gray-50 p-4 rounded-lg space-y-3">
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                        <div>
                                            <label className="text-sm font-medium text-gray-700">List Name</label>
                                            <Input
                                                placeholder="e.g., Known Malicious IPs"
                                                value={newThreatListName}
                                                onChange={(e) => setNewThreatListName(e.target.value)}
                                            />
                                        </div>
                                        <div>
                                            <label className="text-sm font-medium text-gray-700">Description</label>
                                            <Input
                                                placeholder="Brief description of this threat list"
                                                value={newThreatListDescription}
                                                onChange={(e) => setNewThreatListDescription(e.target.value)}
                                            />
                                        </div>
                                    </div>
                                    <div className="flex space-x-2">
                                        <Button
                                            onClick={createThreatIntelList}
                                            disabled={!newThreatListName.trim()}
                                            size="sm"
                                            className="bg-green-600 hover:bg-green-700"
                                        >
                                            <Save className="w-4 h-4 mr-2" />
                                            Create List
                                        </Button>
                                        <Button
                                            onClick={() => {
                                                setIsAddingThreatList(false);
                                                setNewThreatListName('');
                                                setNewThreatListDescription('');
                                            }}
                                            variant="outline"
                                            size="sm"
                                        >
                                            Cancel
                                        </Button>
                                    </div>
                                </div>
                            )}

                            {/* Existing Threat Lists */}
                            <div className="space-y-3">
                                {threatIntelLists.length === 0 ? (
                                    <div className="text-center py-8 text-gray-500">
                                        <ShieldIcon className="w-12 h-12 mx-auto mb-3 text-gray-300" />
                                        <p>No threat intelligence lists configured.</p>
                                        <p className="text-sm">Add a list to start building your custom threat intelligence.</p>
                                    </div>
                                ) : (
                                    <div>
                                        {threatIntelLists.map(list => (
                                        <div key={list.id} className="border rounded-lg p-4 space-y-3">
                                            <div className="flex justify-between items-start">
                                                <div className="flex-1">
                                                    <div className="flex items-center space-x-2">
                                                        <h5 className="font-semibold text-gray-800">{list.name}</h5>
                                                        <Badge variant={list.isActive ? 'default' : 'secondary'}>
                                                            {list.isActive ? 'Active' : 'Inactive'}
                                                        </Badge>
                                                        <Badge variant="outline">
                                                            {list.entries.length} entries
                                                        </Badge>
                                                    </div>
                                                    {list.description && (
                                                        <p className="text-sm text-gray-600 mt-1">{list.description}</p>
                                                    )}
                                                    <p className="text-xs text-gray-500 mt-1">
                                                        Created: {list.dateCreated.toLocaleDateString()} |
                                                        Modified: {list.dateModified.toLocaleDateString()}
                                                    </p>
                                                </div>
                                                <div className="flex space-x-2">
                                                    <Button
                                                        onClick={() => toggleThreatIntelList(list.id)}
                                                        variant="outline"
                                                        size="sm"
                                                        className={list.isActive ? "text-orange-600 hover:bg-orange-50" : "text-green-600 hover:bg-green-50"}
                                                    >
                                                        {list.isActive ? 'Disable' : 'Enable'}
                                                    </Button>
                                                    <Button
                                                        onClick={() => setSelectedThreatList(selectedThreatList === list.id ? null : list.id)}
                                                        variant="outline"
                                                        size="sm"
                                                        className="text-blue-600 hover:bg-blue-50"
                                                    >
                                                        <Edit className="w-4 h-4 mr-1" />
                                                        {selectedThreatList === list.id ? 'Close' : 'Manage'}
                                                    </Button>
                                                    <Button
                                                        onClick={() => deleteThreatIntelList(list.id)}
                                                        variant="outline"
                                                        size="sm"
                                                        className="text-red-600 hover:bg-red-50"
                                                    >
                                                        <Trash className="w-4 h-4" />
                                                    </Button>
                                                </div>
                                            </div>

                                            {/* Threat List Entries Management */}
                                            {selectedThreatList === list.id && (
                                                <div className="border-t pt-3 space-y-3">
                                                    <div className="flex justify-between items-center">
                                                        <h6 className="font-medium text-gray-700">Threat Entries</h6>
                                                        <Button
                                                            onClick={() => setIsAddingThreatEntry(true)}
                                                            size="sm"
                                                            variant="outline"
                                                            className="text-green-600 hover:bg-green-50"
                                                        >
                                                            <Plus className="w-4 h-4 mr-1" />
                                                            Add Entry
                                                        </Button>
                                                    </div>

                                                    {/* Add New Entry Form */}
                                                    {isAddingThreatEntry && (
                                                        <div className="bg-blue-50 p-3 rounded space-y-3">
                                                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                                                <div>
                                                                    <label className="text-sm font-medium text-gray-700">IP Address/CIDR</label>
                                                                    <Input
                                                                        placeholder="e.g., 192.168.1.1 or 10.0.0.0/24"
                                                                        value={newThreatEntry.ip || ''}
                                                                        onChange={(e) => setNewThreatEntry({...newThreatEntry, ip: e.target.value})}
                                                                        variant={newThreatEntry.ip && !validateIpAddress(newThreatEntry.ip) ? "error" : "default"}
                                                                    />
                                                                    {newThreatEntry.ip && !validateIpAddress(newThreatEntry.ip) && (
                                                                        <p className="text-xs text-red-600 mt-1">Invalid IP address or CIDR format</p>
                                                                    )}
                                                                </div>
                                                                <div>
                                                                    <label className="text-sm font-medium text-gray-700">Severity</label>
                                                                    <select
                                                                        value={newThreatEntry.severity || 'medium'}
                                                                        onChange={(e) => setNewThreatEntry({...newThreatEntry, severity: e.target.value as any})}
                                                                        className="w-full h-10 px-3 py-2 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                                                    >
                                                                        <option value="low">Low</option>
                                                                        <option value="medium">Medium</option>
                                                                        <option value="high">High</option>
                                                                        <option value="critical">Critical</option>
                                                                    </select>
                                                                </div>
                                                            </div>
                                                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                                                <div>
                                                                    <label className="text-sm font-medium text-gray-700">Description</label>
                                                                    <Input
                                                                        placeholder="Brief description of the threat"
                                                                        value={newThreatEntry.description || ''}
                                                                        onChange={(e) => setNewThreatEntry({...newThreatEntry, description: e.target.value})}
                                                                    />
                                                                </div>
                                                                <div>
                                                                    <label className="text-sm font-medium text-gray-700">Source</label>
                                                                    <Input
                                                                        placeholder="e.g., Internal Analysis, VirusTotal"
                                                                        value={newThreatEntry.source || ''}
                                                                        onChange={(e) => setNewThreatEntry({...newThreatEntry, source: e.target.value})}
                                                                    />
                                                                </div>
                                                            </div>
                                                            <div className="flex space-x-2">
                                                                <Button
                                                                    onClick={addThreatIntelEntry}
                                                                    disabled={!newThreatEntry.ip?.trim() || !validateIpAddress(newThreatEntry.ip)}
                                                                    size="sm"
                                                                    className="bg-green-600 hover:bg-green-700"
                                                                >
                                                                    <Save className="w-4 h-4 mr-2" />
                                                                    Add Entry
                                                                </Button>
                                                                <Button
                                                                    onClick={() => {
                                                                        setIsAddingThreatEntry(false);
                                                                        setNewThreatEntry({
                                                                            ip: '',
                                                                            description: '',
                                                                            severity: 'medium',
                                                                            source: '',
                                                                            tags: []
                                                                        });
                                                                    }}
                                                                    variant="outline"
                                                                    size="sm"
                                                                >
                                                                    Cancel
                                                                </Button>
                                                            </div>
                                                        </div>
                                                    )}

                                                    {/* Existing Entries */}
                                                    <div className="space-y-2 max-h-60 overflow-y-auto">
                                                        {list.entries.length === 0 ? (
                                                            <p className="text-sm text-gray-500 text-center py-4">No entries in this list.</p>
                                                        ) : (
                                                            list.entries.map(entry => (
                                                                <div key={entry.id} className="flex justify-between items-center p-2 bg-white rounded border">
                                                                    <div className="flex-1">
                                                                        <div className="flex items-center space-x-2">
                                                                            <code className="text-sm font-mono bg-gray-100 px-2 py-1 rounded">{entry.ip}</code>
                                                                            <Badge
                                                                                variant={
                                                                                    entry.severity === 'critical' ? 'destructive' :
                                                                                    entry.severity === 'high' ? 'destructive' :
                                                                                    entry.severity === 'medium' ? 'default' : 'secondary'
                                                                                }
                                                                            >
                                                                                {entry.severity}
                                                                            </Badge>
                                                                        </div>
                                                                        {entry.description && (
                                                                            <p className="text-xs text-gray-600 mt-1">{entry.description}</p>
                                                                        )}
                                                                        <p className="text-xs text-gray-500">
                                                                            {entry.source} • Added {entry.dateAdded.toLocaleDateString()}
                                                                        </p>
                                                                    </div>
                                                                    <Button
                                                                        onClick={() => deleteThreatIntelEntry(list.id, entry.id)}
                                                                        variant="ghost"
                                                                        size="sm"
                                                                        className="text-red-600 hover:bg-red-50"
                                                                    >
                                                                        <Trash className="w-4 h-4" />
                                                                    </Button>
                                                                </div>
                                                            ))
                                                        )}
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                        ))}
                                    </div>
                                )}
                            </div>

                            <div className="bg-blue-50 p-4 rounded-lg">
                                <div className="flex items-center mb-2">
                                    <Info className="w-4 h-4 mr-2 text-blue-600" />
                                    <h4 className="font-semibold text-blue-900">Threat Intelligence Usage</h4>
                                </div>
                                <ul className="list-disc list-inside space-y-1 text-sm text-blue-800">
                                    <li>IPs matching active threat lists will be highlighted in analysis results</li>
                                    <li>Supports both individual IPs (192.168.1.1) and CIDR ranges (10.0.0.0/24)</li>
                                    <li>Lists are stored locally in your browser and never sent to external servers</li>
                                    <li>Disable lists temporarily without deleting entries</li>
                                </ul>
                            </div>
                        </CardContent>
                    </Card>
                </div>
            )}

            {activeTab === 'help' && (
                <div className="space-y-4">
                  {renderHelpAccordionItem('gettingOutput', 'Getting Your Netstat Output', FileText, (
                    <>
                      <p>To use this tool, you'll need to provide the output of a netstat command from your system, saved as a plain text file (.txt, .log).</p>
                      <h4 className="font-semibold mt-3 mb-1">Windows:</h4>
                      <ul className="list-disc pl-5">
                        <li>Open Command Prompt (search "cmd"). For more detailed information (like Process IDs and Executables), run it as Administrator.</li>
                        <li>Command: <code className="bg-gray-200 p-1 rounded">netstat -ano &gt; netstat_output.txt</code></li>
                        <li>This saves output with All connections, Numeric addresses/ports, and owning Process IDs to <code>netstat_output.txt</code> in your current directory.</li>
                        <li>If run as Administrator, you can use <code className="bg-gray-200 p-1 rounded">netstat -anob &gt; netstat_output.txt</code> to include executable names (can make files larger).</li>
                      </ul>
                      <h4 className="font-semibold mt-3 mb-1">Linux:</h4>
                      <ul className="list-disc pl-5">
                        <li>Open your terminal.</li>
                        <li>Recommended Command (modern): <code className="bg-gray-200 p-1 rounded">ss -tulpn &gt; netstat_output.txt</code> (shows TCP, UDP, Listening, Processes, Numeric).</li>
                        <li>Alternative (older): <code className="bg-gray-200 p-1 rounded">netstat -tulnp &gt; netstat_output.txt</code></li>
                        <li>Tip: Use <code className="bg-gray-200 p-1 rounded">sudo</code> (e.g., <code className="bg-gray-200 p-1 rounded">sudo ss -tulpn &gt; netstat_output.txt</code>) for full process information.</li>
                      </ul>
                       <h4 className="font-semibold mt-3 mb-1">macOS:</h4>
                       <ul className="list-disc pl-5">
                        <li>Open Terminal (Applications &gt; Utilities &gt; Terminal).</li>
                        <li>Command: <code className="bg-gray-200 p-1 rounded">netstat -an &gt; netstat_output.txt</code></li>
                        <li>This provides a general overview. The parser is designed for this common format.</li>
                        <li>For more detailed process info (might require sudo): <code className="bg-gray-200 p-1 rounded">lsof -i -P -n &gt; netstat_output.txt</code> (note: lsof output format is different but this tool might parse some common patterns). For best results with this tool, stick to `netstat -an`.</li>
                       </ul>
                    </>
                  ))}
                  {renderHelpAccordionItem('aboutTool', 'About This Tool', Info, (
                    <>
                      <p>This Netstat Security Analyzer helps you understand your system's network connections by parsing the output from netstat (or ss) commands.</p>
                      <p><strong>Key Features:</strong></p>
                      <ul className="list-disc pl-5">
                        <li>Parses netstat logs from Windows, Linux, and macOS.</li>
                        <li>Identifies listening ports and active connections.</li>
                        <li>Flags potential risks based on port numbers, connection states, and a built-in list of known Threat Intelligence IPs.</li>
                        <li>Categorizes local services running on the loopback interface (127.0.0.1).</li>
                        <li>Provides an overview of port usage and IP address interactions.</li>
                        <li>Offers AI-powered insights (if API key is available) for deeper understanding of services, IPs, and overall security posture.</li>
                        <li>Allows historical analysis by loading multiple snapshots.</li>
                        <li>Generates downloadable JSON and HTML reports.</li>
                      </ul>
                      <p><strong>Goal:</strong> To provide a user-friendly way to quickly assess network activity from a netstat log, highlight areas of potential concern, and aid in security awareness and basic troubleshooting.</p>
                    </>
                  ))}
                  {renderHelpAccordionItem('understandingAnalysis', 'Understanding the Analysis', Network, (
                    <>
                      <h4 className="font-semibold mt-2 mb-1">Risk Levels:</h4>
                      <ul className="list-disc pl-5">
                        <li><strong>Safe:</strong> Generally recognized safe services, standard OS behavior, or purely local traffic not typically associated with threats.</li>
                        <li><strong>Warning:</strong> Services that could be misconfigured (e.g., listening on all interfaces unnecessarily), unencrypted versions of services where secure alternatives exist, or minor deviations from best practices.</li>
                        <li><strong>Suspicious:</strong> Connections or services that warrant closer inspection. This includes connections to/from public IPs (especially non-standard services), services like RDP/SMB if exposed, unusual connection states, or services on non-standard ports that are often abused.</li>
                        <li><strong>Critical:</strong> Connections involving IPs from the built-in Threat Intelligence list, or services that are inherently highly vulnerable if exposed (e.g., Telnet). These require immediate attention.</li>
                        <li><strong>Unknown:</strong> The port or service is not in the tool's known list, or its state is indeterminate from the netstat line.</li>
                      </ul>
                      <h4 className="font-semibold mt-3 mb-1">Key Information Points:</h4>
                       <ul className="list-disc pl-5">
                        <li><strong>Local Address / Foreign Address:</strong> Your system's IP:Port and the remote system's IP:Port. An asterisk (*) often means any address or an unspecified port.</li>
                        <li><strong>PID (Process ID):</strong> If available in your netstat output, this number identifies the program on your system responsible for the connection. You can use Task Manager (Windows) or <code>ps</code>/<code>top</code> (Linux/macOS) to match PIDs to programs.</li>
                        <li><strong>State (TCP Connections):</strong>
                            <ul className="list-circle pl-5">
                                <li><code>LISTEN</code> / <code>LISTENING</code>: A service on your machine is waiting for incoming connections on a specific port.</li>
                                <li><code>ESTABLISHED</code>: An active, ongoing connection.</li>
                                <li><code>SYN_SENT</code> / <code>SYN_RCVD</code>: Part of the TCP connection establishment handshake. Many of these could indicate connection attempts (yours or to you) or scanning.</li>
                                <li><code>TIME_WAIT</code>: Connection is closed, but the port is kept unavailable for a short period to ensure all lingering packets are handled. Usually normal.</li>
                                <li><code>CLOSE_WAIT</code> / <code>LAST_ACK</code> / <code>FIN_WAIT_1</code> / <code>FIN_WAIT_2</code>: Various states of connection termination.</li>
                            </ul>
                        </li>
                        <li><strong>Well-Known Ports:</strong> Standardized port numbers for common internet services (e.g., port 80 for HTTP, 443 for HTTPS, 22 for SSH). The tool uses a list of these to identify services and assess baseline risk.</li>
                        <li><strong>Threat Intelligence IPs:</strong> The tool includes a static list of IP addresses that have been reported as malicious. Connections to or from these IPs are flagged as 'Critical'. This list is for demonstration and may not be exhaustive or perfectly up-to-date.</li>
                       </ul>
                    </>
                  ))}
                  {renderHelpAccordionItem('usingAi', 'Using AI Features', Sparkles, (
                     <>
                        <p>This tool can use Google Gemini (via the <code>@google/genai</code> SDK) to provide AI-powered insights on various aspects of your network analysis.</p>
                        <h4 className="font-semibold mt-3 mb-1">How it Works:</h4>
                        <ul className="list-disc pl-5">
                            <li>AI can help explain what a local service on 127.0.0.1 might be.</li>
                            <li>It can provide a reputation analysis for external IP addresses using Google Search grounding.</li>
                            <li>It can offer a contextual security assessment for specific exposed listening ports.</li>
                            <li>It can generate an overall security briefing based on the current analysis results.</li>
                        </ul>
                        <h4 className="font-semibold mt-3 mb-1">API Key Configuration:</h4>
                        <ul className="list-disc pl-5">
                            <li>To use the AI features, you need a valid Google Gemini API Key. You can configure this in two ways:</li>
                            <li><strong>Settings Tab (Recommended):</strong> Use the Settings tab to enter and validate your API key directly in the application. The key is stored securely in your browser's local storage.</li>
                            <li><strong>Environment Variable:</strong> Set the API key as an environment variable named <code>API_KEY</code> or <code>GEMINI_API_KEY</code> in the environment where this application runs.</li>
                            <li>Environment variables take precedence over user-entered keys. If neither is configured, AI features will be disabled.</li>
                            <li>Get your free API key from <a href="https://aistudio.google.com/app/apikey" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">Google AI Studio</a>.</li>
                        </ul>
                        <h4 className="font-semibold mt-3 mb-1">What to Expect:</h4>
                         <p>AI insights are generated based on the specific data from your netstat log (like ports, IPs, PIDs) and Google Gemini's general knowledge and search capabilities. The prompts sent to the AI are designed to be specific to the context you're exploring.</p>
                         <p><em>Always critically evaluate AI-generated information and cross-reference with other sources if making important security decisions.</em></p>
                    </>
                  ))}
                  {renderHelpAccordionItem('interpretationTips', 'Tips for Interpretation', Lightbulb, (
                    <>
                        <ul className="list-disc pl-5 space-y-2">
                            <li><strong><code>0.0.0.0</code> or <code>::</code> (IPv6 equivalent) in Local Address:</strong> This means a service on your machine is "listening" on all available network interfaces (Ethernet, Wi-Fi, etc.). This is common for web servers or other services designed to be accessible from other machines on your network or the internet. If you don't expect a service to be accessible externally, investigate why it's listening on all interfaces.</li>
                            <li><strong><code>127.0.0.1</code> (localhost) or <code>::1</code> (IPv6 localhost):</strong> This is the loopback interface. Connections to/from this IP are typically between processes running on your own machine. While usually safe, malware can also use loopback for local communication or proxying. The "Local Services" tab focuses on these.</li>
                            <li><strong>Many <code>TIME_WAIT</code> states:</strong> This is often normal, especially on busy servers or after browsing many websites. It's part of TCP's mechanism to ensure reliable connection closure. However, an extremely high and persistent number could sometimes indicate network issues or resource exhaustion under specific circumstances, but usually it's benign.</li>
                            <li><strong>Focus Areas:</strong>
                                <ul className="list-circle pl-5">
                                    <li>Pay close attention to <code>LISTEN</code>ing ports, especially those on <code>0.0.0.0</code>, <code>::</code>, or your machine's actual public-facing IP address. Are these services expected to be open? Are they secure?</li>
                                    <li>Examine <code>ESTABLISHED</code> connections to unfamiliar public IP addresses (see "IP Analysis" tab). What local process (PID) is making these connections?</li>
                                    <li>Connections to "Critical" or "Suspicious" well-known ports on foreign IPs could indicate your system is connecting to a risky remote service.</li>
                                </ul>
                            </li>
                            <li><strong>Correlate with System Knowledge:</strong> Always try to correlate the netstat findings with the applications you know are running on your system and your expected network behavior. An "unknown" service might be legitimate if it's part of a specific application you use.</li>
                            <li><strong>PID is Key:</strong> If PIDs are available in your netstat output, they are very helpful for identifying which program is responsible for a particular connection. Use your OS's tools (Task Manager on Windows, <code>ps</code> or Activity Monitor on macOS/Linux) to look up the process name.</li>
                        </ul>
                    </>
                  ))}
                   {renderHelpAccordionItem('disclaimer', 'Disclaimer', AlertTriangle, (
                    <>
                        <p>This Netstat Security Analyzer is provided for informational and educational purposes only. It is intended to help users understand their system's network activity and identify potential areas for further investigation.</p>
                        <ul className="list-disc pl-5 space-y-2">
                            <li><strong>Not a Substitute for Professional Advice:</strong> This tool is not a replacement for professional security audits, dedicated security software (like firewalls or antivirus), or expert consultation.</li>
                            <li><strong>Accuracy Depends on Input:</strong> The accuracy and completeness of the analysis heavily depend on the quality and completeness of the netstat data provided by the user.</li>
                            <li><strong>AI Insights are Suggestions:</strong> AI-generated insights are based on patterns and general knowledge. They should be critically reviewed, verified, and not taken as definitive security advice without further investigation and professional judgment. The AI can make mistakes or provide incomplete information.</li>
                            <li><strong>No Liability:</strong> The creators and maintainers of this tool are not responsible for any actions taken or decisions made based on the information or analysis provided by this tool. Users are solely responsible for interpreting the results and any subsequent actions.</li>
                            <li><strong>Use Responsibly:</strong> Please use this tool responsibly and ethically. Do not use it to analyze systems or data you do not have permission to access.</li>
                        </ul>
                    </>
                  ))}
                </div>
            )}
            </CardContent>
        </Card>
      </div>
       <footer className="text-center py-6 mt-8">
            <p className="text-sm text-gray-500">Netstat Security Analyzer &copy; {new Date().getFullYear()}. For educational and informational purposes only.</p>
            <p className="text-xs text-gray-400 mt-1">AI features powered by Google Gemini. Use responsibly.</p>
      </footer>
    </div>
  );
};

export default App;
