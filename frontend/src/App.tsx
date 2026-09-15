import { type FormEvent, useEffect, useState } from 'react';
import axios from 'axios';
import {
  AlertTriangle,
  ArrowLeft,
  Calendar,
  CheckCircle2,
  ChevronRight,
  Cpu,
  ExternalLink,
  Fingerprint,
  Globe,
  History,
  Lock,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Unlock,
  Volume2,
  VolumeX,
} from 'lucide-react';
import GhostCharacter from './components/GhostCharacter';
import TrustScore from './components/TrustScore';
import ConsequenceVisualizer from './components/ConsequenceVisualizer';

interface ConsequenceStep {
  step: string;
  description: string;
  risk: string;
}

interface ScanReport {
  id: string;
  url: string;
  domain: string;
  trust_score: number;
  risk_level: string;
  domain_age_days: number | null;
  registrar: string;
  https_enabled: boolean;
  suspicious_patterns: string[];
  ghost_summary: string;
  ghost_summary_en?: string;
  ai_explanation: string;
  recommendations: string[];
  consequences: ConsequenceStep[];
  created_at: string;
  crawled_page_content?: {
    title: string;
    headings: string[];
    has_password_field: boolean;
    has_card_field?: boolean;
    forms_count: number;
    input_fields: string[];
    external_scripts: string[];
    text_snippet: string;
    favicon?: string;
    metadata?: Record<string, string>;
    iframes_count?: number;
    copy_paste_locks_detected?: boolean;
    inline_scripts_count?: number;
    inline_scripts_length?: number;
    subpages_scanned?: string[];
  } | null;
  scorecard?: {
    domain_score: number;
    ssl_score: number;
    dom_score: number;
    headers_score: number;
    scripts_score: number;
    ssl_issuer: string;
    security_headers: {
      "Strict-Transport-Security": boolean;
      "Content-Security-Policy": boolean;
      "X-Frame-Options": boolean;
      "X-Content-Type-Options": boolean;
      "Referrer-Policy": boolean;
      Server: string;
    };
  };
  threat_assessment?: {
    is_brand_impersonation: { status: boolean; details: string };
    resembles_phishing: { status: boolean; details: string };
    is_unusually_new: { status: boolean; details: string };
    requests_sensitive_info: { status: boolean; details: string };
    multiple_warnings: { status: boolean; details: string };
    confidence_level: { level: string; details: string };
  };
}

const SCAN_STEPS = [
  "I am entering the website...",
  "Checking secure connection...",
  "Reading domain information...",
  "Inspecting website structure...",
  "Looking for suspicious patterns...",
  "Generating guardian report..."
];

export default function App() {
  const [url, setUrl] = useState('');
  const [status, setStatus] = useState<'landing' | 'scanning' | 'results' | 'error'>('landing');
  const [scanStepIndex, setScanStepIndex] = useState(0);
  const [scanResult, setScanResult] = useState<ScanReport | null>(null);
  const [history, setHistory] = useState<ScanReport[]>([]);
  const [errorMessage, setErrorMessage] = useState('');
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [isSpeaking, setIsSpeaking] = useState(false);
  const [speechLang, setSpeechLang] = useState<'en' | 'hi'>('hi');

  const formatDomainAge = (days: number | null | undefined) => {
    if (days === null || days === undefined) return "Unknown";
    if (days < 30) return `${days} day${days === 1 ? '' : 's'} old`;
    if (days < 365) {
      const months = Math.floor(days / 30);
      return `${months} month${months === 1 ? '' : 's'} old`;
    }
    const years = Math.floor(days / 365);
    const remainingMonths = Math.floor((days % 365) / 30);
    if (remainingMonths > 0) {
      return `${years} yr${years === 1 ? '' : 's'}, ${remainingMonths} mo${remainingMonths === 1 ? '' : 's'} old`;
    }
    return `${years} year${years === 1 ? '' : 's'} old`;
  };

  const toggleSpeech = (lang?: 'en' | 'hi') => {
    if ('speechSynthesis' in window) {
      const targetLang = lang || speechLang;
      if (isSpeaking) {
        window.speechSynthesis.cancel();
        setIsSpeaking(false);
      } else {
        const textToSpeak = targetLang === 'en' ? scanResult?.ghost_summary_en : scanResult?.ghost_summary;
        if (textToSpeak) {
          window.speechSynthesis.cancel();
          const utterance = new SpeechSynthesisUtterance(textToSpeak);
          utterance.rate = 0.95;
          utterance.pitch = 1.05;
          
          const voices = window.speechSynthesis.getVoices();
          if (targetLang === 'en') {
            const englishVoice = voices.find(voice => voice.lang.startsWith('en-US')) || 
                                 voices.find(voice => voice.lang.startsWith('en-'));
            if (englishVoice) {
              utterance.voice = englishVoice;
            }
          } else {
            const hindiVoice = voices.find(voice => 
              voice.lang === 'hi-IN' || 
              voice.lang === 'hi' || 
              voice.lang.startsWith('hi-')
            );
            const defaultVoice = hindiVoice || 
                                 voices.find(voice => voice.lang === 'en-IN') || 
                                 voices.find(voice => voice.lang.startsWith('en-'));
            if (defaultVoice) {
              utterance.voice = defaultVoice;
            }
          }

          utterance.onstart = () => setIsSpeaking(true);
          utterance.onend = () => setIsSpeaking(false);
          utterance.onerror = () => setIsSpeaking(false);
          window.speechSynthesis.speak(utterance);
        }
      }
    }
  };

  useEffect(() => {
    if (status === 'results' && scanResult?.ghost_summary) {
      const timer = setTimeout(() => {
        if ('speechSynthesis' in window) {
          window.speechSynthesis.cancel();
          const textToSpeak = speechLang === 'en' ? scanResult.ghost_summary_en : scanResult.ghost_summary;
          const utterance = new SpeechSynthesisUtterance(textToSpeak || scanResult.ghost_summary);
          utterance.rate = 0.95;
          utterance.pitch = 1.05;
          
          const voices = window.speechSynthesis.getVoices();
          if (speechLang === 'en') {
            const englishVoice = voices.find(voice => voice.lang.startsWith('en-US')) || 
                                 voices.find(voice => voice.lang.startsWith('en-'));
            if (englishVoice) {
              utterance.voice = englishVoice;
            }
          } else {
            const hindiVoice = voices.find(voice => 
              voice.lang === 'hi-IN' || 
              voice.lang === 'hi' || 
              voice.lang.startsWith('hi-')
            );
            const defaultVoice = hindiVoice || 
                                 voices.find(voice => voice.lang === 'en-IN') || 
                                 voices.find(voice => voice.lang.startsWith('en-'));
            if (defaultVoice) {
              utterance.voice = defaultVoice;
            }
          }

          utterance.onstart = () => setIsSpeaking(true);
          utterance.onend = () => setIsSpeaking(false);
          utterance.onerror = () => setIsSpeaking(false);
          window.speechSynthesis.speak(utterance);
        }
      }, 600);
      
      return () => {
        clearTimeout(timer);
        if ('speechSynthesis' in window) {
          window.speechSynthesis.cancel();
        }
      };
    }
  }, [status, scanResult, speechLang]);

  useEffect(() => {
    fetchHistory();
  }, []);

  const fetchHistory = async () => {
    setLoadingHistory(true);
    try {
      const response = await axios.get('/api/history');
      setHistory(response.data);
    } catch (e) {
      console.warn("Could not load history from backend, checking local storage.");
      const cached = localStorage.getItem('ghostnet_scans');
      if (cached) {
        setHistory(JSON.parse(cached));
      }
    } finally {
      setLoadingHistory(false);
    }
  };

  const saveToLocalStorage = (newReport: ScanReport) => {
    const cached = localStorage.getItem('ghostnet_scans');
    let cacheList: ScanReport[] = cached ? JSON.parse(cached) : [];
    
    if (!cacheList.some(item => item.id === newReport.id)) {
      cacheList = [newReport, ...cacheList].slice(0, 20);
      localStorage.setItem('ghostnet_scans', JSON.stringify(cacheList));
      setHistory(cacheList);
    }
  };

  const handleScan = async (e: FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    setStatus('scanning');
    setScanStepIndex(0);
    setErrorMessage('');
    
    const stepInterval = setInterval(() => {
      setScanStepIndex(prev => {
        if (prev < SCAN_STEPS.length - 1) {
          return prev + 1;
        } else {
          clearInterval(stepInterval);
          return prev;
        }
      });
    }, 700);

    try {
      const response = await axios.post('/api/scan', { url });
      const data: ScanReport = response.data;
      
      setTimeout(() => {
        setScanResult(data);
        setStatus('results');
        saveToLocalStorage(data);
        fetchHistory();
      }, 3500);

    } catch (err: any) {
      clearInterval(stepInterval);
      console.error(err);
      setErrorMessage(
        err.response?.data?.detail || 
        "Something went wrong while Ghost was analyzing the website. Please check the URL and try again."
      );
      setStatus('error');
    }
  };

  const handleSelectHistory = (report: ScanReport) => {
    setScanResult(report);
    setStatus('results');
  };

  const handleBackToLanding = () => {
    setUrl('');
    setScanResult(null);
    setStatus('landing');
  };

  const getRiskColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'safe':
        return 'text-green-400 border-green-500/30 bg-green-950/20';
      case 'low risk':
        return 'text-blue-400 border-blue-500/30 bg-blue-950/20';
      case 'medium risk':
        return 'text-amber-400 border-amber-500/30 bg-amber-950/20';
      case 'high risk':
        return 'text-red-400 border-red-500/30 bg-red-950/20';
      case 'critical':
      default:
        return 'text-rose-500 border-rose-500/30 bg-rose-950/30';
    }
  };

  const getGhostState = (level: string): 'idle' | 'safe' | 'warning' | 'danger' => {
    switch (level.toLowerCase()) {
      case 'safe':
        return 'safe';
      case 'low risk':
        return 'idle';
      case 'medium risk':
        return 'warning';
      case 'high risk':
      case 'critical':
      default:
        return 'danger';
    }
  };

  return (
    <div className="min-h-screen flex flex-col font-sans">
      
      <div className="absolute top-0 left-0 right-0 h-[500px] bg-gradient-to-b from-purple-900/5 to-transparent pointer-events-none z-0" />
      
      
      <header className="relative z-10 border-b border-zinc-900 bg-black/70 backdrop-blur-md px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-2 cursor-pointer" onClick={handleBackToLanding}>
          <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-purple-600 to-blue-500 flex items-center justify-center font-bold text-white shadow-lg">
            👻
          </div>
          <div>
            <h1 className="text-xl font-bold font-mono tracking-wider bg-gradient-to-r from-slate-100 to-slate-400 bg-clip-text text-transparent">
              GhostNet
            </h1>
            <p className="text-[10px] text-slate-500 uppercase tracking-widest leading-none font-semibold">
              Cybersecurity
            </p>
          </div>
        </div>
        
        <div className="flex items-center gap-4">
          <a 
            href="https://github.com" 
            target="_blank" 
            rel="noreferrer"
            className="text-xs text-slate-400 hover:text-slate-200 transition-colors flex items-center gap-1.5"
          >
            v1.0.0
          </a>
        </div>
      </header>

      
      <main className="flex-1 relative z-10 flex flex-col px-4 md:px-8 py-10 max-w-6xl w-full mx-auto justify-center">
        
        
        {status === 'landing' && (
          <div className="flex flex-col items-center justify-center text-center mt-4">
            
            
            <div className="mb-6 flex justify-center">
              <GhostCharacter state="idle" size={130} />
            </div>

            
            <div className="max-w-2xl">
              <h2 className="text-4xl md:text-6xl font-bold font-heading tracking-tight leading-tight">
                The Ghost That <span className="bg-gradient-to-r from-purple-400 to-blue-400 bg-clip-text text-transparent">Browses Before You</span>
              </h2>
              <p className="text-slate-400 text-sm md:text-base mt-4 max-w-lg mx-auto">
                Paste any unknown or suspicious URL. GhostNet explores the site in the background, running threat heuristics and AI validation, explaining the risks in human terms.
              </p>
            </div>

            
            <form onSubmit={handleScan} className="w-full max-w-xl mt-10">
              <div className="glass-panel p-2 rounded-2xl flex items-center gap-2 focus-within:border-purple-500/50 transition-all duration-300">
                <div className="pl-3 text-slate-500">
                  <Globe className="w-5 h-5" />
                </div>
                <input 
                  type="text" 
                  placeholder="https://example-banking.com/login" 
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  className="flex-1 bg-transparent border-none outline-none py-3 text-slate-100 text-sm md:text-base placeholder-slate-600 w-full"
                />
                <button 
                  type="submit"
                  className="bg-gradient-to-r from-purple-600 to-blue-500 hover:from-purple-500 hover:to-blue-400 text-white font-medium text-sm px-6 py-3 rounded-xl transition-all shadow-md shadow-purple-900/30 flex items-center gap-2 cursor-pointer active:scale-97"
                >
                  <Search className="w-4 h-4" />
                  Explore
                </button>
              </div>
            </form>

            
            <div className="flex flex-wrap items-center justify-center gap-2.5 mt-4 text-xs text-slate-500">
              <span>Quick tests:</span>
              <button 
                type="button" 
                onClick={() => setUrl('https://paypal-secure-verify.login-check.xyz')}
                className="px-2.5 py-1 rounded-md border border-zinc-900 hover:border-zinc-800 hover:text-slate-400 bg-zinc-950/50 transition-all cursor-pointer"
              >
                Suspicious URL
              </button>
              <button 
                type="button" 
                onClick={() => setUrl('https://google.com')}
                className="px-2.5 py-1 rounded-md border border-zinc-900 hover:border-zinc-800 hover:text-slate-400 bg-zinc-950/50 transition-all cursor-pointer"
              >
                Safe URL
              </button>
              <button 
                type="button" 
                onClick={() => setUrl('http://http-legacy-unsafe.net')}
                className="px-2.5 py-1 rounded-md border border-zinc-900 hover:border-zinc-800 hover:text-slate-400 bg-zinc-950/50 transition-all cursor-pointer"
              >
                Unencrypted URL
              </button>
            </div>
            
            <div className="w-full max-w-4xl mt-20 border-t border-zinc-900 pt-10 text-left">
              <h3 className="text-sm font-semibold tracking-widest text-slate-400 uppercase flex items-center justify-center gap-2 mb-8 text-center">
                Behind the Veil: How GhostNet Scans
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="glass-panel p-5 rounded-2xl bg-zinc-950/20 border border-zinc-900 hover:border-zinc-800 transition-all flex flex-col gap-3 group">
                  <div className="w-8 h-8 rounded-lg bg-blue-950/30 border border-blue-900/50 flex items-center justify-center text-blue-400 group-hover:bg-blue-950/50 group-hover:border-blue-700/50 transition-all">
                    <Server className="w-4 h-4" />
                  </div>
                  <div>
                    <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider">1. Technical Check</h4>
                    <p className="text-[11px] text-slate-400 mt-1.5 leading-relaxed">
                      Resolves connection protocols, checks SSL certificate handshake validity, and validates active HTTPS configurations.
                    </p>
                  </div>
                </div>

                <div className="glass-panel p-5 rounded-2xl bg-zinc-950/20 border border-zinc-900 hover:border-zinc-800 transition-all flex flex-col gap-3 group">
                  <div className="w-8 h-8 rounded-lg bg-purple-950/30 border border-purple-900/50 flex items-center justify-center text-purple-400 group-hover:bg-purple-950/50 group-hover:border-purple-700/50 transition-all">
                    <Fingerprint className="w-4 h-4" />
                  </div>
                  <div>
                    <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider">2. Heuristics</h4>
                    <p className="text-[11px] text-slate-400 mt-1.5 leading-relaxed">
                      Scans hostnames and URL parameters for suspicious keywords, typosquatting variants, and brand impersonation patterns.
                    </p>
                  </div>
                </div>

                <div className="glass-panel p-5 rounded-2xl bg-zinc-950/20 border border-zinc-900 hover:border-zinc-800 transition-all flex flex-col gap-3 group">
                  <div className="w-8 h-8 rounded-lg bg-amber-950/30 border border-amber-900/50 flex items-center justify-center text-amber-400 group-hover:bg-amber-950/50 group-hover:border-amber-700/50 transition-all">
                    <Globe className="w-4 h-4" />
                  </div>
                  <div>
                    <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider">3. Registry DB</h4>
                    <p className="text-[11px] text-slate-400 mt-1.5 leading-relaxed">
                      Queries live RDAP databases to fetch the registration age, registrar info, and domain creation date.
                    </p>
                  </div>
                </div>

                <div className="glass-panel p-5 rounded-2xl bg-zinc-950/20 border border-zinc-900 hover:border-zinc-800 transition-all flex flex-col gap-3 group">
                  <div className="w-8 h-8 rounded-lg bg-emerald-950/30 border border-emerald-900/50 flex items-center justify-center text-emerald-400 group-hover:bg-emerald-950/50 group-hover:border-emerald-700/50 transition-all">
                    <Cpu className="w-4 h-4" />
                  </div>
                  <div>
                    <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider">4. AI Synthesis</h4>
                    <p className="text-[11px] text-slate-400 mt-1.5 leading-relaxed">
                      Leverages Gemini API to translate telemetry metrics into a smart trust score, plain-English summary, and safety guidelines.
                    </p>
                  </div>
                </div>
              </div>
            </div>

            
            <div className="w-full max-w-4xl mt-20 border-t border-zinc-900 pt-10">
              <h3 className="text-sm font-semibold tracking-widest text-slate-400 uppercase flex items-center justify-center gap-2 mb-6">
                <History className="w-4 h-4" />
                Scan History
              </h3>

              {loadingHistory ? (
                <div className="text-xs text-slate-500 py-4">Syncing scans list...</div>
              ) : history.length === 0 ? (
                <div className="glass-panel p-6 rounded-2xl text-center text-xs text-slate-500">
                  No scan logs present. Your explorations will persist here.
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {history.map((item) => (
                    <div 
                      key={item.id} 
                      onClick={() => handleSelectHistory(item)}
                      className="glass-panel p-4 rounded-xl border border-zinc-900 hover:border-zinc-800/80 cursor-pointer transition-all flex items-center justify-between text-left group bg-zinc-950/20"
                    >
                      <div className="truncate max-w-[70%]">
                        <div className="text-xs font-semibold text-slate-300 truncate font-mono">
                          {item.url}
                        </div>
                        <p className="text-[10px] text-slate-500 mt-1 truncate">
                          {item.ghost_summary}
                        </p>
                      </div>
                      <div className="flex items-center gap-2.5">
                        <span className={`text-[10px] px-2 py-0.5 rounded-full border ${getRiskColor(item.risk_level)}`}>
                          {item.risk_level}
                        </span>
                        <div className="w-7 h-7 rounded-full bg-slate-900 flex items-center justify-center text-xs text-slate-400 group-hover:bg-purple-950/20 group-hover:text-purple-400 transition-colors">
                          <ChevronRight className="w-4 h-4" />
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

          </div>
        )}

        
        {status === 'scanning' && (
          <div className="flex flex-col items-center justify-center py-20 text-center">
            
            
            <div className="relative mb-8">
              <div className="absolute inset-0 w-24 h-24 bg-blue-500/20 rounded-full blur-xl animate-pulse" />
              <GhostCharacter state="scanning" size={140} />
            </div>

            
            <div className="h-6 overflow-hidden">
              <span className="text-slate-200 text-sm font-semibold tracking-wide animate-pulse">
                {SCAN_STEPS[scanStepIndex]}
              </span>
            </div>

            
            <div className="flex items-center gap-2.5 mt-6">
              {SCAN_STEPS.map((_, idx) => (
                <div 
                  key={idx}
                  className={`h-1.5 rounded-full transition-all duration-500 ${
                    idx === scanStepIndex 
                      ? 'w-8 bg-blue-500' 
                      : idx < scanStepIndex 
                        ? 'w-3 bg-purple-600' 
                        : 'w-2 bg-zinc-900'
                  }`}
                />
              ))}
            </div>

            <p className="text-xs text-slate-500 mt-12 max-w-xs leading-relaxed">
              Ghost is inspecting standard SSL handshake protocols, security configurations, and DNS registers.
            </p>
          </div>
        )}

        
        {status === 'error' && (
          <div className="flex flex-col items-center justify-center py-20 text-center max-w-md mx-auto">
            <div className="w-16 h-16 rounded-full bg-red-950/30 border border-red-500/30 flex items-center justify-center text-red-500 mb-6 shadow-lg shadow-red-950/20">
              <AlertTriangle className="w-8 h-8" />
            </div>
            
            <h3 className="text-xl font-bold font-heading text-slate-100">Scan Failed</h3>
            <p className="text-slate-400 text-sm mt-3 leading-relaxed">
              {errorMessage}
            </p>

            <button 
              onClick={handleBackToLanding}
              className="mt-8 flex items-center gap-2 text-xs px-5 py-2.5 bg-zinc-950 hover:bg-zinc-900 border border-zinc-900 rounded-xl text-slate-300 hover:text-white transition-all cursor-pointer"
            >
              <ArrowLeft className="w-4 h-4" />
              Try Another URL
            </button>
          </div>
        )}

        
        {status === 'results' && scanResult && (
          <div className="space-y-6">
            
            
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-zinc-900 pb-6">
              <div className="flex items-center gap-3">
                <button 
                  onClick={handleBackToLanding}
                  className="p-2.5 rounded-xl border border-zinc-800 hover:border-zinc-700 bg-zinc-950/50 hover:bg-zinc-900 text-slate-400 hover:text-slate-200 transition-all cursor-pointer active:scale-95"
                >
                  <ArrowLeft className="w-4 h-4" />
                </button>
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs uppercase tracking-widest text-slate-500 font-semibold">
                      Target Report
                    </span>
                    <span className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded-md border ${getRiskColor(scanResult.risk_level)}`}>
                      {scanResult.risk_level}
                    </span>
                    <span className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded-md border ${
                      scanResult.domain_age_days === null || scanResult.domain_age_days === undefined
                        ? 'text-slate-400 border-zinc-800 bg-zinc-950/20' 
                        : scanResult.domain_age_days < 90
                          ? 'text-red-400 border-red-500/30 bg-red-950/20'
                          : 'text-emerald-400 border-emerald-500/30 bg-emerald-950/20'
                    }`}>
                      Age: {formatDomainAge(scanResult.domain_age_days)}
                    </span>
                  </div>
                  <h2 className="text-lg md:text-xl font-bold text-slate-100 font-mono truncate mt-1 max-w-[280px] sm:max-w-sm md:max-w-xl">
                    {scanResult.url}
                  </h2>
                </div>
              </div>

              <a 
                href={scanResult.url} 
                target="_blank" 
                rel="noreferrer"
                className="flex items-center justify-center gap-2 text-xs font-semibold px-4 py-2.5 rounded-xl bg-zinc-950 hover:bg-zinc-900 text-slate-300 hover:text-white border border-zinc-900 transition-all cursor-pointer active:scale-97"
              >
                Go to Website
                <ExternalLink className="w-3.5 h-3.5" />
              </a>
            </div>

            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              
              
              <div className="glass-panel p-6 rounded-2xl flex flex-col items-center justify-center text-center bg-black/40">
                <TrustScore score={scanResult.trust_score} riskLevel={scanResult.risk_level} />
                
                <div className="mt-4 pt-4 border-t border-zinc-900/60 w-full text-center">
                  <span className="text-[10px] text-slate-500 font-bold uppercase tracking-widest">
                    Identity Status
                  </span>
                  <div className="text-sm font-semibold text-slate-200 mt-1 flex items-center justify-center gap-1.5">
                    {scanResult.trust_score >= 80 ? (
                      <>
                        <ShieldCheck className="w-4 h-4 text-green-400" />
                        Verified Secure
                      </>
                    ) : scanResult.trust_score >= 40 ? (
                      <>
                        <AlertTriangle className="w-4 h-4 text-amber-400" />
                        Suspicious Elements
                      </>
                    ) : (
                      <>
                        <ShieldAlert className="w-4 h-4 text-red-400" />
                        Highly Dangerous
                      </>
                    )}
                  </div>
                </div>
              </div>

              
              <div className="glass-panel p-6 rounded-2xl md:col-span-2 flex flex-col justify-between border-purple-500/10 bg-gradient-to-br from-zinc-950/60 to-black/10 relative overflow-hidden">
                
                <div className="absolute -top-12 -right-12 w-48 h-48 bg-purple-500/5 rounded-full blur-3xl pointer-events-none" />
                
                
                <div className="flex items-start gap-4">
                  <div className="shrink-0 scale-90">
                    <GhostCharacter state={getGhostState(scanResult.risk_level)} size={80} />
                  </div>
                  
                  
                  <div className="bg-zinc-950/60 border border-zinc-900/80 p-4 rounded-2xl relative flex-1">
                    <div className="absolute top-4 -left-2 w-3.5 h-3.5 bg-zinc-950 border-l border-b border-zinc-900/80 transform rotate-45" />
                    
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-1 bg-zinc-900/60 p-0.5 rounded-lg border border-zinc-800/80">
                        <button
                          onClick={() => {
                            if (isSpeaking) {
                              window.speechSynthesis.cancel();
                              setIsSpeaking(false);
                            }
                            setSpeechLang('hi');
                            setTimeout(() => toggleSpeech('hi'), 50);
                          }}
                          className={`text-[9px] px-2 py-0.5 rounded-md font-bold uppercase transition-all cursor-pointer ${
                            speechLang === 'hi'
                              ? 'bg-purple-950/60 text-purple-300 border border-purple-800/50'
                              : 'text-slate-500 hover:text-slate-300'
                          }`}
                        >
                          Hindi
                        </button>
                        <button
                          onClick={() => {
                            if (isSpeaking) {
                              window.speechSynthesis.cancel();
                              setIsSpeaking(false);
                            }
                            setSpeechLang('en');
                            setTimeout(() => toggleSpeech('en'), 50);
                          }}
                          className={`text-[9px] px-2 py-0.5 rounded-md font-bold uppercase transition-all cursor-pointer ${
                            speechLang === 'en'
                              ? 'bg-purple-950/60 text-purple-300 border border-purple-800/50'
                              : 'text-slate-500 hover:text-slate-300'
                          }`}
                        >
                          English
                        </button>
                      </div>
                      
                      <button
                        onClick={() => toggleSpeech()}
                        type="button"
                        title={isSpeaking ? "Mute Speech" : "Speak Speech"}
                        className="p-1 rounded-md hover:bg-zinc-900/85 text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
                      >
                        {isSpeaking ? (
                          <VolumeX className="w-3.5 h-3.5 text-purple-400 animate-pulse" />
                        ) : (
                          <Volume2 className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                    <p className="text-xs text-slate-300 mt-2.5 font-medium italic leading-relaxed break-words">
                      "{speechLang === 'en' ? scanResult.ghost_summary_en : scanResult.ghost_summary}"
                    </p>
                  </div>
                </div>

                
                <div className="mt-6 border-t border-zinc-900 pt-5">
                  <h3 className="text-sm font-semibold text-slate-200 tracking-wide">
                    AI Diagnostic Analysis
                  </h3>
                  <p className="text-xs text-slate-400 mt-2 leading-relaxed break-words">
                    {scanResult.ai_explanation}
                  </p>
                </div>
              </div>

            </div>

            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              
              
              <div className="glass-panel p-5 rounded-xl bg-zinc-950/30 space-y-4">
                <h4 className="text-xs uppercase font-bold text-slate-400 tracking-widest flex items-center gap-1.5 border-b border-zinc-900 pb-2">
                  <Calendar className="w-4 h-4 text-purple-400" />
                  Domain Info
                </h4>
                
                <div className="space-y-3.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-500">Domain Registrar</span>
                    <span className="font-semibold text-slate-300 truncate max-w-[150px]">
                      {scanResult.registrar}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-500">Domain Age</span>
                    <span className="font-semibold text-slate-300">
                      {scanResult.domain_age_days !== null && scanResult.domain_age_days !== undefined
                        ? `${Math.round(scanResult.domain_age_days / 365)} years (${scanResult.domain_age_days} days)`
                        : 'Unknown (RDAP Error)'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-500">Registration Risk</span>
                    <span className={`font-semibold ${
                      scanResult.domain_age_days === null || scanResult.domain_age_days === undefined || scanResult.domain_age_days < 90
                        ? 'text-red-400' 
                        : 'text-green-400'
                    }`}>
                      {scanResult.domain_age_days === null || scanResult.domain_age_days === undefined
                        ? 'Unverified' 
                        : scanResult.domain_age_days < 90 
                          ? 'New Domain (Dangerous)' 
                          : 'Highly Established'}
                    </span>
                  </div>
                </div>
              </div>

              
              <div className="glass-panel p-5 rounded-xl bg-zinc-950/30 space-y-4">
                <h4 className="text-xs uppercase font-bold text-slate-400 tracking-widest flex items-center gap-1.5 border-b border-zinc-900 pb-2">
                  <Lock className="w-4 h-4 text-blue-400" />
                  Connection Security
                </h4>

                <div className="space-y-3.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-500">HTTPS Enforced</span>
                    {scanResult.https_enabled ? (
                      scanResult.trust_score >= 70 ? (
                        <span className="font-semibold flex items-center gap-1 text-green-400">
                          <Lock className="w-3.5 h-3.5" />
                          Enabled
                        </span>
                      ) : (
                        <span className="font-semibold flex items-center gap-1 text-amber-400" title="Connection is secure but target site is risky">
                          <Lock className="w-3.5 h-3.5" />
                          Active (Low Trust)
                        </span>
                      )
                    ) : (
                      <span className="font-semibold flex items-center gap-1 text-red-400">
                        <Unlock className="w-3.5 h-3.5" />
                        Disabled
                      </span>
                    )}
                  </div>
                  
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-500">SSL Certificate</span>
                    <span className={`font-semibold ${
                      !scanResult.https_enabled
                        ? 'text-red-400'
                        : scanResult.trust_score >= 70
                          ? 'text-slate-300'
                          : 'text-amber-400'
                    }`}>
                      {!scanResult.https_enabled
                        ? 'Missing / Insecure'
                        : scanResult.trust_score >= 70
                          ? 'Valid / Encrypted'
                          : 'Valid / Suspicious Host'}
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-500">Snooping Exposure</span>
                    {scanResult.https_enabled ? (
                      scanResult.trust_score >= 70 ? (
                        <span className="font-semibold text-green-400">
                          Secure from intercept
                        </span>
                      ) : (
                        <span className="font-semibold text-red-400" title="Encryption does not make the site content safe">
                          Exposed to Scammer
                        </span>
                      )
                    ) : (
                      <span className="font-semibold text-red-400">
                        Credentials vulnerable
                      </span>
                    )}
                  </div>
                </div>
              </div>

              
              <div className="glass-panel p-5 rounded-xl bg-zinc-950/30 space-y-4">
                <h4 className="text-xs uppercase font-bold text-slate-400 tracking-widest flex items-center gap-1.5 border-b border-zinc-900 pb-2">
                  <Server className="w-4 h-4 text-amber-400" />
                  Pattern Diagnostics
                </h4>

                <div className="space-y-2.5 max-h-[105px] overflow-y-auto pr-1">
                  {scanResult.suspicious_patterns.length === 0 ? (
                    <div className="text-xs text-green-400 flex items-center gap-1.5 py-1">
                      <CheckCircle2 className="w-4 h-4" />
                      No malicious signatures found
                    </div>
                  ) : (
                    scanResult.suspicious_patterns.map((pat, idx) => (
                      <div key={idx} className="text-xs text-red-400 flex items-start gap-1.5 leading-tight">
                        <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
                        <span>{pat}</span>
                      </div>
                    ))
                  )}
                </div>
              </div>

            </div>

            
            {scanResult.scorecard && (
              <div className="glass-panel p-6 rounded-2xl bg-black/60 space-y-6">
                <div className="flex items-center justify-between border-b border-zinc-900 pb-3">
                  <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-emerald-400" />
                    Evidence Scorecard & Security Headers
                  </h3>
                  {scanResult.crawled_page_content?.favicon && (
                    <img 
                      src={scanResult.crawled_page_content.favicon} 
                      alt="favicon" 
                      className="w-5 h-5 rounded object-contain bg-zinc-900 p-0.5" 
                      onError={(e) => { e.currentTarget.style.display = 'none'; }}
                    />
                  )}
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  
                  <div className="space-y-4">
                    <h4 className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">5-Pillar Heuristics Breakdown</h4>
                    
                    <div className="space-y-3">
                      
                      <div className="space-y-1">
                        <div className="flex justify-between text-xs font-semibold text-slate-300">
                          <span>Domain Identity & Age</span>
                          <span className="text-emerald-400">{scanResult.scorecard.domain_score} <span className="text-slate-500">/ 25</span></span>
                        </div>
                        <div className="h-1.5 w-full bg-zinc-900 rounded-full overflow-hidden">
                          <div className="h-full bg-emerald-500 rounded-full" style={{ width: `${(scanResult.scorecard.domain_score / 25) * 100}%` }}></div>
                        </div>
                      </div>

                      
                      <div className="space-y-1">
                        <div className="flex justify-between text-xs font-semibold text-slate-300">
                          <span>SSL Connection & TLS</span>
                          <span className="text-blue-400">{scanResult.scorecard.ssl_score} <span className="text-slate-500">/ 20</span></span>
                        </div>
                        <div className="h-1.5 w-full bg-zinc-900 rounded-full overflow-hidden">
                          <div className="h-full bg-blue-500 rounded-full" style={{ width: `${(scanResult.scorecard.ssl_score / 20) * 100}%` }}></div>
                        </div>
                        <div className="text-[10px] text-slate-500 font-mono">Issuer: {scanResult.scorecard.ssl_issuer}</div>
                      </div>

                      
                      <div className="space-y-1">
                        <div className="flex justify-between text-xs font-semibold text-slate-300">
                          <span>DOM & Form Safety</span>
                          <span className="text-purple-400">{scanResult.scorecard.dom_score} <span className="text-slate-500">/ 25</span></span>
                        </div>
                        <div className="h-1.5 w-full bg-zinc-900 rounded-full overflow-hidden">
                          <div className="h-full bg-purple-500 rounded-full" style={{ width: `${(scanResult.scorecard.dom_score / 25) * 100}%` }}></div>
                        </div>
                        {scanResult.crawled_page_content && (
                          <div className="text-[10px] text-slate-500 font-mono flex flex-wrap gap-x-2">
                            <span>iframes: {scanResult.crawled_page_content.iframes_count || 0}</span>
                            <span>locks: {scanResult.crawled_page_content.copy_paste_locks_detected ? "Yes" : "No"}</span>
                            <span>inline js: {scanResult.crawled_page_content.inline_scripts_length || 0}B</span>
                          </div>
                        )}
                      </div>

                      
                      <div className="space-y-1">
                        <div className="flex justify-between text-xs font-semibold text-slate-300">
                          <span>HTTP Security Headers</span>
                          <span className="text-amber-400">{scanResult.scorecard.headers_score} <span className="text-slate-500">/ 15</span></span>
                        </div>
                        <div className="h-1.5 w-full bg-zinc-900 rounded-full overflow-hidden">
                          <div className="h-full bg-amber-500 rounded-full" style={{ width: `${(scanResult.scorecard.headers_score / 15) * 100}%` }}></div>
                        </div>
                      </div>

                      
                      <div className="space-y-1">
                        <div className="flex justify-between text-xs font-semibold text-slate-300">
                          <span>Scripts & Redirects</span>
                          <span className="text-cyan-400">{scanResult.scorecard.scripts_score} <span className="text-slate-500">/ 15</span></span>
                        </div>
                        <div className="h-1.5 w-full bg-zinc-900 rounded-full overflow-hidden">
                          <div className="h-full bg-cyan-500 rounded-full" style={{ width: `${(scanResult.scorecard.scripts_score / 15) * 100}%` }}></div>
                        </div>
                      </div>
                    </div>
                  </div>
                  
                  
                  <div className="space-y-4">
                    <div>
                      <h4 className="text-[10px] text-slate-500 font-bold uppercase tracking-wider mb-2">HTTP Security Headers</h4>
                      <div className="grid grid-cols-2 gap-2 text-xs font-semibold font-mono">
                        {Object.entries(scanResult.scorecard.security_headers).map(([key, val]) => {
                          if (key === "Server") return null;
                          return (
                            <div key={key} className="flex items-center gap-1.5 bg-zinc-950/40 p-2 rounded-lg border border-zinc-900/60">
                              {val ? (
                                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                              ) : (
                                <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                              )}
                              <span className="truncate text-slate-300 text-[10px]">{key}</span>
                            </div>
                          );
                        })}
                      </div>
                      <div className="text-[10px] text-slate-500 font-mono mt-2 bg-zinc-950/40 p-2 rounded-lg border border-zinc-900/60">
                        Server Banner: <span className="text-slate-300">{scanResult.scorecard.security_headers.Server || "Unknown"}</span>
                      </div>
                    </div>

                    {scanResult.threat_assessment && (
                      <div>
                        <h4 className="text-[10px] text-slate-500 font-bold uppercase tracking-wider mb-2">Threat Assessment Checklist</h4>
                        <div className="space-y-2 text-[11px] bg-zinc-950/20 p-3 rounded-xl border border-zinc-900 font-sans">
                          <div className="flex justify-between items-start gap-4">
                            <span className="text-slate-400">Brand Impersonation?</span>
                            <span className={`font-semibold text-right ${scanResult.threat_assessment.is_brand_impersonation.status ? 'text-red-400 animate-pulse' : 'text-green-400'}`} title={scanResult.threat_assessment.is_brand_impersonation.details}>
                              {scanResult.threat_assessment.is_brand_impersonation.status ? 'Yes' : 'No'}
                            </span>
                          </div>
                          <div className="flex justify-between items-start gap-4 border-t border-zinc-900/40 pt-1.5">
                            <span className="text-slate-400">Resembles Phishing Page?</span>
                            <span className={`font-semibold text-right ${scanResult.threat_assessment.resembles_phishing.status ? 'text-red-400' : 'text-green-400'}`} title={scanResult.threat_assessment.resembles_phishing.details}>
                              {scanResult.threat_assessment.resembles_phishing.status ? 'Yes' : 'No'}
                            </span>
                          </div>
                          <div className="flex justify-between items-start gap-4 border-t border-zinc-900/40 pt-1.5">
                            <span className="text-slate-400">Unusually New Domain?</span>
                            <span className={`font-semibold text-right ${scanResult.threat_assessment.is_unusually_new.status ? 'text-amber-400' : 'text-green-400'}`} title={scanResult.threat_assessment.is_unusually_new.details}>
                              {scanResult.threat_assessment.is_unusually_new.status ? 'Yes' : 'No'}
                            </span>
                          </div>
                          <div className="flex justify-between items-start gap-4 border-t border-zinc-900/40 pt-1.5">
                            <span className="text-slate-400">Requesting Sensitive Data?</span>
                            <span className={`font-semibold text-right ${scanResult.threat_assessment.requests_sensitive_info.status ? 'text-red-400' : 'text-green-400'}`} title={scanResult.threat_assessment.requests_sensitive_info.details}>
                              {scanResult.threat_assessment.requests_sensitive_info.status ? 'Yes' : 'No'}
                            </span>
                          </div>
                          <div className="flex justify-between items-start gap-4 border-t border-zinc-900/40 pt-1.5">
                            <span className="text-slate-400">Confidence Assessment:</span>
                            <span className="text-slate-200 font-semibold" title={scanResult.threat_assessment.confidence_level.details}>
                              {scanResult.threat_assessment.confidence_level.level}
                            </span>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            
            <ConsequenceVisualizer 
              consequences={scanResult.consequences} 
              riskLevel={scanResult.risk_level} 
            />

            
            <div className="glass-panel p-6 rounded-2xl bg-black/60 space-y-4">
              <h3 className="text-sm font-semibold text-slate-100">
                Guardian Action Plan
              </h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {scanResult.recommendations.map((rec, index) => (
                  <div key={index} className="flex items-start gap-3 p-3 rounded-xl bg-zinc-950/40 border border-zinc-900">
                    <div className={`w-5 h-5 rounded-full flex items-center justify-center shrink-0 mt-0.5 ${
                      scanResult.trust_score >= 80 
                        ? 'bg-green-950/30 text-green-400' 
                        : 'bg-amber-950/30 text-amber-400'
                    }`}>
                      <CheckCircle2 className="w-3.5 h-3.5" />
                    </div>
                    <span className="text-xs text-slate-300 leading-relaxed font-medium">
                      {rec}
                    </span>
                  </div>
                ))}
              </div>
            </div>

          </div>
        )}

      </main>

      
      <footer className="relative z-10 border-t border-zinc-900 bg-black/70 py-6 text-center text-[10px] text-slate-500 font-semibold tracking-wider uppercase mt-12">
        👻 GhostNet — The Ghost That Browses Before You.
      </footer>
    </div>
  );
}
