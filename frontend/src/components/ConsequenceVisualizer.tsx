import React, { useEffect, useMemo, useState } from 'react';
import { ShieldAlert, ShieldCheck, Play, RotateCcw } from 'lucide-react';

interface ConsequenceStep {
  step: string;
  description: string;
  risk: string;
}

interface ConsequenceVisualizerProps {
  consequences: ConsequenceStep[];
  riskLevel: string;
}

export const ConsequenceVisualizer: React.FC<ConsequenceVisualizerProps> = ({
  consequences,
  riskLevel
}) => {
  const safeConsequences = useMemo(
    () => consequences.filter((item) => item && item.step && item.description),
    [consequences]
  );
  const [activeStep, setActiveStep] = useState(0);
  const [simulationRunning, setSimulationRunning] = useState(false);

  useEffect(() => {
    setActiveStep((current) => Math.min(current, Math.max(0, safeConsequences.length - 1)));
  }, [safeConsequences.length]);

  useEffect(() => {
    if (!simulationRunning || safeConsequences.length <= 1) {
      if (simulationRunning && safeConsequences.length <= 1) {
        setSimulationRunning(false);
      }
      return;
    }

    let current = activeStep;
    const interval = window.setInterval(() => {
      current += 1;
      if (current < safeConsequences.length) {
        setActiveStep(current);
      } else {
        window.clearInterval(interval);
        setSimulationRunning(false);
      }
    }, 1800);

    return () => window.clearInterval(interval);
  }, [simulationRunning, safeConsequences.length]);

  const resetSimulation = () => {
    setActiveStep(0);
    setSimulationRunning(false);
  };

  const runSimulation = () => {
    if (safeConsequences.length <= 1) {
      setActiveStep(0);
      return;
    }
    setActiveStep(0);
    setSimulationRunning(true);
  };

  const getRiskStyles = (risk: string, isActive: boolean) => {
    const normalizedRisk = risk.toLowerCase();
    const isDanger = ['danger', 'critical', 'compromised'].includes(normalizedRisk);
    const isWarning = ['warning', 'medium'].includes(normalizedRisk);

    if (isDanger) {
      return {
        dotClass: isActive ? 'bg-red-500 ring-4 ring-red-500/30 shadow-[0_0_12px_#ef4444]' : 'bg-red-900/60',
        textClass: isActive ? 'text-red-400 font-bold' : 'text-red-900/80',
        borderClass: isActive ? 'border-red-500/40 bg-red-950/20' : 'border-red-950/20 bg-transparent',
        badge: 'Danger'
      };
    }

    if (isWarning) {
      return {
        dotClass: isActive ? 'bg-amber-500 ring-4 ring-amber-500/30 shadow-[0_0_12px_#f59e0b]' : 'bg-amber-900/60',
        textClass: isActive ? 'text-amber-400 font-semibold' : 'text-amber-900/80',
        borderClass: isActive ? 'border-amber-500/40 bg-amber-950/10' : 'border-amber-950/20 bg-transparent',
        badge: 'Warning'
      };
    }

    return {
      dotClass: isActive ? 'bg-green-500 ring-4 ring-green-500/30 shadow-[0_0_12px_#22c55e]' : 'bg-green-900/60',
      textClass: isActive ? 'text-green-400 font-semibold' : 'text-green-900/80',
      borderClass: isActive ? 'border-green-500/40 bg-green-950/10' : 'border-green-950/20 bg-transparent',
      badge: 'Secure'
    };
  };

  if (safeConsequences.length === 0) {
    return (
      <div className="glass-panel p-6 rounded-2xl flex flex-col items-center justify-center text-center">
        <ShieldCheck className="w-12 h-12 text-slate-500 mb-2" />
        <span className="text-slate-400 font-medium">No threat visualization available.</span>
      </div>
    );
  }

  const isMalicious = ['high risk', 'critical', 'danger'].includes(riskLevel.toLowerCase());
  const progress = safeConsequences.length <= 1 ? 100 : (activeStep / (safeConsequences.length - 1)) * 100;

  return (
    <div className="glass-panel p-6 rounded-2xl border border-zinc-900 bg-black/90">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <h3 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
            <ShieldAlert className={`w-5 h-5 ${isMalicious ? 'text-red-400' : 'text-blue-400'}`} />
            What Happens If I Continue?
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            An educational threat model tracing the path of interaction with this URL.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {!simulationRunning && activeStep > 0 ? (
            <button
              type="button"
              onClick={resetSimulation}
              className="flex items-center gap-1 text-xs px-3 py-1.5 rounded-lg border border-zinc-700 bg-zinc-800 text-slate-300 hover:bg-zinc-700 hover:text-white transition-all cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Reset
            </button>
          ) : null}
          <button
            type="button"
            onClick={runSimulation}
            disabled={simulationRunning}
            className={`flex items-center gap-1.5 text-xs px-4 py-2 rounded-lg font-medium transition-all cursor-pointer ${
              simulationRunning
                ? 'bg-zinc-800 text-slate-500 border border-zinc-700'
                : isMalicious
                  ? 'bg-red-500/20 border border-red-500/40 text-red-300 hover:bg-red-500/30'
                  : 'bg-blue-500/20 border border-blue-500/40 text-blue-300 hover:bg-blue-500/30'
            }`}
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            {simulationRunning ? 'Simulating...' : 'Simulate Threat Flow'}
          </button>
        </div>
      </div>

      <div className="relative pl-8 md:pl-0 md:grid md:grid-cols-4 gap-4">
        <div className="hidden md:block absolute top-[18px] left-[12%] right-[12%] h-0.5 bg-zinc-800 z-0">
          <div
            className={`h-full transition-all duration-700 ${isMalicious ? 'bg-red-500/50' : 'bg-green-500/50'}`}
            style={{ width: `${progress}%` }}
          />
        </div>
        <div className="md:hidden absolute top-4 bottom-4 left-[14px] w-0.5 bg-zinc-800 z-0">
          <div
            className={`w-full transition-all duration-700 ${isMalicious ? 'bg-red-500/50' : 'bg-green-500/50'}`}
            style={{ height: `${progress}%` }}
          />
        </div>

        {safeConsequences.map((item, index) => {
          const isActive = index <= activeStep;
          const isCurrent = index === activeStep;
          const styles = getRiskStyles(item.risk, isActive);

          return (
            <button
              type="button"
              key={`${item.step}-${index}`}
              onClick={() => !simulationRunning && setActiveStep(index)}
              className={`relative z-10 flex flex-col items-start md:items-center text-left md:text-center p-3 rounded-xl border transition-all duration-500 cursor-pointer ${styles.borderClass} ${
                isCurrent ? 'scale-103 shadow-lg' : 'hover:bg-zinc-900/20'
              }`}
            >
              <div
                className={`w-8 h-8 rounded-full flex items-center justify-center font-bold text-xs text-slate-100 mb-3 transition-all duration-500 ${styles.dotClass}`}
              >
                {index + 1}
              </div>
              <div className="flex items-center gap-1.5 md:flex-col mt-1">
                <span className={`text-sm font-semibold tracking-wide transition-colors duration-500 ${isActive ? 'text-slate-100' : 'text-slate-500'}`}>
                  {item.step.replace(/^\d+\.\s*/, '')}
                </span>
                {isActive && (
                  <span className={`text-[9px] uppercase tracking-wider px-1.5 py-0.5 rounded-md font-bold mt-1 scale-90 ${
                    styles.badge === 'Danger'
                      ? 'border border-red-500/30 bg-red-500/10 text-red-400'
                      : styles.badge === 'Warning'
                        ? 'border border-amber-500/30 bg-amber-500/10 text-amber-400'
                        : 'border border-green-500/30 bg-green-500/10 text-green-400'
                  }`}>
                    {styles.badge}
                  </span>
                )}
              </div>
              <p className={`text-xs mt-2 transition-all duration-500 line-clamp-3 md:line-clamp-none ${
                isActive ? 'text-slate-300' : 'text-slate-600'
              }`}>
                {item.description}
              </p>
            </button>
          );
        })}
      </div>
    </div>
  );
};

export default ConsequenceVisualizer;
