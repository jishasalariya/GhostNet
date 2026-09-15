import React, { useEffect, useState } from 'react';

interface TrustScoreProps {
  score: number;
  riskLevel: string;
  size?: number;
  strokeWidth?: number;
}

export const TrustScore: React.FC<TrustScoreProps> = ({
  score,
  riskLevel,
  size = 180,
  strokeWidth = 14
}) => {
  const safeScore = Math.max(0, Math.min(100, Number.isFinite(score) ? score : 0));
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    const duration = 900;
    const startTime = performance.now();
    let frameId = 0;

    const animate = (currentTime: number) => {
      const progress = Math.min((currentTime - startTime) / duration, 1);
      const eased = progress * (2 - progress);
      setAnimatedScore(Math.round(eased * safeScore));
      if (progress < 1) {
        frameId = requestAnimationFrame(animate);
      }
    };

    frameId = requestAnimationFrame(animate);

    return () => cancelAnimationFrame(frameId);
  }, [safeScore]);

  let color = '#EF4444';
  let shadowGlow = 'rgba(239, 68, 68, 0.3)';

  if (safeScore >= 80) {
    color = '#22C55E';
    shadowGlow = 'rgba(34, 197, 94, 0.3)';
  } else if (safeScore >= 60) {
    color = '#3B82F6';
    shadowGlow = 'rgba(59, 130, 246, 0.3)';
  } else if (safeScore >= 40) {
    color = '#F59E0B';
    shadowGlow = 'rgba(245, 158, 11, 0.3)';
  }

  const radius = Math.max(1, (size - strokeWidth) / 2);
  const circumference = radius * 2 * Math.PI;
  const offset = circumference - (animatedScore / 100) * circumference;

  return (
    <div className="relative flex flex-col items-center justify-center" style={{ width: size, height: size }}>
      <div
        className="absolute inset-2 rounded-full blur-xl transition-all duration-700 opacity-20"
        style={{ background: color }}
      />
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="#18181b"
          strokeWidth={strokeWidth}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 0.1s ease-out, stroke 0.5s ease' }}
        />
      </svg>
      <div className="absolute flex flex-col items-center justify-center text-center">
        <span
          className="text-4xl md:text-5xl font-bold font-mono tracking-tight"
          style={{ color, textShadow: `0 0 10px ${shadowGlow}` }}
        >
          {animatedScore}
        </span>
        <span className="text-xs uppercase tracking-widest text-slate-400 font-semibold mt-1">
          Trust Score
        </span>
        <span
          className="text-xs font-semibold px-2 py-0.5 rounded-full mt-2 border"
          style={{
            borderColor: `${color}40`,
            backgroundColor: `${color}15`,
            color
          }}
        >
          {riskLevel}
        </span>
      </div>
    </div>
  );
};

export default TrustScore;
