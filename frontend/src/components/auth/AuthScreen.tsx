// Extend window type for grecaptcha
declare global {
  interface Window {
    grecaptcha: any;
    onRecaptchaLoad?: () => void;
  }
}

import React, { useState, useEffect, useRef } from 'react';
import { Tabs } from '@ark-ui/react';
import { Lock, Mail, User, Building, ArrowRight, AlertCircle } from 'lucide-react';
import { api } from '../../services/api';

interface AuthScreenProps {
  onLoginSuccess: (user: any) => void;
}

const RECAPTCHA_SITE_KEY = ((import.meta as any).env?.VITE_RECAPTCHA_SITE_KEY as string | undefined) || '';

export const AuthScreen: React.FC<AuthScreenProps> = ({ onLoginSuccess }) => {
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [organization, setOrganization] = useState('');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const recaptchaReady = useRef(false);

  // Load reCAPTCHA v3 script
  useEffect(() => {
    if (!RECAPTCHA_SITE_KEY) return;
    if (document.getElementById('recaptcha-script')) return;
    const script = document.createElement('script');
    script.id = 'recaptcha-script';
    script.src = `https://www.google.com/recaptcha/api.js?render=${RECAPTCHA_SITE_KEY}`;
    script.async = true;
    script.onload = () => { recaptchaReady.current = true; };
    document.head.appendChild(script);
    return () => { /* intentionally keep script loaded */ };
  }, []);

  const getRecaptchaToken = (action: string): Promise<string | null> => {
    return new Promise((resolve) => {
      if (!RECAPTCHA_SITE_KEY || !window.grecaptcha) {
        resolve(null);
        return;
      }
      window.grecaptcha.ready(() => {
        window.grecaptcha.execute(RECAPTCHA_SITE_KEY, { action }).then((token: string) => {
          resolve(token);
        }).catch(() => resolve(null));
      });
    });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setLoading(true);

    try {
      const recaptchaToken = await getRecaptchaToken(isRegister ? 'register' : 'login');
      if (isRegister) {
        const res = await api.register(email, password, fullName, organization, recaptchaToken ?? undefined);
        onLoginSuccess(res.user);
      } else {
        const res = await api.login(email, password, recaptchaToken ?? undefined);
        onLoginSuccess(res.user);
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-screen flex items-center justify-center bg-slate-50 px-4 relative overflow-hidden font-sans">
      {/* Abstract geometric SVG background */}
      <svg
        className="absolute inset-0 w-full h-full pointer-events-none"
        xmlns="http://www.w3.org/2000/svg"
        aria-hidden="true"
      >
        <defs>
          <pattern id="geo-grid" width="60" height="60" patternUnits="userSpaceOnUse">
            <path d="M 60 0 L 0 0 0 60" fill="none" stroke="#e2e8f0" strokeWidth="0.5"/>
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#geo-grid)" />
        {/* Large hexagon outlines */}
        <polygon points="120,30 180,65 180,135 120,170 60,135 60,65" fill="none" stroke="#f97316" strokeWidth="1" opacity="0.15"/>
        <polygon points="420,80 500,125 500,215 420,260 340,215 340,125" fill="none" stroke="#f97316" strokeWidth="1.5" opacity="0.1"/>
        <polygon points="850,20 920,60 920,140 850,180 780,140 780,60" fill="none" stroke="#94a3b8" strokeWidth="1" opacity="0.2"/>
        <polygon points="1100,200 1160,235 1160,305 1100,340 1040,305 1040,235" fill="none" stroke="#f97316" strokeWidth="1" opacity="0.12"/>
        <polygon points="200,400 260,435 260,505 200,540 140,505 140,435" fill="none" stroke="#94a3b8" strokeWidth="1" opacity="0.15"/>
        <polygon points="700,500 760,535 760,605 700,640 640,605 640,535" fill="none" stroke="#f97316" strokeWidth="1" opacity="0.1"/>
        {/* Circles */}
        <circle cx="80" cy="80" r="40" fill="none" stroke="#f97316" strokeWidth="1" opacity="0.1"/>
        <circle cx="1200" cy="100" r="60" fill="none" stroke="#94a3b8" strokeWidth="1" opacity="0.12"/>
        <circle cx="950" cy="600" r="80" fill="none" stroke="#f97316" strokeWidth="1" opacity="0.08"/>
        <circle cx="250" cy="650" r="50" fill="none" stroke="#94a3b8" strokeWidth="1" opacity="0.1"/>
        {/* Diagonal accent lines */}
        <line x1="0" y1="0" x2="300" y2="300" stroke="#f97316" strokeWidth="0.5" opacity="0.08"/>
        <line x1="1300" y1="0" x2="1000" y2="300" stroke="#94a3b8" strokeWidth="0.5" opacity="0.08"/>
        <line x1="0" y1="700" x2="200" y2="500" stroke="#f97316" strokeWidth="0.5" opacity="0.08"/>
        {/* Small diamonds */}
        <rect x="300" y="50" width="16" height="16" transform="rotate(45 308 58)" fill="none" stroke="#f97316" strokeWidth="1" opacity="0.2"/>
        <rect x="1050" y="400" width="12" height="12" transform="rotate(45 1056 406)" fill="none" stroke="#94a3b8" strokeWidth="1" opacity="0.2"/>
        <rect x="80" y="550" width="10" height="10" transform="rotate(45 85 555)" fill="none" stroke="#f97316" strokeWidth="1" opacity="0.15"/>
        {/* Triangle outlines */}
        <polygon points="1150,500 1200,580 1100,580" fill="none" stroke="#f97316" strokeWidth="1" opacity="0.12"/>
        <polygon points="400,600 440,660 360,660" fill="none" stroke="#94a3b8" strokeWidth="1" opacity="0.1"/>
        {/* Orange gradient glow blobs */}
        <circle cx="15%" cy="25%" r="180" fill="#f97316" opacity="0.04"/>
        <circle cx="85%" cy="75%" r="200" fill="#fb923c" opacity="0.04"/>
      </svg>

      <div className="w-full max-w-md bg-white rounded-2xl border border-slate-200 p-8 relative z-10">
        {/* Brand Banner */}
        <div className="text-center mb-8">
          <img
            src="/logo.png"
            alt="VegaIntel"
            className="inline-flex w-16 h-16 object-contain rounded-xl shadow-sm border border-slate-200 mb-3"
          />
          <h1 className="text-2xl font-bold tracking-wider text-slate-900">
            VEGA<span className="text-orange-600 font-extrabold">INTEL</span>
          </h1>
          <p className="text-xs text-slate-500 font-mono mt-1 uppercase tracking-wider">
            Threat Intelligence Platform
          </p>
        </div>

        {/* Ark UI Tab Switcher */}
        <Tabs.Root
          value={isRegister ? 'register' : 'login'}
          onValueChange={(details) => {
            setIsRegister(details.value === 'register');
            setErrorMsg(null);
          }}
          className="mb-6 font-mono text-xs"
        >
          <Tabs.List className="flex rounded-lg bg-slate-100 border border-slate-200 p-1 gap-1">
            <Tabs.Trigger
              value="login"
              className={`flex-1 py-2 rounded-md font-semibold transition-all text-center ${
                !isRegister
                  ? 'bg-white text-orange-600 shadow-sm border border-slate-200 font-bold'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Sign In
            </Tabs.Trigger>
            <Tabs.Trigger
              value="register"
              className={`flex-1 py-2 rounded-md font-semibold transition-all text-center ${
                isRegister
                  ? 'bg-white text-orange-600 shadow-sm border border-slate-200 font-bold'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Create Account
            </Tabs.Trigger>
          </Tabs.List>
        </Tabs.Root>

        {/* Error Alert */}
        {errorMsg && (
          <div className="mb-4 p-3 rounded-lg bg-red-50 border border-red-200 text-red-700 text-xs font-mono flex items-start gap-2">
            <AlertCircle className="w-4 h-4 text-red-500 shrink-0 mt-0.5" />
            <span>{errorMsg}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4 text-xs font-mono">
          {isRegister && (
            <>
              <div>
                <label className="block text-slate-700 uppercase mb-1 font-semibold text-[11px]">
                  Full Name
                </label>
                <div className="relative">
                  <User className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    required
                    placeholder="Jane Doe"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    className="w-full pl-10 pr-4 py-2.5 bg-white border border-slate-300 rounded-lg text-slate-900 placeholder-slate-400 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-700 uppercase mb-1 font-semibold text-[11px]">
                  Organization / Team
                </label>
                <div className="relative">
                  <Building className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    placeholder="Security Operations Center"
                    value={organization}
                    onChange={(e) => setOrganization(e.target.value)}
                    className="w-full pl-10 pr-4 py-2.5 bg-white border border-slate-300 rounded-lg text-slate-900 placeholder-slate-400 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500"
                  />
                </div>
              </div>
            </>
          )}

          <div>
            <label className="block text-slate-700 uppercase mb-1 font-semibold text-[11px]">
              Email Address *
            </label>
            <div className="relative">
              <Mail className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="email"
                required
                placeholder="analyst@organization.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full pl-10 pr-4 py-2.5 bg-white border border-slate-300 rounded-lg text-slate-900 placeholder-slate-400 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-slate-700 uppercase mb-1 font-semibold text-[11px]">
              Password *
            </label>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="password"
                required
                placeholder="••••••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full pl-10 pr-4 py-2.5 bg-white border border-slate-300 rounded-lg text-slate-900 placeholder-slate-400 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 rounded-lg bg-orange-500 hover:bg-orange-600 text-white font-bold uppercase tracking-wider text-xs shadow-md transition-all flex items-center justify-center gap-2 mt-2"
          >
            <span>{loading ? 'Authenticating...' : isRegister ? 'Create Account & Enter' : 'Sign In'}</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>
      </div>
    </div>
  );
};
