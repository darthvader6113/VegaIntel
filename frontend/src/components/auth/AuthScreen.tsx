// Extend window type for grecaptcha
declare global {
  interface Window {
    grecaptcha: any;
    onRecaptchaLoad?: () => void;
  }
}

import React, { useState, useEffect, useRef } from 'react';
import { Lock, Mail, User, Building, ArrowRight, AlertCircle, ShieldCheck } from 'lucide-react';
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
      if (isRegister) {
        // Registration Flow
        const token = await getRecaptchaToken('register');
        const regRes = await api.register({
          email: email.trim().toLowerCase(),
          password: password.trim(),
          full_name: fullName.trim() || undefined,
          organization: organization.trim() || undefined,
          recaptcha_token: token || undefined,
        });

        onLoginSuccess(regRes.user);
      } else {
        // Login Flow
        const token = await getRecaptchaToken('login');
        const res = await api.login(email.trim().toLowerCase(), password.trim(), token || undefined);
        onLoginSuccess(res.user);
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Authentication failed. Please check your credentials.');
    } finally {
      setLoading(false);
    }
  };

  const handleDemoLogin = () => {
    setEmail('analyst@vegaintel.io');
    setPassword('VegaIntel2026!');
    setIsRegister(false);
    setErrorMsg(null);
  };

  return (
    <div className="min-h-screen w-screen flex items-center justify-center p-6 bg-[#f8fafc] text-slate-800 font-sans relative overflow-hidden select-none">
      {/* Abstract Geometric SVG Background (No Shadows, Crisp Clean Enterprise) */}
      <div className="absolute inset-0 z-0 pointer-events-none opacity-40">
        <svg className="w-full h-full" xmlns="http://www.w3.org/2000/svg">
          <defs>
            <pattern id="sec-grid" width="48" height="48" patternUnits="userSpaceOnUse">
              <path d="M 48 0 L 0 0 0 48" fill="none" stroke="#e2e8f0" strokeWidth="0.8" />
              <circle cx="24" cy="24" r="1" fill="#cbd5e1" />
            </pattern>
            <linearGradient id="geom-grad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#ea580c" stopOpacity="0.08" />
              <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.03" />
            </linearGradient>
          </defs>
          <rect width="100%" height="100%" fill="url(#sec-grid)" />
          {/* Subtle Abstract Polygonal Accents */}
          <polygon points="0,0 600,0 450,400 0,250" fill="url(#geom-grad)" />
          <polygon points="1200,800 1800,400 1800,1000 1000,1000" fill="url(#geom-grad)" />
          <line x1="100" y1="200" x2="500" y2="600" stroke="#f97316" strokeWidth="0.5" strokeDasharray="4 8" opacity="0.4" />
          <line x1="800" y1="100" x2="1400" y2="700" stroke="#0ea5e9" strokeWidth="0.5" strokeDasharray="6 6" opacity="0.3" />
        </svg>
      </div>

      {/* Main Auth Container (Zero Shadow, Pure Border) */}
      <div className="w-full max-w-md bg-white rounded-2xl border border-slate-200/90 p-8 relative z-10 shadow-xs">
        {/* Brand Banner */}
        <div className="text-center mb-8">
          <img
            src="/logo.png"
            alt="VegaIntel"
            className="inline-flex w-14 h-14 object-contain rounded-xl border border-slate-200/80 p-0.5 bg-slate-50 mb-3"
          />
          <h1 className="text-2xl font-bold tracking-wider text-slate-900">
            VEGA<span className="text-orange-600 font-extrabold">INTEL</span>
          </h1>
          <p className="text-[11px] text-slate-400 font-mono mt-1 uppercase tracking-wider">
            Enterprise Threat Intelligence Platform
          </p>
        </div>

        {/* Native Pure React Tab Switcher (No Ark UI Zag runtime dependency) */}
        <div className="flex rounded-xl bg-slate-100/80 border border-slate-200/80 p-1 gap-1 mb-6 font-mono text-xs">
          <button
            type="button"
            onClick={() => {
              setIsRegister(false);
              setErrorMsg(null);
            }}
            className={`flex-1 py-2 rounded-lg font-bold transition-all text-center ${
              !isRegister
                ? 'bg-white text-orange-600 border border-slate-200 shadow-2xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Sign In
          </button>
          <button
            type="button"
            onClick={() => {
              setIsRegister(true);
              setErrorMsg(null);
            }}
            className={`flex-1 py-2 rounded-lg font-bold transition-all text-center ${
              isRegister
                ? 'bg-white text-orange-600 border border-slate-200 shadow-2xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Create Account
          </button>
        </div>

        {/* Error Alert */}
        {errorMsg && (
          <div className="mb-4 p-3.5 rounded-xl bg-rose-50 border border-rose-200 text-rose-700 text-xs font-mono flex items-start gap-2.5">
            <AlertCircle className="w-4 h-4 text-rose-500 shrink-0 mt-0.5" />
            <span>{errorMsg}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4 text-xs font-mono">
          {isRegister && (
            <>
              <div>
                <label className="block text-slate-700 uppercase mb-1 font-bold text-[11px]">
                  Full Name
                </label>
                <div className="relative">
                  <User className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    required
                    placeholder="Alex Mercer"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    className="w-full pl-10 pr-4 py-2 bg-slate-50 hover:bg-slate-100/70 focus:bg-white border border-slate-300 rounded-lg text-slate-900 placeholder-slate-400 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 transition-all"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-700 uppercase mb-1 font-bold text-[11px]">
                  Organization / Team
                </label>
                <div className="relative">
                  <Building className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    placeholder="Global Threat Intelligence Unit"
                    value={organization}
                    onChange={(e) => setOrganization(e.target.value)}
                    className="w-full pl-10 pr-4 py-2 bg-slate-50 hover:bg-slate-100/70 focus:bg-white border border-slate-300 rounded-lg text-slate-900 placeholder-slate-400 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 transition-all"
                  />
                </div>
              </div>
            </>
          )}

          <div>
            <label className="block text-slate-700 uppercase mb-1 font-bold text-[11px]">
              Email Address *
            </label>
            <div className="relative">
              <Mail className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="email"
                required
                placeholder="analyst@enterprise.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-slate-50 hover:bg-slate-100/70 focus:bg-white border border-slate-300 rounded-lg text-slate-900 placeholder-slate-400 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 transition-all"
              />
            </div>
          </div>

          <div>
            <label className="block text-slate-700 uppercase mb-1 font-bold text-[11px]">
              Password *
            </label>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="password"
                required
                minLength={6}
                placeholder="••••••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-slate-50 hover:bg-slate-100/70 focus:bg-white border border-slate-300 rounded-lg text-slate-900 placeholder-slate-400 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 transition-all"
              />
            </div>
            {isRegister && (
              <span className="text-[10px] text-slate-400 mt-1 block">
                Must be at least 6 characters long.
              </span>
            )}
          </div>

          <button
            type="submit"
            disabled={loading}
            className={`w-full py-2.5 px-4 rounded-xl text-xs font-mono font-bold uppercase tracking-wider transition-all flex items-center justify-center gap-2 mt-6 ${
              loading
                ? 'bg-orange-200 text-orange-800 cursor-wait'
                : 'bg-orange-500 hover:bg-orange-600 active:scale-98 text-white shadow-xs'
            }`}
          >
            <span>{loading ? 'Processing...' : isRegister ? 'Create Account' : 'Authenticate'}</span>
            {!loading && <ArrowRight className="w-4 h-4" />}
          </button>

          {!isRegister && (
            <button
              type="button"
              onClick={handleDemoLogin}
              className="w-full py-2 px-3 rounded-lg border border-slate-200 hover:bg-slate-50 text-[11px] font-mono text-slate-600 hover:text-slate-900 transition-colors flex items-center justify-center gap-1.5"
            >
              <span>Auto-Fill Demo Analyst Credentials</span>
            </button>
          )}
        </form>

        {/* Security Notice */}
        <div className="mt-6 pt-4 border-t border-slate-100 text-center">
          <div className="flex items-center justify-center gap-1.5 text-[10px] text-slate-400 font-mono">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
            <span>OASIS STIX 2.1 Compliant • Zero Trust Session</span>
          </div>
        </div>
      </div>
    </div>
  );
};
