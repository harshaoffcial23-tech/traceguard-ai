import React, { useState } from 'react';
import { Lock, Mail, User as UserIcon, Shield, X, AlertCircle, CheckCircle2 } from 'lucide-react';
import { login, register } from '../services/api';
import { User, UserRole } from '../types';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAuthSuccess: (user: User) => void;
  initialMode?: 'login' | 'register';
}

export const AuthModal: React.FC<AuthModalProps> = ({
  isOpen,
  onClose,
  onAuthSuccess,
  initialMode = 'login',
}) => {
  const [mode, setMode] = useState<'login' | 'register'>(initialMode);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [role, setRole] = useState<UserRole>('operator');
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);

    try {
      if (mode === 'login') {
        const res = await login({ email, password });
        onAuthSuccess(res.user);
        onClose();
      } else {
        const res = await register({
          email,
          password,
          full_name: fullName,
          role,
        });
        onAuthSuccess(res.user);
        onClose();
      }
    } catch (err: any) {
      setError(err.message || 'Authentication failed. Please check your credentials.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleQuickDemoFill = () => {
    setEmail('admin@traceguard.internal');
    setPassword('AdminSecurePass123!');
    setMode('login');
    setError(null);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md">
      <div className="relative w-full max-w-md glass-panel border border-white/20 rounded-2xl shadow-2xl p-6 sm:p-7 overflow-hidden">
        {/* Subtle accent highlight */}
        <div className="absolute top-0 left-0 right-0 h-1 bg-linear-to-r from-transparent via-[#C7F36B] to-transparent"></div>

        {/* Close button */}
        <button
          type="button"
          onClick={onClose}
          className="absolute top-4 right-4 text-[#8E969E] hover:text-white p-1 rounded-lg hover:bg-white/10 transition cursor-pointer"
        >
          <X className="w-4 h-4" />
        </button>

        {/* Header */}
        <div className="flex items-center gap-3.5 mb-6">
          <div className="w-10 h-10 rounded-xl bg-white/[0.05] border border-white/15 flex items-center justify-center text-[#C7F36B]">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-white">
              {mode === 'login' ? 'TraceGuard Gateway Access' : 'Register Operator Identity'}
            </h3>
            <p className="text-xs text-[#8E969E]">
              {mode === 'login'
                ? 'Authenticate to enforce invariants and run agent tasks'
                : 'Create an authorized operator session'}
            </p>
          </div>
        </div>

        {/* Mode Switcher Tabs */}
        <div className="grid grid-cols-2 gap-1 p-1 bg-black/60 border border-white/10 rounded-xl mb-5 text-xs font-medium">
          <button
            type="button"
            onClick={() => {
              setMode('login');
              setError(null);
            }}
            className={`py-2 rounded-lg transition cursor-pointer ${
              mode === 'login'
                ? 'bg-white/15 text-white font-semibold shadow-xs'
                : 'text-[#8E969E] hover:text-white'
            }`}
          >
            Sign In
          </button>
          <button
            type="button"
            onClick={() => {
              setMode('register');
              setError(null);
            }}
            className={`py-2 rounded-lg transition cursor-pointer ${
              mode === 'register'
                ? 'bg-white/15 text-white font-semibold shadow-xs'
                : 'text-[#8E969E] hover:text-white'
            }`}
          >
            Register
          </button>
        </div>

        {/* Error message */}
        {error && (
          <div className="flex items-start gap-2.5 p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-xs mb-4">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
            <span>{error}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          {mode === 'register' && (
            <div>
              <label className="block text-[#8E969E] font-medium mb-1">Full Name</label>
              <div className="relative">
                <UserIcon className="w-4 h-4 text-[#535C64] absolute left-3 top-2.5" />
                <input
                  type="text"
                  required
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="e.g. Alex Vance"
                  className="w-full bg-black/80 border border-white/10 rounded-xl py-2 pl-9 pr-3 text-white placeholder-[#535C64] focus:outline-hidden focus:border-[#C7F36B] transition font-mono"
                />
              </div>
            </div>
          )}

          <div>
            <label className="block text-[#8E969E] font-medium mb-1">Email Address</label>
            <div className="relative">
              <Mail className="w-4 h-4 text-[#535C64] absolute left-3 top-2.5" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="operator@traceguard.internal"
                className="w-full bg-black/80 border border-white/10 rounded-xl py-2 pl-9 pr-3 text-white placeholder-[#535C64] focus:outline-hidden focus:border-[#C7F36B] transition font-mono"
              />
            </div>
          </div>

          <div>
            <label className="block text-[#8E969E] font-medium mb-1">
              Password {mode === 'register' && <span className="text-[#535C64] font-normal">(min. 8 characters)</span>}
            </label>
            <div className="relative">
              <Lock className="w-4 h-4 text-[#535C64] absolute left-3 top-2.5" />
              <input
                type="password"
                required
                minLength={8}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-black/80 border border-white/10 rounded-xl py-2 pl-9 pr-3 text-white placeholder-[#535C64] focus:outline-hidden focus:border-[#C7F36B] transition font-mono"
              />
            </div>
          </div>

          {mode === 'register' && (
            <div className="p-3 rounded-xl bg-black/60 border border-white/10 text-[11px] text-[#8E969E]">
              <span className="text-white font-medium">Provisioning Policy:</span> New gateway registrations are assigned the <strong className="text-[#C7F36B]">Operator</strong> role. SecOps Administrator permissions require server-side promotion.
            </div>
          )}

          <button
            type="submit"
            disabled={isLoading}
            className="w-full mt-2 glass-button-primary py-2.5 px-4 rounded-full text-white font-semibold text-xs tracking-wide transition shadow-lg flex items-center justify-center gap-2 disabled:opacity-60 cursor-pointer"
          >
            {isLoading ? (
              <span className="inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></span>
            ) : mode === 'login' ? (
              'Authenticate Session'
            ) : (
              'Create Authorized Identity'
            )}
          </button>
        </form>

        {/* Quick Demo Login Option */}
        <div className="mt-5 pt-4 border-t border-white/10 flex flex-col gap-2">
          <button
            type="button"
            onClick={handleQuickDemoFill}
            className="text-[11px] font-mono text-[#8E969E] hover:text-[#C7F36B] flex items-center justify-center gap-1.5 transition py-2 px-3 rounded-xl bg-white/[0.03] hover:bg-white/[0.07] border border-white/10 cursor-pointer"
          >
            <CheckCircle2 className="w-3.5 h-3.5 text-[#C7F36B]" />
            <span>Fill Demo Admin (admin@traceguard.internal)</span>
          </button>
        </div>
      </div>
    </div>
  );
};
