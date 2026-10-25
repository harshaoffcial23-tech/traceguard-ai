import React, { useRef, useEffect, useState } from 'react';
import { Shield, Lock, Database, FileText, Mail, Globe, Zap, AlertTriangle } from 'lucide-react';

interface Node3D {
  id: string;
  label: string;
  sublabel: string;
  x: number;
  y: number;
  z: number;
  color: string;
  icon: string;
  status: 'active' | 'blocked' | 'verified';
}

interface Packet3D {
  fromIndex: number;
  toIndex: number;
  progress: number;
  speed: number;
  isAttack: boolean;
  label: string;
}

export const Interactive3DGateway: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const [activeScenario, setActiveScenario] = useState<'normal' | 'attack' | 'invariant'>('attack');
  const [hoveredNode, setHoveredNode] = useState<Node3D | null>(null);

  // Rotation angles
  const rotX = useRef<number>(0.2);
  const rotY = useRef<number>(0.4);
  const isDragging = useRef<boolean>(false);
  const lastMousePos = useRef<{ x: number; y: number }>({ x: 0, y: 0 });

  // 3D Nodes Definition
  const nodes: Node3D[] = [
    { id: 'gateway', label: 'TraceGuard Core', sublabel: 'Zero-Trust Gateway', x: 0, y: 0, z: 0, color: '#C7F36B', icon: 'shield', status: 'verified' },
    { id: 'agent', label: 'Autonomous Agent', sublabel: 'Untrusted Caller', x: -160, y: -90, z: 40, color: '#929CA3', icon: 'zap', status: 'active' },
    { id: 'db', label: 'Internal SQL Vault', sublabel: 'Strict AST Checked', x: 170, y: -70, z: -30, color: '#38BDF8', icon: 'db', status: 'verified' },
    { id: 'files', label: 'Customer Documents', sublabel: 'Sandbox Isolated', x: 150, y: 100, z: 60, color: '#A78BFA', icon: 'file', status: 'verified' },
    { id: 'email', label: 'Egress Email Relay', sublabel: 'Domain Allowlist', x: -140, y: 110, z: -50, color: '#F472B6', icon: 'mail', status: 'verified' },
    { id: 'tavily', label: 'Web Research Scraper', sublabel: 'Taint Tracked', x: 20, y: -160, z: 70, color: '#34D399', icon: 'globe', status: 'active' },
  ];

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let width = (canvas.width = canvas.parentElement?.clientWidth || 700);
    let height = (canvas.height = canvas.parentElement?.clientHeight || 450);

    const handleResize = () => {
      if (!canvas.parentElement) return;
      width = canvas.width = canvas.parentElement.clientWidth;
      height = canvas.height = canvas.parentElement.clientHeight;
    };
    window.addEventListener('resize', handleResize);

    // Dynamic Packets
    const packets: Packet3D[] = [
      { fromIndex: 1, toIndex: 0, progress: 0.1, speed: 0.008, isAttack: true, label: "UNION SELECT * --" },
      { fromIndex: 5, toIndex: 0, progress: 0.4, speed: 0.006, isAttack: false, label: "Search: API Docs" },
      { fromIndex: 0, toIndex: 2, progress: 0.7, speed: 0.009, isAttack: false, label: "Allowed Query" },
      { fromIndex: 1, toIndex: 0, progress: 0.8, speed: 0.007, isAttack: true, label: "Path ../../credentials" },
    ];

    // Shockwaves
    interface Shockwave {
      radius: number;
      maxRadius: number;
      opacity: number;
      color: string;
    }
    const shockwaves: Shockwave[] = [];

    const triggerShockwave = (color: string) => {
      shockwaves.push({ radius: 10, maxRadius: 180, opacity: 1, color });
      if (shockwaves.length > 5) shockwaves.shift();
    };

    let tick = 0;

    const render = () => {
      tick++;
      ctx.clearRect(0, 0, width, height);

      // Auto-rotation when not dragging
      if (!isDragging.current) {
        rotY.current += 0.003;
      }

      const cx = width / 2;
      const cy = height / 2;
      const fov = 450;

      // Project 3D points
      const project = (x: number, y: number, z: number) => {
        // Rotate around Y
        const cosY = Math.cos(rotY.current);
        const sinY = Math.sin(rotY.current);
        const x1 = x * cosY - z * sinY;
        const z1 = z * cosY + x * sinY;

        // Rotate around X
        const cosX = Math.cos(rotX.current);
        const sinX = Math.sin(rotX.current);
        const y2 = y * cosX - z1 * sinX;
        const z2 = z1 * cosX + y * sinX;

        const distance = 480;
        const scale = fov / (distance + z2);
        return {
          px: cx + x1 * scale,
          py: cy + y2 * scale,
          scale,
          z2,
        };
      };

      // 1. Draw concentric orbital rings around gateway center
      ctx.save();
      for (let r = 0; r < 3; r++) {
        const radius = 90 + r * 50;
        const tilt = tick * 0.004 * (r % 2 === 0 ? 1 : -1);
        ctx.beginPath();
        for (let a = 0; a <= Math.PI * 2; a += 0.2) {
          const rx = Math.cos(a) * radius;
          const rz = Math.sin(a) * radius;
          const ry = Math.sin(a + tilt) * 30;
          const pt = project(rx, ry, rz);
          if (a === 0) ctx.moveTo(pt.px, pt.py);
          else ctx.lineTo(pt.px, pt.py);
        }
        ctx.closePath();
        ctx.strokeStyle = r === 0 ? 'rgba(199, 243, 107, 0.25)' : 'rgba(255, 255, 255, 0.08)';
        ctx.lineWidth = r === 0 ? 1.5 : 1;
        ctx.setLineDash(r === 1 ? [4, 6] : []);
        ctx.stroke();
      }
      ctx.restore();

      // 2. Draw shockwaves from blocked attacks
      for (let i = shockwaves.length - 1; i >= 0; i--) {
        const sw = shockwaves[i];
        sw.radius += 2.5;
        sw.opacity = Math.max(0, 1 - sw.radius / sw.maxRadius);

        const centerPt = project(0, 0, 0);
        ctx.save();
        ctx.beginPath();
        ctx.arc(centerPt.px, centerPt.py, sw.radius, 0, Math.PI * 2);
        ctx.strokeStyle = sw.color.replace('1)', `${sw.opacity})`);
        ctx.lineWidth = 2;
        ctx.stroke();
        ctx.restore();

        if (sw.radius >= sw.maxRadius) {
          shockwaves.splice(i, 1);
        }
      }

      // 3. Draw connecting conduits between nodes & gateway core
      const corePt = project(nodes[0].x, nodes[0].y, nodes[0].z);

      for (let i = 1; i < nodes.length; i++) {
        const pt = project(nodes[i].x, nodes[i].y, nodes[i].z);

        ctx.save();
        const grad = ctx.createLinearGradient(corePt.px, corePt.py, pt.px, pt.py);
        grad.addColorStop(0, 'rgba(199, 243, 107, 0.4)');
        grad.addColorStop(1, 'rgba(255, 255, 255, 0.08)');

        ctx.beginPath();
        ctx.moveTo(corePt.px, corePt.py);
        ctx.lineTo(pt.px, pt.py);
        ctx.strokeStyle = grad;
        ctx.lineWidth = 1.2;
        ctx.stroke();
        ctx.restore();
      }

      // 4. Update and draw in-flight packets
      packets.forEach((p) => {
        p.progress += p.speed;
        if (p.progress >= 1) {
          p.progress = 0;
          if (p.isAttack) {
            triggerShockwave('rgba(239, 68, 68, 1)');
          } else {
            triggerShockwave('rgba(199, 243, 107, 1)');
          }
        }

        const from = nodes[p.fromIndex];
        const to = nodes[p.toIndex];

        // Linear interpolation with slight arc
        const currX = from.x + (to.x - from.x) * p.progress;
        const currY = from.y + (to.y - from.y) * p.progress + Math.sin(p.progress * Math.PI) * -15;
        const currZ = from.z + (to.z - from.z) * p.progress;

        const packetPt = project(currX, currY, currZ);

        ctx.save();
        ctx.beginPath();
        ctx.arc(packetPt.px, packetPt.py, Math.max(3, 4.5 * packetPt.scale), 0, Math.PI * 2);
        ctx.fillStyle = p.isAttack ? '#EF4444' : '#C7F36B';
        ctx.shadowColor = p.isAttack ? '#EF4444' : '#C7F36B';
        ctx.shadowBlur = 12;
        ctx.fill();

        // Draw small floating payload badge
        if (packetPt.scale > 0.8) {
          ctx.font = '10px monospace';
          ctx.fillStyle = p.isAttack ? '#FCA5A5' : '#D9F99D';
          ctx.fillText(p.label, packetPt.px + 8, packetPt.py - 6);
        }
        ctx.restore();
      });

      // 5. Draw 3D Nodes
      nodes.forEach((node, idx) => {
        const pt = project(node.x, node.y, node.z);
        const radius = (idx === 0 ? 28 : 18) * pt.scale;

        ctx.save();

        // Outer glow
        const glowGrad = ctx.createRadialGradient(pt.px, pt.py, 2, pt.px, pt.py, radius * 2);
        glowGrad.addColorStop(0, idx === 0 ? 'rgba(199, 243, 107, 0.3)' : 'rgba(255, 255, 255, 0.15)');
        glowGrad.addColorStop(1, 'transparent');
        ctx.fillStyle = glowGrad;
        ctx.beginPath();
        ctx.arc(pt.px, pt.py, radius * 2, 0, Math.PI * 2);
        ctx.fill();

        // Node circle container
        ctx.beginPath();
        ctx.arc(pt.px, pt.py, radius, 0, Math.PI * 2);
        ctx.fillStyle = idx === 0 ? '#111417' : '#0B0D10';
        ctx.fill();
        ctx.strokeStyle = idx === 0 ? '#C7F36B' : 'rgba(255, 255, 255, 0.25)';
        ctx.lineWidth = idx === 0 ? 2 : 1.2;
        ctx.stroke();

        // Center dot / status
        ctx.beginPath();
        ctx.arc(pt.px, pt.py, radius * 0.4, 0, Math.PI * 2);
        ctx.fillStyle = node.color;
        ctx.fill();

        // Label
        ctx.font = `${Math.round(11 * pt.scale)}px sans-serif`;
        ctx.fillStyle = '#FFFFFF';
        ctx.textAlign = 'center';
        ctx.fillText(node.label, pt.px, pt.py + radius + 14);

        ctx.font = `${Math.round(9 * pt.scale)}px monospace`;
        ctx.fillStyle = '#8E969E';
        ctx.fillText(node.sublabel, pt.px, pt.py + radius + 26);

        ctx.restore();
      });

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('resize', handleResize);
    };
  }, []);

  // Mouse drag handlers for 3D rotation
  const handleMouseDown = (e: React.MouseEvent) => {
    isDragging.current = true;
    lastMousePos.current = { x: e.clientX, y: e.clientY };
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isDragging.current) return;
    const deltaX = e.clientX - lastMousePos.current.x;
    const deltaY = e.clientY - lastMousePos.current.y;

    rotY.current += deltaX * 0.008;
    rotX.current = Math.max(-0.8, Math.min(0.8, rotX.current + deltaY * 0.008));

    lastMousePos.current = { x: e.clientX, y: e.clientY };
  };

  const handleMouseUp = () => {
    isDragging.current = false;
  };

  return (
    <div
      ref={containerRef}
      className="relative w-full h-[420px] sm:h-[480px] rounded-2xl glass-panel border border-white/10 overflow-hidden select-none"
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onMouseLeave={handleMouseUp}
    >
      {/* 3D Canvas */}
      <canvas ref={canvasRef} className="w-full h-full cursor-grab active:cursor-grabbing" />

      {/* Top Left Overlay Badge */}
      <div className="absolute top-4 left-4 z-20 flex flex-col gap-1.5 pointer-events-none">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-black/60 border border-white/15 backdrop-blur-md text-[11px] font-mono text-white/90">
          <span className="w-2 h-2 rounded-full bg-[#C7F36B] animate-pulse"></span>
          <span>Zero-Trust 3D Interceptor Mesh</span>
        </div>
        <span className="text-[10px] text-[#8E969E] font-mono pl-1">
          Drag to orbit scene in 3D space
        </span>
      </div>

      {/* Top Right Live Telemetry */}
      <div className="absolute top-4 right-4 z-20 flex items-center gap-3 pointer-events-none">
        <div className="px-3 py-1.5 rounded-lg bg-black/70 border border-white/10 backdrop-blur-md text-right">
          <div className="text-[10px] font-mono text-[#8E969E]">Gateway Policy</div>
          <div className="text-xs font-mono font-semibold text-[#C7F36B]">Deny-by-Default</div>
        </div>
        <div className="px-3 py-1.5 rounded-lg bg-black/70 border border-white/10 backdrop-blur-md text-right">
          <div className="text-[10px] font-mono text-[#8E969E]">Enforcement</div>
          <div className="text-xs font-mono font-semibold text-white">Pre-Execution Gate</div>
        </div>
      </div>

      {/* Bottom Floating Scenario Switcher */}
      <div className="absolute bottom-4 left-1/2 -translate-x-1/2 z-20 flex items-center liquid-pill rounded-full p-1 gap-1 text-xs">
        <button
          type="button"
          onClick={() => setActiveScenario('attack')}
          className={`px-3 py-1.5 rounded-full font-medium transition cursor-pointer flex items-center gap-1.5 ${
            activeScenario === 'attack'
              ? 'bg-red-500/20 text-red-300 border border-red-500/30'
              : 'text-[#929CA3] hover:text-white'
          }`}
        >
          <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
          <span>Active Attack Defense</span>
        </button>
        <button
          type="button"
          onClick={() => setActiveScenario('normal')}
          className={`px-3 py-1.5 rounded-full font-medium transition cursor-pointer flex items-center gap-1.5 ${
            activeScenario === 'normal'
              ? 'bg-[#C7F36B]/20 text-[#C7F36B] border border-[#C7F36B]/30'
              : 'text-[#929CA3] hover:text-white'
          }`}
        >
          <Shield className="w-3.5 h-3.5 text-[#C7F36B]" />
          <span>Verified Invariant Traffic</span>
        </button>
      </div>
    </div>
  );
};
