import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import {
  Search,
  LayoutDashboard,
  BarChart3,
  AlertTriangle,
  Settings,
  Shield,
} from "lucide-react";
import { cn } from "@/lib/cn";
import { ROUTES } from "@/lib/constants";

interface PaletteItem {
  label: string;
  to: string;
  icon: React.ReactNode;
}

const ITEMS: PaletteItem[] = [
  { label: "Dashboard", to: ROUTES.HOME, icon: <LayoutDashboard size={16} /> },
  { label: "Spend Analytics", to: ROUTES.SPEND, icon: <BarChart3 size={16} /> },
  { label: "Onchain Permits", to: ROUTES.ONCHAIN, icon: <Shield size={16} /> },
  { label: "Alerts", to: ROUTES.ALERTS, icon: <AlertTriangle size={16} /> },
  { label: "Settings", to: ROUTES.SETTINGS, icon: <Settings size={16} /> },
];

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  // Global keyboard shortcut
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setOpen((prev) => !prev);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  // Focus input when opened
  useEffect(() => {
    if (open) {
      setQuery("");
      setActiveIndex(0);
      setTimeout(() => inputRef.current?.focus(), 0);
    }
  }, [open]);

  const filtered = useMemo(() => {
    if (!query.trim()) return ITEMS;
    const q = query.toLowerCase();
    return ITEMS.filter((item) => item.label.toLowerCase().includes(q));
  }, [query]);

  const select = useCallback(
    (item: PaletteItem) => {
      setOpen(false);
      navigate(item.to);
    },
    [navigate],
  );

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
      } else if (e.key === "ArrowDown") {
        e.preventDefault();
        setActiveIndex((i) => (i + 1) % filtered.length);
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setActiveIndex((i) => (i - 1 + filtered.length) % filtered.length);
      } else if (e.key === "Enter" && filtered[activeIndex]) {
        select(filtered[activeIndex]);
      }
    },
    [filtered, activeIndex, select],
  );

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[20vh]"
      onClick={() => setOpen(false)}
    >
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />

      {/* Palette */}
      <div
        className="relative w-full max-w-md animate-fade-in-up rounded-xl border border-border bg-surface shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Search input */}
        <div className="flex items-center gap-3 border-b border-border px-4 py-3">
          <Search size={16} className="shrink-0 text-text-tertiary" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setActiveIndex(0);
            }}
            onKeyDown={handleKeyDown}
            placeholder="Search pages..."
            className="w-full bg-transparent text-sm text-text placeholder:text-text-tertiary focus:outline-none"
          />
          <kbd className="shrink-0 rounded border border-border px-1.5 py-0.5 font-mono text-[10px] text-text-tertiary">
            ESC
          </kbd>
        </div>

        {/* Results */}
        <div className="max-h-64 overflow-y-auto p-2">
          {filtered.length === 0 ? (
            <p className="px-3 py-4 text-center text-sm text-text-tertiary">
              No results
            </p>
          ) : (
            filtered.map((item, i) => (
              <button
                key={item.to}
                onClick={() => select(item)}
                onMouseEnter={() => setActiveIndex(i)}
                className={cn(
                  "flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition-colors",
                  i === activeIndex
                    ? "bg-brand-muted text-brand"
                    : "text-text-secondary hover:bg-surface-hover",
                )}
              >
                <span className="shrink-0">{item.icon}</span>
                <span>{item.label}</span>
              </button>
            ))
          )}
        </div>

        {/* Footer hint */}
        <div className="border-t border-border px-4 py-2 text-[11px] text-text-tertiary">
          <span className="mr-3">
            <kbd className="rounded border border-border px-1 py-0.5 font-mono">
              ↑↓
            </kbd>{" "}
            navigate
          </span>
          <span>
            <kbd className="rounded border border-border px-1 py-0.5 font-mono">
              ↵
            </kbd>{" "}
            select
          </span>
        </div>
      </div>
    </div>
  );
}
