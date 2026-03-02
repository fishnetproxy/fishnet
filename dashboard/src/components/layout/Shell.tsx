import { useState, useCallback, useEffect } from "react";
import { Outlet, useLocation } from "react-router-dom";
import { Sidebar } from "./Sidebar";
import { AlertsProvider, useAlertsContext } from "@/context/alerts-context";
import { ToastProvider } from "@/context/toast-context";
import { CommandPalette } from "@/components/CommandPalette";
import { useMediaQuery } from "@/hooks/use-media-query";
import { ROUTES } from "@/lib/constants";

const routeTitles: Record<string, string> = {
  [ROUTES.HOME]: "Dashboard",
  [ROUTES.SETTINGS]: "Settings",
  [ROUTES.ALERTS]: "Alerts",
  [ROUTES.SPEND]: "Spend Analytics",
  [ROUTES.ONCHAIN]: "Onchain Permits",
};

const routeSubtitles: Record<string, string> = {
  [ROUTES.HOME]: "Overview and control center for your Fishnet instance",
  [ROUTES.SETTINGS]: "User preferences and integrations",
  [ROUTES.ALERTS]: "Monitor and manage security and budget alerts",
  [ROUTES.SPEND]: "Budget tracking and daily spend breakdown",
  [ROUTES.ONCHAIN]: "Contract whitelist, permit history, and signer status",
};

export function Shell() {
  return (
    <AlertsProvider>
      <ToastProvider>
        <ShellInner />
      </ToastProvider>
    </AlertsProvider>
  );
}

function ShellInner() {
  const isMobile = useMediaQuery("(max-width: 768px)");

  const [collapsed, setCollapsed] = useState(() => {
    if (typeof window === "undefined") return false;
    return localStorage.getItem("sidebar-collapsed") === "true";
  });

  // Auto-collapse on small viewports
  useEffect(() => {
    if (isMobile) setCollapsed(true);
  }, [isMobile]);

  const location = useLocation();
  const title = routeTitles[location.pathname] ?? "Fishnet";
  const subtitle = routeSubtitles[location.pathname];

  const { undismissed } = useAlertsContext();

  const handleToggle = useCallback(() => {
    setCollapsed((prev) => {
      const next = !prev;
      localStorage.setItem("sidebar-collapsed", String(next));
      return next;
    });
  }, []);

  return (
    <div className="flex h-screen overflow-hidden bg-bg">
      <Sidebar
        collapsed={collapsed}
        onToggle={handleToggle}
        alertCount={undismissed.length}
      />
      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Header row */}
        <header className="shrink-0 px-10 pt-10 pb-2">
          <div className="mx-auto max-w-6xl">
            <h1 className="text-2xl font-bold tracking-tight text-text">
              {title}
            </h1>
            {subtitle && (
              <p className="mt-1 text-sm text-text-secondary">{subtitle}</p>
            )}
          </div>
        </header>

        {/* Main content with page enter animation */}
        <main
          key={location.pathname}
          className="page-enter flex-1 overflow-y-auto px-10 py-6"
        >
          <div className="mx-auto max-w-6xl">
            <Outlet />
          </div>
        </main>
      </div>

      {/* Command palette (Cmd+K) */}
      <CommandPalette />
    </div>
  );
}
