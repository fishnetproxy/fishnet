import { NavLink, useNavigate } from "react-router-dom";
import { useCallback } from "react";
import { cn } from "@/lib/cn";
import { useAuth } from "@/hooks/use-auth";
import { ROUTES } from "@/lib/constants";
import {
  LayoutDashboard,
  Key,
  Sliders,
  FileText,
  BarChart3,
  AlertTriangle,
  Settings,
  ChevronLeft,
  ChevronRight,
  LogOut,
  Shield,
} from "lucide-react";
interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
  proxyStatus?: "running" | "stopped" | "error";
  version?: string;
  alertCount?: number;
}

interface NavItemData {
  to?: string;
  label: string;
  icon: React.ReactNode;
  disabled?: boolean;
  badge?: number;
}

const mainNavItems: NavItemData[] = [
  { to: ROUTES.HOME, label: "Dashboard", icon: <LayoutDashboard size={18} /> },
  { to: ROUTES.CREDENTIALS, label: "Credentials", icon: <Key size={18} /> },
  { label: "Policies", icon: <Sliders size={18} />, disabled: true },
  { label: "Audit Log", icon: <FileText size={18} />, disabled: true },
  { to: ROUTES.SPEND, label: "Spend", icon: <BarChart3 size={18} /> },
  { to: ROUTES.ONCHAIN, label: "Onchain", icon: <Shield size={18} /> },
];

function getSecondaryNavItems(alertCount: number): NavItemData[] {
  return [
    {
      to: ROUTES.ALERTS,
      label: "Alerts",
      icon: <AlertTriangle size={18} />,
      badge: alertCount,
    },
    { to: ROUTES.SETTINGS, label: "Settings", icon: <Settings size={18} /> },
  ];
}

export function Sidebar({
  collapsed,
  onToggle,
  proxyStatus = "running",
  version = "0.1.0",
  alertCount = 0,
}: SidebarProps) {
  const secondaryNavItems = getSecondaryNavItems(alertCount);
  const { logout } = useAuth();
  const navigate = useNavigate();

  const handleSignOut = useCallback(async () => {
    await logout();
    navigate(ROUTES.LOGIN);
  }, [logout, navigate]);

  return (
    <aside
      className={cn(
        "flex h-screen flex-col border-r border-sidebar-border bg-sidebar transition-all duration-300 ease-[cubic-bezier(0.33,1,0.68,1)]",
        collapsed ? "w-[72px]" : "w-[260px]",
      )}
    >
      {/* ── Logo area ────────────────────────────── */}
      <div className="flex h-16 items-center border-b border-sidebar-border-subtle px-4">
        <div className="flex items-center gap-2.5 overflow-hidden">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-brand">
            <Shield size={16} className="text-white" />
          </div>
          {!collapsed && (
            <span className="text-[15px] font-bold tracking-tight text-sidebar-logo">
              Fishnet
            </span>
          )}
        </div>
      </div>

      {/* ── Navigation ───────────────────────────── */}
      <nav className="flex-1 overflow-y-auto px-3 py-4">
        <ul className="space-y-1">
          {mainNavItems.map((item) => (
            <SidebarNavItem key={item.label} item={item} collapsed={collapsed} />
          ))}
        </ul>

        {/* Divider */}
        <div className="my-4 border-t border-sidebar-border-subtle" />

        <ul className="space-y-1">
          {secondaryNavItems.map((item) => (
            <SidebarNavItem key={item.label} item={item} collapsed={collapsed} />
          ))}
        </ul>
      </nav>

      {/* ── Bottom section ───────────────────────── */}
      <div className="border-t border-sidebar-border-subtle px-3 py-3 space-y-1.5">
        {/* Status */}
        <div
          className={cn(
            "flex items-center gap-2.5 rounded-lg px-3 py-2",
            collapsed && "justify-center px-0",
          )}
        >
          <span
            className={cn(
              "h-2 w-2 shrink-0 rounded-full",
              proxyStatus === "running"
                ? "bg-success status-pulse"
                : proxyStatus === "error"
                  ? "bg-danger"
                  : "bg-text-tertiary",
            )}
          />
          {!collapsed && (
            <span className="text-xs text-text-tertiary leading-tight">
              <span className="capitalize font-medium">{proxyStatus}</span>
              <br />
              <span className="font-mono text-[11px] opacity-70">v{version}</span>
            </span>
          )}
        </div>

        {/* Collapse toggle */}
        <button
          onClick={onToggle}
          className={cn(
            "flex w-full items-center gap-2 rounded-lg px-3 py-2 text-xs text-sidebar-text",
            "transition-all duration-150 hover:bg-sidebar-hover hover:text-sidebar-logo",
            collapsed && "justify-center px-2",
          )}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? (
            <ChevronRight size={16} className="transition-transform duration-200" />
          ) : (
            <>
              <ChevronLeft size={16} className="transition-transform duration-200" />
              <span>Collapse</span>
            </>
          )}
        </button>

        {/* Sign out */}
        <button
          onClick={handleSignOut}
          className={cn(
            "flex w-full items-center gap-2 rounded-lg px-3 py-2 text-xs text-text-tertiary",
            "transition-all duration-150 hover:bg-danger-dim hover:text-danger",
            collapsed && "justify-center px-2",
          )}
        >
          <LogOut size={16} />
          {!collapsed && <span>Sign Out</span>}
        </button>
      </div>
    </aside>
  );
}

/* ── Individual nav item ─────────────────────────── */

function SidebarNavItem({
  item,
  collapsed,
}: {
  item: NavItemData;
  collapsed: boolean;
}) {
  // Disabled items render as a plain div instead of a NavLink
  if (item.disabled) {
    return (
      <li>
        <div
          className={cn(
            "group relative flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm",
            "cursor-default opacity-40",
            collapsed && "justify-center px-2",
          )}
          title={collapsed ? `${item.label} — Coming soon` : "Coming soon"}
        >
          <span className="shrink-0">{item.icon}</span>
          {!collapsed && <span>{item.label}</span>}
          {!collapsed && (
            <span className="ml-auto text-[10px] font-medium uppercase tracking-wider text-text-tertiary">
              Soon
            </span>
          )}
        </div>
      </li>
    );
  }

  return (
    <li>
      <NavLink
        to={item.to!}
        end={item.to === "/"}
        className={({ isActive }) =>
          cn(
            "group relative flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm",
            "transition-all duration-150",
            collapsed && "justify-center px-2",
            isActive
              ? "bg-brand-muted text-brand font-medium"
              : "text-sidebar-text hover:bg-sidebar-hover hover:text-sidebar-logo",
          )
        }
        title={collapsed ? item.label : undefined}
      >
        {/* Active left bar indicator with slide animation */}
        <NavActiveBar />

        <span className="shrink-0 transition-transform duration-150 group-hover:scale-105">
          {item.icon}
        </span>
        {!collapsed && <span>{item.label}</span>}

        {/* Alert count badge */}
        {item.badge != null && item.badge > 0 && (
          <span
            className={cn(
              "flex h-[18px] min-w-[18px] items-center justify-center rounded-full bg-danger px-1 text-[10px] font-bold leading-none text-white",
              collapsed ? "absolute -right-0.5 -top-0.5" : "ml-auto",
            )}
          >
            {item.badge > 99 ? "99+" : item.badge}
          </span>
        )}
      </NavLink>
    </li>
  );
}

/** Active bar that only renders inside NavLink when active */
function NavActiveBar() {
  return (
    <span className="absolute left-0 top-1/2 hidden h-5 w-[3px] -translate-y-1/2 rounded-r-full bg-brand nav-active-bar group-[.active]:block" />
  );
}
