import { useState } from "react";
import { NavLink, Outlet, Link } from "react-router-dom";
import {
  Shield,
  BookOpen,
  Puzzle,
  FileCode2,
  ShieldAlert,
  Menu,
  X,
  ArrowLeft,
} from "lucide-react";
import { cn } from "@/lib/cn";
import { ROUTES } from "@/lib/constants";

interface DocNavItem {
  to: string;
  label: string;
  icon: React.ReactNode;
}

const DOC_NAV: DocNavItem[] = [
  {
    to: ROUTES.DOCS_GETTING_STARTED,
    label: "Getting Started",
    icon: <BookOpen size={16} />,
  },
  {
    to: ROUTES.DOCS_OPENCLAW,
    label: "OpenClaw Integration",
    icon: <Puzzle size={16} />,
  },
  {
    to: ROUTES.DOCS_POLICIES,
    label: "Policy Reference",
    icon: <FileCode2 size={16} />,
  },
  {
    to: ROUTES.DOCS_SECURITY,
    label: "Security Model",
    icon: <ShieldAlert size={16} />,
  },
];

export default function DocsLayout() {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="flex min-h-screen bg-[#0A0A0B] text-[#F5F5F7]">
      {/* Sidebar */}
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-40 w-64 border-r border-[#1F1F23] bg-[#111113] transition-transform duration-200 md:static md:translate-x-0",
          mobileOpen ? "translate-x-0" : "-translate-x-full",
        )}
      >
        <div className="flex h-14 items-center justify-between border-b border-[#1F1F23] px-5">
          <Link to={ROUTES.DOCS} className="flex items-center gap-2">
            <Shield size={16} className="text-[#E63946]" />
            <span className="text-sm font-bold">Fishnet Docs</span>
          </Link>
          <button
            onClick={() => setMobileOpen(false)}
            className="md:hidden text-[#71717A]"
          >
            <X size={18} />
          </button>
        </div>

        <nav className="p-4 space-y-1">
          {DOC_NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              onClick={() => setMobileOpen(false)}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition-colors",
                  isActive
                    ? "bg-[#E63946]/10 text-[#E63946] font-medium"
                    : "text-[#A1A1AA] hover:bg-[#222225] hover:text-[#F5F5F7]",
                )
              }
            >
              {item.icon}
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="absolute bottom-0 w-full border-t border-[#1F1F23] p-4">
          <Link
            to={ROUTES.HOME}
            className="flex items-center gap-2 text-xs text-[#71717A] transition-colors hover:text-[#F5F5F7]"
          >
            <ArrowLeft size={12} />
            Back to Dashboard
          </Link>
        </div>
      </aside>

      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/60 md:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Main content */}
      <div className="flex-1">
        {/* Mobile header */}
        <div className="flex h-14 items-center border-b border-[#1F1F23] px-6 md:hidden">
          <button
            onClick={() => setMobileOpen(true)}
            className="text-[#A1A1AA]"
          >
            <Menu size={20} />
          </button>
          <span className="ml-3 text-sm font-bold">Fishnet Docs</span>
        </div>

        <main className="mx-auto max-w-3xl px-6 py-10 md:px-12">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
