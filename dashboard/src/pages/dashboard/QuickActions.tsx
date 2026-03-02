import { Link } from "react-router-dom";
import { Plus, SlidersHorizontal, FileText } from "lucide-react";
import { ROUTES } from "@/lib/constants";

interface ActionItem {
  label: string;
  description: string;
  icon: React.ReactNode;
  to: string;
}

const ACTIONS: ActionItem[] = [
  {
    label: "Add Credential",
    description: "Store a new API key in the vault",
    icon: <Plus size={18} />,
    to: ROUTES.SETTINGS,
  },
  {
    label: "Edit Policies",
    description: "Configure spend limits and rate caps",
    icon: <SlidersHorizontal size={18} />,
    to: ROUTES.SETTINGS,
  },
  {
    label: "View Audit Log",
    description: "Review proxied request history",
    icon: <FileText size={18} />,
    to: ROUTES.SPEND,
  },
];

export function QuickActions() {
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
      {ACTIONS.map((action) => (
        <Link
          key={action.label}
          to={action.to}
          className="group rounded-xl border border-border bg-surface p-4 transition-all duration-150 hover:border-[#3a3a3f] hover:-translate-y-0.5"
        >
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-brand-muted text-brand transition-colors group-hover:bg-brand group-hover:text-white">
              {action.icon}
            </div>
            <div className="min-w-0">
              <p className="text-sm font-medium text-text">{action.label}</p>
              <p className="text-xs text-text-tertiary">{action.description}</p>
            </div>
          </div>
        </Link>
      ))}
    </div>
  );
}
