import { useState } from "react";
import { ArrowLeftRight, Plus } from "lucide-react";
import { EmptyState } from "@/components/ui/EmptyState";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { useExchangeConfig } from "@/hooks/use-exchange-config";
import { ExchangeCard } from "./ExchangeCard";
import { AddExchangeModal } from "./AddExchangeModal";

export default function ExchangeConfigPage() {
  const { exchanges, loading, add, remove, toggleEndpoint, updateLimits } = useExchangeConfig();
  const [showAddModal, setShowAddModal] = useState(false);

  return (
    <div className="space-y-6">
      {/* Toolbar */}
      <div className="flex items-center justify-between">
        <p className="text-sm text-text-secondary">
          {loading
            ? "Loading..."
            : `${exchanges.length} exchange${exchanges.length !== 1 ? "s" : ""} configured`}
        </p>
        <button
          onClick={() => setShowAddModal(true)}
          className="flex items-center gap-1.5 rounded-lg bg-brand px-3 py-1.5 text-sm font-medium text-white transition-all duration-150 hover:bg-brand-hover"
        >
          <Plus size={14} />
          Add Exchange
        </button>
      </div>

      {/* Content */}
      {loading ? (
        <div className="space-y-4">
          <SkeletonCard />
          <SkeletonCard />
        </div>
      ) : exchanges.length === 0 ? (
        <EmptyState
          icon={<ArrowLeftRight size={24} className="text-text-tertiary" />}
          title="No exchanges configured"
          subtitle="Add your first exchange to manage endpoint access and volume limits."
        />
      ) : (
        <div className="space-y-4">
          {exchanges.map((exchange, i) => (
            <div
              key={exchange.id}
              className="animate-fade-in-up"
              style={{ animationDelay: `${i * 60}ms` }}
            >
              <ExchangeCard
                exchange={exchange}
                onToggleEndpoint={toggleEndpoint}
                onUpdateLimits={updateLimits}
                onRemove={remove}
              />
            </div>
          ))}
        </div>
      )}

      <AddExchangeModal
        open={showAddModal}
        onClose={() => setShowAddModal(false)}
        onSubmit={add}
      />
    </div>
  );
}
