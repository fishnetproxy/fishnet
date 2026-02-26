import { useState } from "react";
import { Key, Plus } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { useCredentials } from "@/hooks/use-credentials";
import { CredentialRow } from "./CredentialRow";
import { AddCredentialModal } from "./AddCredentialModal";

export default function CredentialsPage() {
  const { credentials, loading, add, remove } = useCredentials();
  const [showAddModal, setShowAddModal] = useState(false);

  return (
    <div className="space-y-6">
      {/* Toolbar */}
      <div className="flex items-center justify-between">
        <p className="text-sm text-text-secondary">
          {loading
            ? "Loading..."
            : `${credentials.length} credential${credentials.length !== 1 ? "s" : ""}`}
        </p>
        <button
          onClick={() => setShowAddModal(true)}
          className="flex items-center gap-1.5 rounded-lg bg-brand px-3 py-1.5 text-sm font-medium text-white transition-all duration-150 hover:bg-brand-hover"
        >
          <Plus size={14} />
          Add Credential
        </button>
      </div>

      {/* Content */}
      {loading ? (
        <SkeletonCard />
      ) : credentials.length === 0 ? (
        <EmptyState
          icon={<Key size={24} className="text-text-tertiary" />}
          title="No credentials stored"
          subtitle="Add your first API key to get started."
        />
      ) : (
        <Card padding={false} hover={false}>
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-border-subtle">
                <th className="py-2.5 pl-5 pr-3 text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">
                  Service
                </th>
                <th className="py-2.5 pr-3 text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">
                  Name
                </th>
                <th className="py-2.5 pr-3 text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">
                  Created
                </th>
                <th className="py-2.5 pr-3 text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">
                  Last Used
                </th>
                <th className="py-2.5 pr-5 text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {credentials.map((cred) => (
                <CredentialRow
                  key={cred.id}
                  credential={cred}
                  onRemove={remove}
                />
              ))}
            </tbody>
          </table>
        </Card>
      )}

      {/* Add modal */}
      <AddCredentialModal
        open={showAddModal}
        onClose={() => setShowAddModal(false)}
        onSubmit={add}
      />
    </div>
  );
}
