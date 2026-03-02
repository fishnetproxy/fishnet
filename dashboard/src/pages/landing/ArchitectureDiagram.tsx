import { cn } from "@/lib/cn";

function Box({
  label,
  sub,
  color = "border-border",
  glow,
}: {
  label: string;
  sub?: string;
  color?: string;
  glow?: string;
}) {
  return (
    <div
      className={cn(
        "rounded-lg border px-4 py-3 text-center",
        color,
        glow,
      )}
    >
      <p className="text-sm font-semibold text-[#F5F5F7]">{label}</p>
      {sub && <p className="mt-0.5 text-[11px] text-[#71717A]">{sub}</p>}
    </div>
  );
}

export function ArchitectureDiagram() {
  return (
    <div className="flex flex-col items-center gap-3">
      {/* Agent */}
      <Box
        label="AI Agent"
        sub="OpenClaw / LangChain / Custom"
        color="border-[#3B82F6]/40"
        glow="shadow-[0_0_12px_rgba(59,130,246,0.1)]"
      />

      <Arrow />

      {/* Fishnet */}
      <div className="relative w-full max-w-sm rounded-xl border border-[#E63946]/30 bg-[#E63946]/5 px-6 py-5 text-center shadow-[0_0_20px_rgba(230,57,70,0.08)]">
        <p className="text-base font-bold text-[#E63946]">Fishnet Proxy</p>
        <p className="mt-1 text-[11px] text-[#71717A]">
          Credential Vault &middot; Policy Engine &middot; Audit Log
        </p>
      </div>

      <Arrow />

      {/* Services */}
      <div className="grid w-full max-w-sm grid-cols-3 gap-2">
        <Box
          label="APIs"
          sub="OpenAI, Anthropic"
          color="border-[#22C55E]/30"
        />
        <Box
          label="Exchanges"
          sub="Binance, Coinbase"
          color="border-[#F59E0B]/30"
        />
        <Box
          label="Contracts"
          sub="EVM chains"
          color="border-[#8B5CF6]/30"
        />
      </div>
    </div>
  );
}

function Arrow() {
  return (
    <div className="flex h-6 items-center justify-center">
      <div className="h-6 w-px bg-[#2A2A2E]" />
      <div className="absolute h-0 w-0 translate-y-2 border-l-[5px] border-r-[5px] border-t-[6px] border-l-transparent border-r-transparent border-t-[#2A2A2E]" />
    </div>
  );
}
