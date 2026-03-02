import { Check } from "lucide-react";
import { cn } from "@/lib/cn";

interface WizardProgressProps {
  currentStep: number;
  steps: string[];
}

export function WizardProgress({ currentStep, steps }: WizardProgressProps) {
  return (
    <div className="flex items-center justify-center gap-0">
      {steps.map((label, i) => {
        const completed = i < currentStep;
        const active = i === currentStep;

        return (
          <div key={label} className="flex items-center">
            {/* Step circle */}
            <div className="flex flex-col items-center">
              <div
                className={cn(
                  "flex h-8 w-8 items-center justify-center rounded-full text-xs font-bold transition-all duration-200",
                  completed
                    ? "bg-success text-white"
                    : active
                      ? "border-2 border-brand bg-brand-muted text-brand"
                      : "border border-border bg-surface text-text-tertiary",
                )}
              >
                {completed ? <Check size={14} /> : i + 1}
              </div>
              <span
                className={cn(
                  "mt-2 text-[11px] font-medium",
                  completed
                    ? "text-success"
                    : active
                      ? "text-brand"
                      : "text-text-tertiary",
                )}
              >
                {label}
              </span>
            </div>

            {/* Connector line (except after last step) */}
            {i < steps.length - 1 && (
              <div
                className={cn(
                  "mx-2 h-px w-12 transition-colors duration-200 sm:w-16",
                  i < currentStep ? "bg-success" : "bg-border",
                )}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}
