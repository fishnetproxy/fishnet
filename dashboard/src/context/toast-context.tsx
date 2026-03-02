import {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
  useRef,
} from "react";
import { CheckCircle2, XCircle, Info } from "lucide-react";
import { cn } from "@/lib/cn";

type ToastVariant = "success" | "error" | "info";

interface ToastItem {
  id: number;
  message: string;
  variant: ToastVariant;
  exiting: boolean;
}

interface ToastContextValue {
  toast: (message: string, variant?: ToastVariant) => void;
}

const ToastContext = createContext<ToastContextValue>({
  toast: () => {},
});

export function useToast() {
  return useContext(ToastContext);
}

let nextId = 0;

const VARIANT_STYLES: Record<ToastVariant, string> = {
  success: "border-success/30 bg-success-dim text-success",
  error: "border-danger/30 bg-danger-dim text-danger",
  info: "border-brand/30 bg-brand-muted text-brand",
};

const VARIANT_ICONS: Record<ToastVariant, React.ReactNode> = {
  success: <CheckCircle2 size={16} />,
  error: <XCircle size={16} />,
  info: <Info size={16} />,
};

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [current, setCurrent] = useState<ToastItem | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout>>(null);

  const dismiss = useCallback(() => {
    setCurrent((prev) => (prev ? { ...prev, exiting: true } : null));
    setTimeout(() => setCurrent(null), 150);
  }, []);

  const toast = useCallback(
    (message: string, variant: ToastVariant = "success") => {
      if (timerRef.current) clearTimeout(timerRef.current);
      const id = ++nextId;
      setCurrent({ id, message, variant, exiting: false });
      timerRef.current = setTimeout(dismiss, 3000);
    },
    [dismiss],
  );

  useEffect(() => {
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, []);

  return (
    <ToastContext value={{ toast }}>
      {children}
      {current && (
        <div className="fixed bottom-6 left-1/2 z-[60] -translate-x-1/2">
          <div
            className={cn(
              "flex items-center gap-2 rounded-lg border px-4 py-2.5 text-sm font-medium shadow-lg backdrop-blur-sm",
              VARIANT_STYLES[current.variant],
              current.exiting ? "animate-toast-out" : "animate-toast-in",
            )}
          >
            {VARIANT_ICONS[current.variant]}
            <span>{current.message}</span>
          </div>
        </div>
      )}
    </ToastContext>
  );
}
