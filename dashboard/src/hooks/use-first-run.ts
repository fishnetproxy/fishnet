import { useState, useCallback } from "react";

const WIZARD_KEY = "fishnet_wizard_complete";

export function useFirstRun() {
  const [isFirstRun, setIsFirstRun] = useState(
    () => localStorage.getItem(WIZARD_KEY) !== "true",
  );

  const completeWizard = useCallback(() => {
    localStorage.setItem(WIZARD_KEY, "true");
    setIsFirstRun(false);
  }, []);

  const skipWizard = useCallback(() => {
    localStorage.setItem(WIZARD_KEY, "true");
    setIsFirstRun(false);
  }, []);

  return { isFirstRun, completeWizard, skipWizard };
}
