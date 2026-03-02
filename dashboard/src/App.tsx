import { lazy, Suspense } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { ThemeContext, useThemeProvider } from "@/hooks/use-theme";
import { AuthContext, useAuthProvider } from "@/hooks/use-auth";
import { Shell } from "@/components/layout/Shell";
import { ProtectedRoute } from "@/components/auth/ProtectedRoute";
import { PublicRoute } from "@/components/auth/PublicRoute";
import { ROUTES } from "@/lib/constants";
import { Skeleton } from "@/components/ui/Skeleton";

// Route-based code splitting
const DashboardPage = lazy(() => import("@/pages/dashboard/DashboardPage"));
const SettingsPage = lazy(() => import("@/pages/settings/SettingsPage"));
const AlertsPage = lazy(() => import("@/pages/alerts/AlertsPage"));
const SpendPage = lazy(() => import("@/pages/spend/SpendPage"));
const OnchainPage = lazy(() => import("@/pages/onchain/OnchainPage"));
const LoginPage = lazy(() => import("@/pages/login/LoginPage"));
const LandingPage = lazy(() => import("@/pages/landing/LandingPage"));
const DocsLayout = lazy(() => import("@/pages/docs/DocsLayout"));
const GettingStarted = lazy(() => import("@/pages/docs/GettingStarted"));
const OpenClawGuide = lazy(() => import("@/pages/docs/OpenClawGuide"));
const PolicyReference = lazy(() => import("@/pages/docs/PolicyReference"));
const SecurityModel = lazy(() => import("@/pages/docs/SecurityModel"));

function PageLoader() {
  return (
    <div className="space-y-4">
      <Skeleton className="h-8 w-48" />
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
        <Skeleton className="h-32" />
        <Skeleton className="h-32" />
        <Skeleton className="h-32" />
      </div>
    </div>
  );
}

export default function App() {
  const themeValue = useThemeProvider();
  const authValue = useAuthProvider();

  return (
    <AuthContext value={authValue}>
      <ThemeContext value={themeValue}>
        <BrowserRouter>
          <Routes>
            {/* Public: Landing page */}
            <Route
              path={ROUTES.WELCOME}
              element={
                <Suspense
                  fallback={
                    <div
                      className="h-screen"
                      style={{ background: "#08080A" }}
                    />
                  }
                >
                  <LandingPage />
                </Suspense>
              }
            />

            {/* Public: Login page */}
            <Route
              path={ROUTES.LOGIN}
              element={
                <PublicRoute>
                  <Suspense
                    fallback={
                      <div
                        className="h-screen"
                        style={{ background: "#FAFAFA" }}
                      />
                    }
                  >
                    <LoginPage />
                  </Suspense>
                </PublicRoute>
              }
            />

            {/* Public: Docs site */}
            <Route
              path="/docs"
              element={
                <Suspense
                  fallback={
                    <div
                      className="h-screen"
                      style={{ background: "#0A0A0B" }}
                    />
                  }
                >
                  <DocsLayout />
                </Suspense>
              }
            >
              <Route
                index
                element={
                  <Suspense fallback={<PageLoader />}>
                    <GettingStarted />
                  </Suspense>
                }
              />
              <Route
                path="getting-started"
                element={
                  <Suspense fallback={<PageLoader />}>
                    <GettingStarted />
                  </Suspense>
                }
              />
              <Route
                path="openclaw"
                element={
                  <Suspense fallback={<PageLoader />}>
                    <OpenClawGuide />
                  </Suspense>
                }
              />
              <Route
                path="policies"
                element={
                  <Suspense fallback={<PageLoader />}>
                    <PolicyReference />
                  </Suspense>
                }
              />
              <Route
                path="security"
                element={
                  <Suspense fallback={<PageLoader />}>
                    <SecurityModel />
                  </Suspense>
                }
              />
            </Route>

            {/* Protected: Dashboard shell */}
            <Route
              element={
                <ProtectedRoute>
                  <Shell />
                </ProtectedRoute>
              }
            >
              <Route
                index
                element={
                  <Suspense fallback={<PageLoader />}>
                    <DashboardPage />
                  </Suspense>
                }
              />
              <Route
                path={ROUTES.ALERTS}
                element={
                  <Suspense fallback={<PageLoader />}>
                    <AlertsPage />
                  </Suspense>
                }
              />
              <Route
                path={ROUTES.SPEND}
                element={
                  <Suspense fallback={<PageLoader />}>
                    <SpendPage />
                  </Suspense>
                }
              />
              <Route
                path={ROUTES.ONCHAIN}
                element={
                  <Suspense fallback={<PageLoader />}>
                    <OnchainPage />
                  </Suspense>
                }
              />
              <Route
                path={ROUTES.SETTINGS}
                element={
                  <Suspense fallback={<PageLoader />}>
                    <SettingsPage />
                  </Suspense>
                }
              />
            </Route>

            {/* Catch-all → landing page */}
            <Route
              path="*"
              element={<Navigate to={ROUTES.WELCOME} replace />}
            />
          </Routes>
        </BrowserRouter>
      </ThemeContext>
    </AuthContext>
  );
}
