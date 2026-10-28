import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { App } from "./App";
import { AuthProvider } from "./auth/AuthContext";
import { AppearanceProvider } from "./theme/AppearanceContext";
import "./styles.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <AppearanceProvider>
      <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <AuthProvider>
          <App />
        </AuthProvider>
      </BrowserRouter>
    </AppearanceProvider>
  </StrictMode>,
);
