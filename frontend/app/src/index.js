import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from 'react-router-dom';
import { AuthProvider } from "./contexts/AuthContext";
import { ThemeProvider } from "./contexts/ThemeContext";
import App from "./App";
import "./index.css";

// Suppress the benign ResizeObserver loop warning thrown by Recharts ResponsiveContainer.
// This is a known browser quirk — the notification is always delivered on the next frame.
const _err = window.onerror;
window.onerror = (msg, ...rest) => {
  if (typeof msg === 'string' && msg.includes('ResizeObserver loop')) return true;
  return _err ? _err(msg, ...rest) : false;
};
window.addEventListener('error', (e) => {
  if (e.message && e.message.includes('ResizeObserver loop')) e.stopImmediatePropagation();
}, true);

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(
  <React.StrictMode>
    <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <ThemeProvider>
        <AuthProvider>
          <App />
        </AuthProvider>
      </ThemeProvider>
    </BrowserRouter>
  </React.StrictMode>
);
