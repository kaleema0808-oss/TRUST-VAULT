import React from "react";
import ReactDOM from "react-dom/client";
import "./style.css";

function App() {
  return (
    <main>
      <p className="eyebrow">SNOVASYS FRESHER HIRING CHALLENGE 2026</p>
      <h1>TrustVault</h1>
      <p className="intro">Private document sharing, built around explicit access control.</p>
      <p className="status">Milestone 2: secure application foundations are in progress.</p>
    </main>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
