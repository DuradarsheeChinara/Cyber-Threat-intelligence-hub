import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { API_BASE, saveSession } from "../services/api";
import {
  Eye,
  EyeOff,
  LockKeyhole,
  LogIn,
  Mail,
  ShieldCheck,
} from "lucide-react";

export default function Login() {
  const navigate = useNavigate();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");

  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError("");

    if (!username.trim() || !password.trim()) {
      setError("Please enter your username and password.");
      return;
    }

    setSubmitting(true);
    try {
      const response = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim(), password }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail ?? "Unable to sign in.");
      saveSession(result.access_token, username.trim());
      navigate("/dashboard", { replace: true });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to reach the API.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="auth-page">
      {/* Animated cyber background */}
      <iframe
        className="auth-background"
        src="/planet-background.html"
        title="CTI Hub cyber visualization"
        aria-hidden="true"
      />

      <div className="auth-background-overlay" />

      {/* Branding */}
      <div className="auth-brand">
        <div className="auth-brand-icon">
          <ShieldCheck size={28} strokeWidth={2.2} />
        </div>

        <div>
          <div className="auth-brand-name">CTI Hub</div>
          <div className="auth-brand-tagline">
            Detect · Analyze · Stay Ahead
          </div>
        </div>
      </div>

      {/* Login card */}
      <main className="auth-card">
        <div className="auth-card-glow" />

        <div className="auth-card-content">
          <div className="auth-heading">
            <div className="auth-heading-icon">
              <LogIn size={22} />
            </div>

            <h1>Welcome Back</h1>

            <p>
              Sign in to access your threat intelligence dashboard.
            </p>
          </div>

          <form className="auth-form" onSubmit={handleSubmit}>
            <div className="auth-field">
              <label htmlFor="login-username">Username</label>

              <div className="auth-input-wrapper">
                <Mail className="auth-input-icon" size={18} />

                <input
                  id="login-username"
                  type="text"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  placeholder="Enter your username"
                  autoComplete="username"
                />
              </div>
            </div>

            <div className="auth-field">
              <label htmlFor="login-password">Password</label>

              <div className="auth-input-wrapper">
                <LockKeyhole className="auth-input-icon" size={18} />

                <input
                  id="login-password"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  placeholder="Enter your password"
                  autoComplete="current-password"
                />

                <button
                  type="button"
                  className="auth-password-toggle"
                  onClick={() => setShowPassword((current) => !current)}
                  aria-label={
                    showPassword ? "Hide password" : "Show password"
                  }
                >
                  {showPassword ? (
                    <EyeOff size={18} />
                  ) : (
                    <Eye size={18} />
                  )}
                </button>
              </div>
            </div>

            {error && <div className="auth-error">{error}</div>}

            <button type="submit" className="auth-submit" disabled={submitting}>
              <LogIn size={18} />
              <span>{submitting ? "Signing In…" : "Sign In"}</span>
            </button>
          </form>

          <div className="auth-divider">
            <span>SECURE ACCESS</span>
          </div>

          <div className="auth-switch">
            <span>Don't have an account?</span>
            <Link to="/register">Create Account</Link>
          </div>

          <div className="auth-security-note">
            <ShieldCheck size={15} />
            <span>Protected by CTI Hub threat intelligence</span>
          </div>
        </div>
      </main>

      <div className="auth-footer">
        CTI Hub · Cyber Threat Intelligence Platform
      </div>
    </div>
  );
}
