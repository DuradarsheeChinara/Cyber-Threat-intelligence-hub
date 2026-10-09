import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { API_BASE, saveSession } from "../services/api";
import {
  Eye,
  EyeOff,
  LockKeyhole,
  Mail,
  ShieldCheck,
  UserPlus,
} from "lucide-react";

export default function Register() {
  const navigate = useNavigate();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError("");

    if (
      !username.trim() ||
      !password.trim() ||
      !confirmPassword.trim()
    ) {
      setError("Please fill in all fields.");
      return;
    }

    if (password.length < 8) {
      setError("Password must be at least 8 characters long.");
      return;
    }

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setSubmitting(true);
    try {
      const response = await fetch(`${API_BASE}/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim(), password }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail ?? "Unable to create account.");
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

      {/* Register card */}
      <main className="auth-card auth-card-register">
        <div className="auth-card-glow" />

        <div className="auth-card-content">
          <div className="auth-heading">
            <div className="auth-heading-icon">
              <UserPlus size={22} />
            </div>

            <h1>Create Account</h1>

            <p>
              Create a local analyst account to access CTI Hub.
            </p>
          </div>

          <form className="auth-form" onSubmit={handleSubmit}>
            <div className="auth-field">
              <label htmlFor="register-username">Username</label>

              <div className="auth-input-wrapper">
                <Mail className="auth-input-icon" size={18} />

                <input
                  id="register-username"
                  type="text"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  placeholder="Choose a username"
                  autoComplete="username"
                />
              </div>
            </div>

            <div className="auth-field">
              <label htmlFor="register-password">Password</label>

              <div className="auth-input-wrapper">
                <LockKeyhole className="auth-input-icon" size={18} />

                <input
                  id="register-password"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  placeholder="Create a password"
                  autoComplete="new-password"
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

            <div className="auth-field">
              <label htmlFor="register-confirm-password">
                Confirm Password
              </label>

              <div className="auth-input-wrapper">
                <LockKeyhole className="auth-input-icon" size={18} />

                <input
                  id="register-confirm-password"
                  type={showConfirmPassword ? "text" : "password"}
                  value={confirmPassword}
                  onChange={(event) =>
                    setConfirmPassword(event.target.value)
                  }
                  placeholder="Confirm your password"
                  autoComplete="new-password"
                />

                <button
                  type="button"
                  className="auth-password-toggle"
                  onClick={() =>
                    setShowConfirmPassword((current) => !current)
                  }
                  aria-label={
                    showConfirmPassword
                      ? "Hide password"
                      : "Show password"
                  }
                >
                  {showConfirmPassword ? (
                    <EyeOff size={18} />
                  ) : (
                    <Eye size={18} />
                  )}
                </button>
              </div>
            </div>

            {error && <div className="auth-error">{error}</div>}

            <button type="submit" className="auth-submit" disabled={submitting}>
              <UserPlus size={18} />
              <span>{submitting ? "Creating Account…" : "Create Account"}</span>
            </button>
          </form>

          <div className="auth-divider">
            <span>SECURE REGISTRATION</span>
          </div>

          <div className="auth-switch">
            <span>Already have an account?</span>
            <Link to="/login">Sign In</Link>
          </div>

          <div className="auth-security-note">
            <ShieldCheck size={15} />
            <span>Your account is protected by CTI Hub</span>
          </div>
        </div>
      </main>

      <div className="auth-footer">
        CTI Hub · Cyber Threat Intelligence Platform
      </div>
    </div>
  );
}
