import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
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

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError("");

    if (!email.trim() || !password.trim()) {
      setError("Please enter your email and password.");
      return;
    }

    if (!email.includes("@")) {
      setError("Please enter a valid email address.");
      return;
    }

    // Frontend-only authentication for now.
    // Backend authentication can be connected later.
    navigate("/dashboard");
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
              <label htmlFor="login-email">Email Address</label>

              <div className="auth-input-wrapper">
                <Mail className="auth-input-icon" size={18} />

                <input
                  id="login-email"
                  type="email"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  placeholder="Enter your email"
                  autoComplete="email"
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

            <button type="submit" className="auth-submit">
              <LogIn size={18} />
              <span>Sign In</span>
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