import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Eye,
  EyeOff,
  LockKeyhole,
  Mail,
  ShieldCheck,
  UserPlus,
  UserRound,
} from "lucide-react";

export default function Register() {
  const navigate = useNavigate();

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const [error, setError] = useState("");

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError("");

    if (
      !name.trim() ||
      !email.trim() ||
      !password.trim() ||
      !confirmPassword.trim()
    ) {
      setError("Please fill in all fields.");
      return;
    }

    if (!email.includes("@")) {
      setError("Please enter a valid email address.");
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

    // Frontend-only registration for now.
    // Backend registration can be connected later.
    navigate("/login");
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
              Join CTI Hub and start monitoring cyber threats.
            </p>
          </div>

          <form className="auth-form" onSubmit={handleSubmit}>
            <div className="auth-field">
              <label htmlFor="register-name">Full Name</label>

              <div className="auth-input-wrapper">
                <UserRound className="auth-input-icon" size={18} />

                <input
                  id="register-name"
                  type="text"
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  placeholder="Enter your name"
                  autoComplete="name"
                />
              </div>
            </div>

            <div className="auth-field">
              <label htmlFor="register-email">Email Address</label>

              <div className="auth-input-wrapper">
                <Mail className="auth-input-icon" size={18} />

                <input
                  id="register-email"
                  type="email"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  placeholder="Enter your email"
                  autoComplete="email"
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

            <button type="submit" className="auth-submit">
              <UserPlus size={18} />
              <span>Create Account</span>
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