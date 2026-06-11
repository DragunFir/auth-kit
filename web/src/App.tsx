import {
  type FormEvent,
  type ReactNode,
  startTransition,
  useDeferredValue,
  useEffect,
  useState,
} from "react";
import {
  Alert,
  AppBar,
  Avatar,
  Box,
  Button,
  Card,
  CardContent,
  CardHeader,
  Checkbox,
  Chip,
  CircularProgress,
  Container,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  FormControlLabel,
  Grid,
  List,
  ListItemButton,
  ListItemText,
  MenuItem,
  Paper,
  Stack,
  Switch,
  TextField,
  Toolbar,
  Typography,
} from "@mui/material";
import AddCircleOutlineRoundedIcon from "@mui/icons-material/AddCircleOutlineRounded";
import AdminPanelSettingsRoundedIcon from "@mui/icons-material/AdminPanelSettingsRounded";
import LogoutRoundedIcon from "@mui/icons-material/LogoutRounded";
import PersonRoundedIcon from "@mui/icons-material/PersonRounded";
import RefreshRoundedIcon from "@mui/icons-material/RefreshRounded";
import SecurityRoundedIcon from "@mui/icons-material/SecurityRounded";
import {
  Navigate,
  Route,
  Routes,
  useLocation,
  useNavigate,
} from "react-router-dom";

import { ApiError, apiRequest } from "./api";
import type {
  AdminUserDetail,
  MeResponse,
  SetupStatusResponse,
  SessionInfo,
  StatusMessageResponse,
  UserAddress,
  UserContact,
  UserPreferences,
  UserProfile,
  UserPublic,
  UserRole,
  UserSecurity,
} from "./types";

type Notice = {
  severity: "success" | "error" | "info";
  message: string;
};

type AddressDraft = {
  type: string;
  name: string;
  street_line_1: string;
  street_line_2: string;
  postal_code: string;
  city: string;
  state: string;
  country: string;
  is_default: boolean;
};

type AdminFormState = {
  email: string;
  username: string;
  display_name: string;
  roles: UserRole[];
  is_active: boolean;
  is_verified: boolean;
  profile: {
    bio: string;
    locale: string;
    timezone: string;
  };
  contact: {
    phone: string;
    website: string;
    social_links: string;
  };
  preferences: {
    theme: string;
    language: string;
    notification_settings: string;
  };
};

const roleOptions: UserRole[] = ["user", "admin", "owner"];
const passwordRules = [
  "At least 12 characters",
  "At least one lowercase letter",
  "At least one uppercase letter",
  "At least one digit",
  "At least one special character",
  "Must not contain your email address",
  "Must not contain your username",
];

const emptyAddressDraft = (): AddressDraft => ({
  type: "shipping",
  name: "",
  street_line_1: "",
  street_line_2: "",
  postal_code: "",
  city: "",
  state: "",
  country: "",
  is_default: false,
});

const emptyAdminForm = (): AdminFormState => ({
  email: "",
  username: "",
  display_name: "",
  roles: ["user"],
  is_active: true,
  is_verified: true,
  profile: {
    bio: "",
    locale: "",
    timezone: "",
  },
  contact: {
    phone: "",
    website: "",
    social_links: "{}",
  },
  preferences: {
    theme: "",
    language: "",
    notification_settings: "{}",
  },
});

function App() {
  const navigate = useNavigate();
  const location = useLocation();
  const [me, setMe] = useState<MeResponse | null>(null);
  const [setupStatus, setSetupStatus] = useState<SetupStatusResponse | null>(null);
  const [loading, setLoading] = useState(true);

  async function loadCurrentUser(): Promise<MeResponse | null> {
    try {
      return await apiRequest<MeResponse>("/api/auth/me");
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        return null;
      }
      throw error;
    }
  }

  async function refreshMe() {
    const response = await loadCurrentUser();
    setMe(response);
  }

  useEffect(() => {
    let active = true;
    Promise.all([loadCurrentUser(), apiRequest<SetupStatusResponse>("/api/setup/status")])
      .then(([user, setup]) => {
        if (active) {
          setMe(user);
          setSetupStatus(setup);
        }
      })
      .catch(() => {
        if (active) {
          setMe(null);
          setSetupStatus({ needs_setup: false, has_owner: true });
        }
      })
      .finally(() => {
        if (active) {
          setLoading(false);
        }
      });

    return () => {
      active = false;
    };
  }, []);

  async function handleLogout() {
    await apiRequest("/api/auth/logout", { method: "POST" });
    setMe(null);
    navigate(setupStatus?.needs_setup ? "/setup" : "/login");
  }

  const isAdmin = me?.roles.includes("admin") || me?.roles.includes("owner");
  const needsSetup = setupStatus?.needs_setup ?? false;

  if (loading) {
    return (
      <Box minHeight="100vh" display="grid" sx={{ placeItems: "center" }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box minHeight="100vh" pb={6}>
      <AppBar
        position="sticky"
        color="transparent"
        elevation={0}
        sx={{
          borderBottom: "1px solid rgba(15, 118, 110, 0.12)",
          backdropFilter: "blur(16px)",
          backgroundColor: "rgba(245, 239, 228, 0.74)",
        }}
      >
        <Toolbar
          sx={{
            gap: 1.5,
            py: 1.25,
            alignItems: { xs: "stretch", sm: "center" },
            flexWrap: "wrap",
          }}
        >
          <Stack direction="row" spacing={1.5} alignItems="center" sx={{ flexGrow: 1, minWidth: 0 }}>
            <Avatar sx={{ bgcolor: "primary.main", color: "white" }}>
              <SecurityRoundedIcon fontSize="small" />
            </Avatar>
            <Box sx={{ minWidth: 0 }}>
              <Typography variant="h6" sx={{ lineHeight: 1.1 }}>
                auth-kit
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Account, Sessions and Admin
              </Typography>
            </Box>
          </Stack>

          {me ? (
            <Stack
              direction={{ xs: "column", sm: "row" }}
              spacing={1}
              alignItems={{ xs: "stretch", sm: "center" }}
              sx={{ width: { xs: "100%", sm: "auto" } }}
            >
              <Chip
                icon={<PersonRoundedIcon />}
                label={me.display_name || me.username}
                color="primary"
                variant="outlined"
              />
              <Button
                color={location.pathname.startsWith("/account") ? "secondary" : "inherit"}
                variant={location.pathname.startsWith("/account") ? "contained" : "text"}
                onClick={() => navigate("/account")}
                fullWidth
              >
                Account
              </Button>
              {isAdmin ? (
                <Button
                  color={location.pathname.startsWith("/admin") ? "secondary" : "inherit"}
                  variant={location.pathname.startsWith("/admin") ? "contained" : "text"}
                  startIcon={<AdminPanelSettingsRoundedIcon />}
                  onClick={() => navigate("/admin/users")}
                  fullWidth
                >
                  Admin
                </Button>
              ) : null}
              <Button
                variant="text"
                color="inherit"
                startIcon={<LogoutRoundedIcon />}
                onClick={() => void handleLogout()}
                fullWidth
              >
                Logout
              </Button>
            </Stack>
          ) : (
            <Stack
              direction={{ xs: "column", sm: "row" }}
              spacing={1}
              sx={{ width: { xs: "100%", sm: "auto" } }}
            >
              {needsSetup ? (
                <Button
                  variant={location.pathname === "/setup" ? "contained" : "text"}
                  color="secondary"
                  onClick={() => navigate("/setup")}
                  fullWidth
                >
                  First Owner Setup
                </Button>
              ) : (
                <>
                  <Button
                    variant={location.pathname === "/login" ? "contained" : "text"}
                    onClick={() => navigate("/login")}
                    fullWidth
                  >
                    Login
                  </Button>
                  <Button
                    variant={location.pathname === "/register" ? "contained" : "text"}
                    color="secondary"
                    onClick={() => navigate("/register")}
                    fullWidth
                  >
                    Register
                  </Button>
                </>
              )}
            </Stack>
          )}
        </Toolbar>
      </AppBar>

      <Container maxWidth="xl" className="app-shell" sx={{ pt: { xs: 3, md: 5 }, pb: { xs: 3, md: 5 } }}>
        <Routes>
          <Route path="/" element={<Navigate to={me ? "/account" : needsSetup ? "/setup" : "/login"} replace />} />
          <Route
            path="/setup"
            element={
              me ? (
                <Navigate to="/account" replace />
              ) : needsSetup ? (
                <SetupOwnerPage
                  onOwnerCreated={(user) => {
                    setMe(user);
                    setSetupStatus({ needs_setup: false, has_owner: true });
                  }}
                />
              ) : (
                <Navigate to="/login" replace />
              )
            }
          />
          <Route
            path="/login"
            element={me ? <Navigate to="/account" replace /> : needsSetup ? <Navigate to="/setup" replace /> : <LoginPage onLogin={setMe} />}
          />
          <Route
            path="/forgot-password"
            element={me ? <Navigate to="/account" replace /> : needsSetup ? <Navigate to="/setup" replace /> : <ForgotPasswordPage />}
          />
          <Route
            path="/reset-password"
            element={me ? <Navigate to="/account" replace /> : needsSetup ? <Navigate to="/setup" replace /> : <ResetPasswordPage />}
          />
          <Route
            path="/register"
            element={me ? <Navigate to="/account" replace /> : needsSetup ? <Navigate to="/setup" replace /> : <RegisterPage onRegister={setMe} />}
          />
          <Route
            path="/account"
            element={
              <RequireUser me={me} needsSetup={needsSetup}>
                <AccountPage me={me!} onRefreshMe={refreshMe} />
              </RequireUser>
            }
          />
          <Route
            path="/admin/users"
            element={
              <RequireAdmin me={me} needsSetup={needsSetup}>
                <AdminUsersPage currentUser={me!} />
              </RequireAdmin>
            }
          />
        </Routes>
      </Container>
    </Box>
  );
}

function RequireUser({
  me,
  needsSetup,
  children,
}: {
  me: MeResponse | null;
  needsSetup: boolean;
  children: ReactNode;
}) {
  if (!me) {
    return <Navigate to={needsSetup ? "/setup" : "/login"} replace />;
  }
  return children;
}

function RequireAdmin({
  me,
  needsSetup,
  children,
}: {
  me: MeResponse | null;
  needsSetup: boolean;
  children: ReactNode;
}) {
  if (!me) {
    return <Navigate to={needsSetup ? "/setup" : "/login"} replace />;
  }
  if (!me.roles.includes("admin") && !me.roles.includes("owner")) {
    return <Navigate to="/account" replace />;
  }
  return children;
}

function NoticeBanner({ notice }: { notice: Notice | null }) {
  if (!notice) {
    return null;
  }

  return (
    <Alert
      severity={notice.severity}
      variant="outlined"
      className="page-notice"
      sx={{ alignItems: "flex-start" }}
    >
      <Typography variant="body2" sx={{ fontWeight: 600 }}>
        {notice.message}
      </Typography>
    </Alert>
  );
}

function PageLead({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string;
  title: string;
  description: string;
  actions?: ReactNode;
}) {
  return (
    <Paper
      variant="outlined"
      sx={{
        p: { xs: 2.5, md: 3 },
        overflow: "hidden",
        background:
          "linear-gradient(135deg, rgba(255, 250, 241, 0.94) 0%, rgba(243, 251, 248, 0.86) 100%)",
      }}
    >
      <Stack direction={{ xs: "column", lg: "row" }} spacing={2.5} alignItems={{ lg: "flex-start" }}>
        <Box sx={{ flexGrow: 1, maxWidth: 820 }}>
          <Typography variant="overline" color="secondary.main" sx={{ letterSpacing: "0.18em" }}>
            {eyebrow}
          </Typography>
          <Typography variant="h2" sx={{ mb: 1 }}>
            {title}
          </Typography>
          <Typography color="text.secondary">{description}</Typography>
        </Box>
        {actions ? (
          <Stack direction={{ xs: "column", sm: "row" }} spacing={1.25} sx={{ width: { xs: "100%", lg: "auto" } }}>
            {actions}
          </Stack>
        ) : null}
      </Stack>
    </Paper>
  );
}

function SectionLead({
  eyebrow,
  title,
  description,
}: {
  eyebrow: string;
  title: string;
  description: string;
}) {
  return (
    <Box sx={{ mb: { xs: 0.5, md: 1 } }}>
      <Typography variant="overline" color="secondary.main" sx={{ letterSpacing: "0.16em" }}>
        {eyebrow}
      </Typography>
      <Typography variant="h5" sx={{ mb: 0.5 }}>
        {title}
      </Typography>
      <Typography color="text.secondary">{description}</Typography>
    </Box>
  );
}

function AuthCardShell({
  title,
  eyebrow,
  children,
}: {
  title: string;
  eyebrow: string;
  children: ReactNode;
}) {
  return (
    <Paper
      className="auth-shell page-enter"
      sx={{
        p: { xs: 3, md: 4.25 },
        maxWidth: 580,
        mx: "auto",
        overflow: "hidden",
        background:
          "linear-gradient(155deg, rgba(255, 250, 241, 0.96) 0%, rgba(243, 251, 248, 0.9) 100%)",
      }}
    >
      <Stack spacing={1.25} mb={3.5}>
        <Typography variant="overline" color="secondary.main" sx={{ letterSpacing: "0.18em" }}>
          {eyebrow}
        </Typography>
        <Typography variant="h3">{title}</Typography>
      </Stack>
      <Stack spacing={2.5}>{children}</Stack>
    </Paper>
  );
}

function PasswordRulesPanel() {
  return (
    <Paper
      variant="outlined"
      sx={{ p: 2.25, backgroundColor: "rgba(255, 255, 255, 0.34)" }}
    >
      <Stack spacing={1.5}>
        <Typography variant="subtitle2">Password rules</Typography>
        <Box className="rule-chip-grid">
          {passwordRules.map((rule) => (
            <Chip key={rule} label={rule} variant="outlined" size="small" color="primary" />
          ))}
        </Box>
      </Stack>
    </Paper>
  );
}

function LoginPage({ onLogin }: { onLogin: (value: MeResponse) => void }) {
  const navigate = useNavigate();
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [notice, setNotice] = useState<Notice | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setNotice(null);

    try {
      await apiRequest<UserPublic>("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ identifier, password }),
      });
      const me = await apiRequest<MeResponse>("/api/auth/me");
      onLogin(me);
      navigate("/account");
    } catch (error) {
      setNotice({ severity: "error", message: getErrorMessage(error) });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AuthCardShell title="Sign In" eyebrow="Standalone Identity">
      <>
        <Typography color="text.secondary">
          Log in to manage your account, profile, sessions and administrative user flows.
        </Typography>
        <NoticeBanner notice={notice} />
        <Box component="form" onSubmit={handleSubmit}>
          <Stack spacing={2.25}>
            <TextField
              label="Email or Username"
              value={identifier}
              onChange={(event) => setIdentifier(event.target.value)}
            />
            <TextField
              label="Password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
            <Button type="submit" variant="contained" color="primary" disabled={submitting} fullWidth>
              {submitting ? "Signing in..." : "Login"}
            </Button>
            <Stack direction={{ xs: "column", sm: "row" }} spacing={1.25}>
              <Button variant="text" onClick={() => navigate("/forgot-password")} fullWidth>
                Forgot password
              </Button>
              <Button variant="text" color="secondary" onClick={() => navigate("/register")} fullWidth>
                Create account
              </Button>
            </Stack>
          </Stack>
        </Box>
      </>
    </AuthCardShell>
  );
}

function ForgotPasswordPage() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [notice, setNotice] = useState<Notice | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setNotice(null);

    try {
      await apiRequest<StatusMessageResponse>("/api/auth/forgot-password", {
        method: "POST",
        body: JSON.stringify({ email }),
      });
      setNotice({
        severity: "success",
        message: "Wenn ein Konto existiert, wurde eine Reset-Anleitung verschickt.",
      });
    } catch (error) {
      setNotice({ severity: "error", message: getErrorMessage(error) });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AuthCardShell title="Forgot Password" eyebrow="Recovery Flow">
      <>
        <Typography color="text.secondary">
          Submit your account email to request password reset instructions.
        </Typography>
        <NoticeBanner notice={notice} />
        <Box component="form" onSubmit={handleSubmit}>
          <Stack spacing={2.25}>
            <TextField label="Email" value={email} onChange={(event) => setEmail(event.target.value)} />
            <Button type="submit" variant="contained" color="secondary" disabled={submitting} fullWidth>
              {submitting ? "Sending..." : "Send reset instructions"}
            </Button>
            <Stack direction={{ xs: "column", sm: "row" }} spacing={1.25}>
              <Button variant="text" onClick={() => navigate("/reset-password")} fullWidth>
                I already have a token
              </Button>
              <Button variant="text" onClick={() => navigate("/login")} fullWidth>
                Back to login
              </Button>
            </Stack>
          </Stack>
        </Box>
      </>
    </AuthCardShell>
  );
}

function ResetPasswordPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const [token, setToken] = useState(() => new URLSearchParams(location.search).get("token") ?? "");
  const [newPassword, setNewPassword] = useState("");
  const [notice, setNotice] = useState<Notice | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setNotice(null);

    try {
      const response = await apiRequest<StatusMessageResponse>("/api/auth/reset-password", {
        method: "POST",
        body: JSON.stringify({ token, new_password: newPassword }),
      });
      setNewPassword("");
      setNotice({ severity: "success", message: response.message });
    } catch (error) {
      setNotice({ severity: "error", message: getErrorMessage(error) });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AuthCardShell title="Reset Password" eyebrow="Recovery Flow">
      <>
        <Typography color="text.secondary">
          Open a reset link or paste the token you received to choose a new password.
        </Typography>
        <NoticeBanner notice={notice} />
        <PasswordRulesPanel />
        <Box component="form" onSubmit={handleSubmit}>
          <Stack spacing={2.25}>
            <TextField label="Reset token" value={token} onChange={(event) => setToken(event.target.value)} />
            <TextField
              label="New password"
              type="password"
              value={newPassword}
              onChange={(event) => setNewPassword(event.target.value)}
            />
            <Button type="submit" variant="contained" color="secondary" disabled={submitting} fullWidth>
              {submitting ? "Resetting..." : "Reset password"}
            </Button>
            <Button variant="text" onClick={() => navigate("/login")} fullWidth>
              Back to login
            </Button>
          </Stack>
        </Box>
      </>
    </AuthCardShell>
  );
}

function SetupOwnerPage({ onOwnerCreated }: { onOwnerCreated: (value: MeResponse) => void }) {
  const navigate = useNavigate();
  const [form, setForm] = useState({
    email: "",
    username: "",
    display_name: "",
    password: "",
  });
  const [notice, setNotice] = useState<Notice | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setNotice(null);

    try {
      await apiRequest<UserPublic>("/api/setup/owner", {
        method: "POST",
        body: JSON.stringify(form),
      });
      const me = await apiRequest<MeResponse>("/api/auth/me");
      onOwnerCreated(me);
      navigate("/account");
    } catch (error) {
      setNotice({ severity: "error", message: getErrorMessage(error) });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AuthCardShell title="Create First Owner" eyebrow="Initial Setup">
      <>
        <Typography color="text.secondary">
          No owner account exists yet. Create the first owner to unlock account and admin management.
        </Typography>
        <NoticeBanner notice={notice} />
        <PasswordRulesPanel />
        <Box component="form" onSubmit={handleSubmit}>
          <Stack spacing={2.25}>
            <TextField
              label="Email"
              value={form.email}
              onChange={(event) => setForm({ ...form, email: event.target.value })}
            />
            <TextField
              label="Username"
              value={form.username}
              onChange={(event) => setForm({ ...form, username: event.target.value })}
            />
            <TextField
              label="Display Name"
              value={form.display_name}
              onChange={(event) => setForm({ ...form, display_name: event.target.value })}
            />
            <TextField
              label="Password"
              type="password"
              value={form.password}
              onChange={(event) => setForm({ ...form, password: event.target.value })}
            />
            <Button type="submit" variant="contained" color="secondary" disabled={submitting} fullWidth>
              {submitting ? "Creating owner..." : "Create first owner"}
            </Button>
          </Stack>
        </Box>
      </>
    </AuthCardShell>
  );
}

function RegisterPage({ onRegister }: { onRegister: (value: MeResponse) => void }) {
  const navigate = useNavigate();
  const [form, setForm] = useState({
    email: "",
    username: "",
    display_name: "",
    password: "",
  });
  const [notice, setNotice] = useState<Notice | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setNotice(null);

    try {
      await apiRequest<UserPublic>("/api/auth/register", {
        method: "POST",
        body: JSON.stringify(form),
      });
      const me = await apiRequest<MeResponse>("/api/auth/me");
      onRegister(me);
      navigate("/account");
    } catch (error) {
      setNotice({ severity: "error", message: getErrorMessage(error) });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AuthCardShell title="Create Account" eyebrow="auth-kit 1.0">
      <>
        <Typography color="text.secondary">
          Registration creates the base identity and signs you in immediately.
        </Typography>
        <NoticeBanner notice={notice} />
        <PasswordRulesPanel />
        <Box component="form" onSubmit={handleSubmit}>
          <Stack spacing={2.25}>
            <TextField
              label="Email"
              value={form.email}
              onChange={(event) => setForm({ ...form, email: event.target.value })}
            />
            <TextField
              label="Username"
              value={form.username}
              onChange={(event) => setForm({ ...form, username: event.target.value })}
            />
            <TextField
              label="Display Name"
              value={form.display_name}
              onChange={(event) => setForm({ ...form, display_name: event.target.value })}
            />
            <TextField
              label="Password"
              type="password"
              value={form.password}
              onChange={(event) => setForm({ ...form, password: event.target.value })}
            />
            <Button type="submit" variant="contained" color="secondary" disabled={submitting} fullWidth>
              {submitting ? "Creating..." : "Register"}
            </Button>
            <Button variant="text" onClick={() => navigate("/login")} fullWidth>
              Back to login
            </Button>
          </Stack>
        </Box>
      </>
    </AuthCardShell>
  );
}

function AccountPage({ me, onRefreshMe }: { me: MeResponse; onRefreshMe: () => Promise<void> }) {
  const [profile, setProfile] = useState<UserProfile | null>(me.profile);
  const [addresses, setAddresses] = useState<UserAddress[]>([]);
  const [contact, setContact] = useState<UserContact | null>(null);
  const [preferences, setPreferences] = useState<UserPreferences | null>(me.preferences);
  const [security, setSecurity] = useState<UserSecurity | null>(null);
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [contactSocialLinksText, setContactSocialLinksText] = useState("{}");
  const [preferenceNotificationsText, setPreferenceNotificationsText] = useState("{}");
  const [notice, setNotice] = useState<Notice | null>(null);
  const [loading, setLoading] = useState(true);
  const [avatarFile, setAvatarFile] = useState<File | null>(null);
  const [avatarUploading, setAvatarUploading] = useState(false);
  const [addressDraft, setAddressDraft] = useState<AddressDraft>(emptyAddressDraft());
  const [editingAddressId, setEditingAddressId] = useState<number | null>(null);
  const [passwordForm, setPasswordForm] = useState({
    current_password: "",
    new_password: "",
  });

  async function loadAccountData() {
    setLoading(true);
    try {
      const [
        nextProfile,
        nextAddresses,
        nextContact,
        nextPreferences,
        nextSecurity,
        nextSessions,
      ] = await Promise.all([
        apiRequest<UserProfile>("/api/auth/profile"),
        apiRequest<UserAddress[]>("/api/auth/addresses"),
        apiRequest<UserContact>("/api/auth/contact"),
        apiRequest<UserPreferences>("/api/auth/preferences"),
        apiRequest<UserSecurity>("/api/auth/security"),
        apiRequest<SessionInfo[]>("/api/auth/sessions"),
      ]);
      setProfile(nextProfile);
      setAddresses(nextAddresses);
      setContact(nextContact);
      setPreferences(nextPreferences);
      setSecurity(nextSecurity);
      setSessions(nextSessions);
      setContactSocialLinksText(JSON.stringify(nextContact.social_links, null, 2));
      setPreferenceNotificationsText(JSON.stringify(nextPreferences.notification_settings, null, 2));
    } catch (error) {
      setNotice({ severity: "error", message: getErrorMessage(error) });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    let active = true;
    Promise.all([
      apiRequest<UserProfile>("/api/auth/profile"),
      apiRequest<UserAddress[]>("/api/auth/addresses"),
      apiRequest<UserContact>("/api/auth/contact"),
      apiRequest<UserPreferences>("/api/auth/preferences"),
      apiRequest<UserSecurity>("/api/auth/security"),
      apiRequest<SessionInfo[]>("/api/auth/sessions"),
    ])
      .then(
        ([
          nextProfile,
          nextAddresses,
          nextContact,
          nextPreferences,
          nextSecurity,
          nextSessions,
        ]) => {
          if (!active) {
            return;
          }
          setProfile(nextProfile);
          setAddresses(nextAddresses);
          setContact(nextContact);
          setPreferences(nextPreferences);
          setSecurity(nextSecurity);
          setSessions(nextSessions);
          setContactSocialLinksText(JSON.stringify(nextContact.social_links, null, 2));
          setPreferenceNotificationsText(
            JSON.stringify(nextPreferences.notification_settings, null, 2),
          );
        },
      )
      .catch((error) => {
        if (active) {
          setNotice({ severity: "error", message: getErrorMessage(error) });
        }
      })
      .finally(() => {
        if (active) {
          setLoading(false);
        }
      });

    return () => {
      active = false;
    };
  }, []);

  async function saveProfile() {
    if (!profile) {
      return;
    }
    try {
      const updated = await apiRequest<UserProfile>("/api/auth/profile", {
        method: "PATCH",
        body: JSON.stringify({
          bio: profile.bio,
          locale: profile.locale,
          timezone: profile.timezone,
        }),
      });
      setProfile(updated);
      await onRefreshMe();
      setNotice({ severity: "success", message: "Profile saved." });
    } catch (error) {
      setNotice({ severity: "error", message: getErrorMessage(error) });
    }
  }

  async function uploadAvatar() {
    if (!avatarFile) {
      return;
    }
    setAvatarUploading(true);
    try {
      const formData = new FormData();
      formData.append("avatar", avatarFile);
      const updated = await apiRequest<UserProfile>("/api/auth/profile/avatar", {
        method: "POST",
        body: formData,
      });
      setProfile(updated);
      setAvatarFile(null);
      await onRefreshMe();
      setNotice({ severity: "success", message: "Avatar uploaded." });
    } catch (error) {
      setNotice({ severity: "error", message: getErrorMessage(error) });
    } finally {
      setAvatarUploading(false);
    }
  }

  async function saveContact() {
    if (!contact) {
      return;
    }
    try {
      const socialLinks = parseJsonOrThrow<Record<string, string>>(
        contactSocialLinksText,
        "Social links",
      );
      const updated = await apiRequest<UserContact>("/api/auth/contact", {
        method: "PATCH",
        body: JSON.stringify({
          phone: contact.phone,
          website: contact.website,
          social_links: socialLinks,
        }),
      });
      setContact(updated);
      setContactSocialLinksText(JSON.stringify(updated.social_links, null, 2));
      setNotice({ severity: "success", message: "Contact details saved." });
    } catch (error) {
      setNotice({ severity: "error", message: getErrorMessage(error) });
    }
  }

  async function savePreferences() {
    if (!preferences) {
      return;
    }
    try {
      const notificationSettings = parseJsonOrThrow<Record<string, boolean | string | number>>(
        preferenceNotificationsText,
        "Notification settings",
      );
      const updated = await apiRequest<UserPreferences>("/api/auth/preferences", {
        method: "PATCH",
        body: JSON.stringify({
          theme: preferences.theme,
          language: preferences.language,
          notification_settings: notificationSettings,
        }),
      });
      setPreferences(updated);
      setPreferenceNotificationsText(JSON.stringify(updated.notification_settings, null, 2));
      await onRefreshMe();
      setNotice({ severity: "success", message: "Preferences saved." });
    } catch (error) {
      setNotice({ severity: "error", message: getErrorMessage(error) });
    }
  }

  async function submitAddress() {
    try {
      const payload = {
        ...addressDraft,
        name: addressDraft.name || null,
        street_line_2: addressDraft.street_line_2 || null,
        state: addressDraft.state || null,
      };
      const updatedAddress = editingAddressId
        ? await apiRequest<UserAddress>(`/api/auth/addresses/${editingAddressId}`, {
            method: "PATCH",
            body: JSON.stringify(payload),
          })
        : await apiRequest<UserAddress>("/api/auth/addresses", {
            method: "POST",
            body: JSON.stringify(payload),
          });

      const nextAddresses = editingAddressId
        ? addresses.map((address) => (address.id === editingAddressId ? updatedAddress : address))
        : [...addresses, updatedAddress];

      setAddresses(normalizeDefaultAddresses(nextAddresses));
      setAddressDraft(emptyAddressDraft());
      setEditingAddressId(null);
      setNotice({
        severity: "success",
        message: editingAddressId ? "Address updated." : "Address added.",
      });
    } catch (error) {
      setNotice({ severity: "error", message: getErrorMessage(error) });
    }
  }

  async function deleteAddress(addressId: number) {
    try {
      await apiRequest(`/api/auth/addresses/${addressId}`, { method: "DELETE" });
      setAddresses(addresses.filter((address) => address.id !== addressId));
      if (editingAddressId === addressId) {
        setEditingAddressId(null);
        setAddressDraft(emptyAddressDraft());
      }
      setNotice({ severity: "success", message: "Address removed." });
    } catch (error) {
      setNotice({ severity: "error", message: getErrorMessage(error) });
    }
  }

  async function endSession(sessionId: string, isCurrent: boolean) {
    try {
      const path = isCurrent ? "/api/auth/sessions/current" : `/api/auth/sessions/${sessionId}`;
      await apiRequest(path, { method: "DELETE" });
      setSessions(sessions.filter((session) => session.id !== sessionId));
      setNotice({
        severity: "success",
        message: isCurrent ? "Current session ended." : "Session ended.",
      });
    } catch (error) {
      setNotice({ severity: "error", message: getErrorMessage(error) });
    }
  }

  async function changePassword() {
    try {
      await apiRequest("/api/auth/change-password", {
        method: "POST",
        body: JSON.stringify(passwordForm),
      });
      setPasswordForm({ current_password: "", new_password: "" });
      setNotice({ severity: "success", message: "Password changed." });
    } catch (error) {
      setNotice({ severity: "error", message: getErrorMessage(error) });
    }
  }

  if (loading || !profile || !contact || !preferences || !security) {
    return (
      <Box minHeight="60vh" display="grid" sx={{ placeItems: "center" }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Stack spacing={3.5} className="page-enter">
      <PageLead
        eyebrow="Account"
        title="Identity, profile and session control"
        description="Manage your everyday account data, avatar, password and active sessions from one place."
        actions={
          <Button
            variant="outlined"
            startIcon={<RefreshRoundedIcon />}
            onClick={() => void loadAccountData()}
            fullWidth
          >
            Refresh
          </Button>
        }
      />

      <NoticeBanner notice={notice} />

      <Grid container spacing={{ xs: 2.5, md: 3 }}>
        <Grid size={{ xs: 12 }}>
          <SectionLead
            eyebrow="Account"
            title="Profile and identity"
            description="Core identity data, avatar upload and public profile settings."
          />
        </Grid>
        <Grid size={{ xs: 12, lg: 4 }}>
          <Card>
            <CardHeader title="Identity" subheader="Base data from /api/auth/me" />
            <CardContent>
              <Stack spacing={2}>
                <Stack direction="row" spacing={2} alignItems="center">
                  <Avatar
                    src={profile.avatar_url || undefined}
                    sx={{ width: 64, height: 64, bgcolor: "secondary.main" }}
                  >
                    {(me.display_name || me.username).slice(0, 1).toUpperCase()}
                  </Avatar>
                  <Box>
                    <Typography variant="h5">{me.display_name || me.username}</Typography>
                    <Typography color="text.secondary">{me.email}</Typography>
                  </Box>
                </Stack>
                <Stack direction="row" spacing={1} flexWrap="wrap">
                  {me.roles.map((role) => (
                    <Chip key={role} label={role} color={role === "owner" ? "secondary" : "primary"} />
                  ))}
                </Stack>
                <Typography variant="body2" color="text.secondary">
                  Verified: {me.is_verified ? "yes" : "no"} · Active: {me.is_active ? "yes" : "no"}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Last login: {formatDateTime(me.last_login_at)}
                </Typography>
              </Stack>
            </CardContent>
          </Card>
        </Grid>

        <Grid size={{ xs: 12, lg: 8 }}>
          <Card>
            <CardHeader title="Profile" subheader="Edit display profile and upload an avatar image" />
            <CardContent>
              <Stack spacing={2.25}>
                <Paper
                  variant="outlined"
                  sx={{
                    p: 2,
                    borderStyle: "dashed",
                    backgroundColor: "rgba(255, 255, 255, 0.34)",
                  }}
                >
                  <Stack direction={{ xs: "column", md: "row" }} spacing={2} alignItems={{ md: "center" }}>
                    <Avatar
                      src={profile.avatar_url || undefined}
                      sx={{ width: 72, height: 72, bgcolor: "secondary.main" }}
                    >
                      {(me.display_name || me.username).slice(0, 1).toUpperCase()}
                    </Avatar>
                    <Box sx={{ flexGrow: 1 }}>
                      <Typography variant="subtitle1">Avatar</Typography>
                      <Typography variant="body2" color="text.secondary">
                        {avatarFile
                          ? `Selected file: ${avatarFile.name}`
                          : "PNG, JPEG or WebP. Upload replaces the current avatar preview."}
                      </Typography>
                    </Box>
                    <Stack direction={{ xs: "column", sm: "row" }} spacing={1.25} sx={{ width: { xs: "100%", md: "auto" } }}>
                      <Button component="label" variant="outlined" color="secondary" fullWidth>
                        Choose file
                        <input
                          hidden
                          type="file"
                          accept="image/png,image/jpeg,image/webp"
                          onChange={(event) => setAvatarFile(event.target.files?.[0] ?? null)}
                        />
                      </Button>
                      <Button
                        variant="contained"
                        color="secondary"
                        disabled={!avatarFile || avatarUploading}
                        onClick={() => void uploadAvatar()}
                        fullWidth
                      >
                        {avatarUploading ? "Uploading..." : "Upload avatar"}
                      </Button>
                    </Stack>
                  </Stack>
                </Paper>
                <TextField
                  label="Bio"
                  multiline
                  minRows={3}
                  value={profile.bio ?? ""}
                  onChange={(event) => setProfile({ ...profile, bio: event.target.value || null })}
                />
                <Stack direction={{ xs: "column", sm: "row" }} spacing={2}>
                  <TextField
                    label="Locale"
                    value={profile.locale ?? ""}
                    onChange={(event) =>
                      setProfile({ ...profile, locale: event.target.value || null })
                    }
                  />
                  <TextField
                    label="Timezone"
                    value={profile.timezone ?? ""}
                    onChange={(event) =>
                      setProfile({ ...profile, timezone: event.target.value || null })
                    }
                  />
                </Stack>
                <Button variant="contained" onClick={() => void saveProfile()}>
                  Save profile
                </Button>
              </Stack>
            </CardContent>
          </Card>
        </Grid>

        <Grid size={{ xs: 12 }}>
          <SectionLead
            eyebrow="Account"
            title="Contact and preferences"
            description="Day-to-day profile metadata and presentation settings."
          />
        </Grid>
        <Grid size={{ xs: 12, md: 6 }}>
          <Card>
            <CardHeader title="Contact" subheader="Phone, website and web handles" />
            <CardContent>
              <Stack spacing={2}>
                <TextField
                  label="Phone"
                  value={contact.phone ?? ""}
                  onChange={(event) => setContact({ ...contact, phone: event.target.value || null })}
                />
                <TextField
                  label="Website"
                  value={contact.website ?? ""}
                  onChange={(event) =>
                    setContact({ ...contact, website: event.target.value || null })
                  }
                />
                <TextField
                  label="Social Links JSON"
                  multiline
                  minRows={4}
                  value={contactSocialLinksText}
                  onChange={(event) => setContactSocialLinksText(event.target.value)}
                />
                <Button variant="contained" onClick={() => void saveContact()}>
                  Save contact
                </Button>
              </Stack>
            </CardContent>
          </Card>
        </Grid>

        <Grid size={{ xs: 12, md: 6 }}>
          <Card>
            <CardHeader title="Preferences" subheader="Theme, language and notifications" />
            <CardContent>
              <Stack spacing={2}>
                <TextField
                  label="Theme"
                  value={preferences.theme ?? ""}
                  onChange={(event) =>
                    setPreferences({ ...preferences, theme: event.target.value || null })
                  }
                />
                <TextField
                  label="Language"
                  value={preferences.language ?? ""}
                  onChange={(event) =>
                    setPreferences({ ...preferences, language: event.target.value || null })
                  }
                />
                <TextField
                  label="Notification Settings JSON"
                  multiline
                  minRows={4}
                  value={preferenceNotificationsText}
                  onChange={(event) => setPreferenceNotificationsText(event.target.value)}
                />
                <Button variant="contained" color="secondary" onClick={() => void savePreferences()}>
                  Save preferences
                </Button>
              </Stack>
            </CardContent>
          </Card>
        </Grid>

        <Grid size={{ xs: 12 }}>
          <SectionLead
            eyebrow="Security"
            title="Password and active access"
            description="Update account protection settings and end sessions from trusted devices."
          />
        </Grid>
        <Grid size={{ xs: 12, md: 6 }}>
          <Card>
            <CardHeader title="Security preferences" subheader="Prepared security options" />
            <CardContent>
              <Stack spacing={1.5}>
                <Alert severity="info" variant="outlined">
                  These options are prepared for future releases and are not active security features yet.
                </Alert>
                <FormControlLabel
                  control={
                    <Switch
                      checked={false}
                      disabled
                    />
                  }
                  label="Two-factor authentication planned"
                />
                <FormControlLabel
                  control={
                    <Switch
                      checked={false}
                      disabled
                    />
                  }
                  label="Passkeys planned"
                />
                <FormControlLabel
                  control={
                    <Switch
                      checked={false}
                      disabled
                    />
                  }
                  label="Recovery codes planned"
                />
                <FormControlLabel
                  control={
                    <Switch
                      checked={false}
                      disabled
                    />
                  }
                  label="Trusted devices planned"
                />
              </Stack>
            </CardContent>
          </Card>
        </Grid>

        <Grid size={{ xs: 12, md: 6 }}>
          <Card>
            <CardHeader title="Password" subheader="Rotate the current account password" />
            <CardContent>
              <Stack spacing={2.25}>
                <PasswordRulesPanel />
                <TextField
                  label="Current password"
                  type="password"
                  value={passwordForm.current_password}
                  onChange={(event) =>
                    setPasswordForm({ ...passwordForm, current_password: event.target.value })
                  }
                />
                <TextField
                  label="New password"
                  type="password"
                  value={passwordForm.new_password}
                  onChange={(event) =>
                    setPasswordForm({ ...passwordForm, new_password: event.target.value })
                  }
                />
                <Button variant="contained" color="secondary" onClick={() => void changePassword()}>
                  Change password
                </Button>
              </Stack>
            </CardContent>
          </Card>
        </Grid>

        <Grid size={{ xs: 12 }}>
          <SectionLead
            eyebrow="Address Book"
            title="Addresses"
            description="Manage shipping, billing and default address records."
          />
        </Grid>
        <Grid size={{ xs: 12 }}>
          <Card>
            <CardHeader title="Addresses" subheader="Multiple addresses per user" />
            <CardContent>
              <Grid container spacing={3}>
                <Grid size={{ xs: 12, lg: 7 }}>
                  <Stack spacing={2}>
                    {addresses.length === 0 ? (
                      <Alert severity="info">No addresses yet. Add the first one below.</Alert>
                    ) : (
                      addresses.map((address) => (
                        <Paper key={address.id} sx={{ p: 2.25 }}>
                          <Stack spacing={1.5}>
                            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap">
                              <Chip label={address.type} color="primary" />
                              {address.is_default ? <Chip label="default" color="secondary" /> : null}
                              <Typography variant="h6">{address.name || address.street_line_1}</Typography>
                            </Stack>
                            <Typography color="text.secondary">
                              {address.street_line_1}
                              {address.street_line_2 ? `, ${address.street_line_2}` : ""}
                              {` · ${address.postal_code} ${address.city}`}
                              {address.state ? ` · ${address.state}` : ""}
                              {` · ${address.country}`}
                            </Typography>
                            <Stack direction="row" spacing={1}>
                              <Button
                                variant="outlined"
                                onClick={() => {
                                  setEditingAddressId(address.id);
                                  setAddressDraft({
                                    type: address.type,
                                    name: address.name ?? "",
                                    street_line_1: address.street_line_1,
                                    street_line_2: address.street_line_2 ?? "",
                                    postal_code: address.postal_code,
                                    city: address.city,
                                    state: address.state ?? "",
                                    country: address.country,
                                    is_default: address.is_default,
                                  });
                                }}
                              >
                                Edit
                              </Button>
                              <Button
                                variant="text"
                                color="secondary"
                                onClick={() => void deleteAddress(address.id)}
                              >
                                Delete
                              </Button>
                            </Stack>
                          </Stack>
                        </Paper>
                      ))
                    )}
                  </Stack>
                </Grid>

                <Grid size={{ xs: 12, lg: 5 }}>
                  <Paper sx={{ p: 2.5 }}>
                    <Stack spacing={2}>
                      <Typography variant="h6">
                        {editingAddressId ? "Edit address" : "Add address"}
                      </Typography>
                      <TextField
                        label="Type"
                        select
                        value={addressDraft.type}
                        onChange={(event) =>
                          setAddressDraft({ ...addressDraft, type: event.target.value })
                        }
                      >
                        <MenuItem value="shipping">Shipping</MenuItem>
                        <MenuItem value="billing">Billing</MenuItem>
                        <MenuItem value="home">Home</MenuItem>
                        <MenuItem value="office">Office</MenuItem>
                      </TextField>
                      <TextField
                        label="Name"
                        value={addressDraft.name}
                        onChange={(event) =>
                          setAddressDraft({ ...addressDraft, name: event.target.value })
                        }
                      />
                      <TextField
                        label="Street line 1"
                        value={addressDraft.street_line_1}
                        onChange={(event) =>
                          setAddressDraft({ ...addressDraft, street_line_1: event.target.value })
                        }
                      />
                      <TextField
                        label="Street line 2"
                        value={addressDraft.street_line_2}
                        onChange={(event) =>
                          setAddressDraft({ ...addressDraft, street_line_2: event.target.value })
                        }
                      />
                      <Stack direction={{ xs: "column", sm: "row" }} spacing={2}>
                        <TextField
                          label="Postal code"
                          value={addressDraft.postal_code}
                          onChange={(event) =>
                            setAddressDraft({ ...addressDraft, postal_code: event.target.value })
                          }
                        />
                        <TextField
                          label="City"
                          value={addressDraft.city}
                          onChange={(event) =>
                            setAddressDraft({ ...addressDraft, city: event.target.value })
                          }
                        />
                      </Stack>
                      <Stack direction={{ xs: "column", sm: "row" }} spacing={2}>
                        <TextField
                          label="State"
                          value={addressDraft.state}
                          onChange={(event) =>
                            setAddressDraft({ ...addressDraft, state: event.target.value })
                          }
                        />
                        <TextField
                          label="Country"
                          value={addressDraft.country}
                          onChange={(event) =>
                            setAddressDraft({ ...addressDraft, country: event.target.value })
                          }
                        />
                      </Stack>
                      <FormControlLabel
                        control={
                          <Checkbox
                            checked={addressDraft.is_default}
                            onChange={(event) =>
                              setAddressDraft({ ...addressDraft, is_default: event.target.checked })
                            }
                          />
                        }
                        label="Set as default"
                      />
                      <Stack direction="row" spacing={1}>
                        <Button variant="contained" onClick={() => void submitAddress()}>
                          {editingAddressId ? "Save address" : "Add address"}
                        </Button>
                        {editingAddressId ? (
                          <Button
                            variant="text"
                            onClick={() => {
                              setEditingAddressId(null);
                              setAddressDraft(emptyAddressDraft());
                            }}
                          >
                            Cancel
                          </Button>
                        ) : null}
                      </Stack>
                    </Stack>
                  </Paper>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        <Grid size={{ xs: 12 }}>
          <Card>
            <CardHeader title="Sessions and Devices" subheader="Active browser sessions" />
            <CardContent>
              <Stack spacing={2}>
                {sessions.map((session) => (
                  <Paper key={session.id} sx={{ p: 2.25 }}>
                    <Stack
                      direction={{ xs: "column", md: "row" }}
                      spacing={2}
                      justifyContent="space-between"
                    >
                      <Box>
                        <Stack direction="row" spacing={1} flexWrap="wrap" mb={1}>
                          {session.is_current ? <Chip label="current" color="secondary" /> : null}
                          <Chip label={session.ip_address || "unknown ip"} variant="outlined" />
                        </Stack>
                        <Typography variant="body1">
                          {session.user_agent || "Unknown device"}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          Created {formatDateTime(session.created_at)} · Expires {formatDateTime(session.expires_at)}
                        </Typography>
                      </Box>
                      <Button
                        variant="outlined"
                        color="secondary"
                        onClick={() => void endSession(session.id, session.is_current)}
                      >
                        {session.is_current ? "Logout current" : "End session"}
                      </Button>
                    </Stack>
                  </Paper>
                ))}
              </Stack>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Stack>
  );
}

function AdminUsersPage({ currentUser }: { currentUser: MeResponse }) {
  const [users, setUsers] = useState<UserPublic[]>([]);
  const [selectedUser, setSelectedUser] = useState<AdminUserDetail | null>(null);
  const [selectedUserId, setSelectedUserId] = useState<number | null>(null);
  const [adminForm, setAdminForm] = useState<AdminFormState>(emptyAdminForm());
  const [notice, setNotice] = useState<Notice | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const deferredSearch = useDeferredValue(search);
  const [createOpen, setCreateOpen] = useState(false);
  const [createForm, setCreateForm] = useState({
    email: "",
    username: "",
    display_name: "",
    password: "",
    roles: ["user"] as UserRole[],
    is_active: true,
    is_verified: true,
  });
  const [resetPassword, setResetPassword] = useState("");

  async function loadUsers() {
    setLoading(true);
    try {
      const response = await apiRequest<UserPublic[]>("/api/admin/users");
      setUsers(response);
      if (response.length > 0) {
        startTransition(() => {
          setSelectedUserId((current) => current ?? response[0].id);
        });
      }
    } catch (error) {
      setNotice({ severity: "error", message: getErrorMessage(error) });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    let active = true;
    apiRequest<UserPublic[]>("/api/admin/users")
      .then((response) => {
        if (!active) {
          return;
        }
        setUsers(response);
        if (response.length > 0) {
          startTransition(() => {
            setSelectedUserId((current) => current ?? response[0].id);
          });
        }
      })
      .catch((error) => {
        if (active) {
          setNotice({ severity: "error", message: getErrorMessage(error) });
        }
      })
      .finally(() => {
        if (active) {
          setLoading(false);
        }
      });

    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (!selectedUserId) {
      return;
    }
    let active = true;
    apiRequest<AdminUserDetail>(`/api/admin/users/${selectedUserId}`)
      .then((detail) => {
        if (!active) {
          return;
        }
        setSelectedUser(detail);
        setAdminForm(adminFormFromDetail(detail));
      })
      .catch((error) => {
        if (active) {
          setNotice({ severity: "error", message: getErrorMessage(error) });
        }
      });
    return () => {
      active = false;
    };
  }, [selectedUserId]);

  const filteredUsers = users.filter((user) => {
    const needle = deferredSearch.trim().toLowerCase();
    if (!needle) {
      return true;
    }
    return (
      user.email.toLowerCase().includes(needle) ||
      user.username.toLowerCase().includes(needle) ||
      (user.display_name ?? "").toLowerCase().includes(needle)
    );
  });

  async function saveSelectedUser() {
    if (!selectedUser) {
      return;
    }
    try {
      const socialLinks = parseJsonOrThrow<Record<string, string>>(
        adminForm.contact.social_links,
        "Admin social links",
      );
      const notificationSettings = parseJsonOrThrow<Record<string, boolean | string | number>>(
        adminForm.preferences.notification_settings,
        "Admin notification settings",
      );
      const response = await apiRequest<AdminUserDetail>(`/api/admin/users/${selectedUser.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          email: adminForm.email,
          username: adminForm.username,
          display_name: adminForm.display_name || null,
          roles: adminForm.roles,
          is_active: adminForm.is_active,
          is_verified: adminForm.is_verified,
          profile: {
            bio: adminForm.profile.bio || null,
            locale: adminForm.profile.locale || null,
            timezone: adminForm.profile.timezone || null,
          },
          contact: {
            phone: adminForm.contact.phone || null,
            website: adminForm.contact.website || null,
            social_links: socialLinks,
          },
          preferences: {
            theme: adminForm.preferences.theme || null,
            language: adminForm.preferences.language || null,
            notification_settings: notificationSettings,
          },
        }),
      });
      setSelectedUser(response);
      setAdminForm(adminFormFromDetail(response));
      startTransition(() => {
        setUsers(
          users.map((user) =>
            user.id === response.id
              ? {
                  ...user,
                  email: response.email,
                  username: response.username,
                  display_name: response.display_name,
                  roles: response.roles,
                  is_active: response.is_active,
                  is_verified: response.is_verified,
                }
              : user,
          ),
        );
      });
      setNotice({ severity: "success", message: "User updated." });
    } catch (error) {
      setNotice({ severity: "error", message: getErrorMessage(error) });
    }
  }

  async function createUser() {
    try {
      const created = await apiRequest<UserPublic>("/api/admin/users", {
        method: "POST",
        body: JSON.stringify({
          ...createForm,
          display_name: createForm.display_name || null,
        }),
      });
      setCreateOpen(false);
      setCreateForm({
        email: "",
        username: "",
        display_name: "",
        password: "",
        roles: ["user"],
        is_active: true,
        is_verified: true,
      });
      setNotice({ severity: "success", message: "User created." });
      const nextUsers = [...users, created];
      setUsers(nextUsers);
      startTransition(() => setSelectedUserId(created.id));
    } catch (error) {
      setNotice({ severity: "error", message: getErrorMessage(error) });
    }
  }

  async function toggleUserActive() {
    if (!selectedUser) {
      return;
    }
    try {
      const endpoint = selectedUser.is_active ? "disable" : "enable";
      const response = await apiRequest<UserPublic>(
        `/api/admin/users/${selectedUser.id}/${endpoint}`,
        { method: "POST" },
      );
      setUsers(users.map((user) => (user.id === response.id ? response : user)));
      setSelectedUser({ ...selectedUser, is_active: response.is_active });
      setAdminForm({ ...adminForm, is_active: response.is_active });
      setNotice({
        severity: "success",
        message: response.is_active ? "User enabled." : "User disabled.",
      });
    } catch (error) {
      setNotice({ severity: "error", message: getErrorMessage(error) });
    }
  }

  async function submitResetPassword() {
    if (!selectedUser || !resetPassword) {
      return;
    }
    try {
      await apiRequest(`/api/admin/users/${selectedUser.id}/reset-password`, {
        method: "POST",
        body: JSON.stringify({ new_password: resetPassword }),
      });
      setResetPassword("");
      setNotice({ severity: "success", message: "Password reset completed." });
    } catch (error) {
      setNotice({ severity: "error", message: getErrorMessage(error) });
    }
  }

  if (loading && users.length === 0) {
    return (
      <Box minHeight="60vh" display="grid" sx={{ placeItems: "center" }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Stack spacing={3.5} className="page-enter">
      <PageLead
        eyebrow="Admin"
        title="Users, roles and account operations"
        description="Manage account status, roles and editable profile data without surfacing internal security implementation details."
        actions={
          <>
            <Chip label={`Signed in as ${currentUser.username}`} color="primary" variant="outlined" />
            <Button
              variant="outlined"
              startIcon={<RefreshRoundedIcon />}
              onClick={() => void loadUsers()}
              fullWidth
            >
              Refresh
            </Button>
            <Button
              variant="contained"
              color="secondary"
              startIcon={<AddCircleOutlineRoundedIcon />}
              onClick={() => setCreateOpen(true)}
              fullWidth
            >
              Create user
            </Button>
          </>
        }
      />

      <NoticeBanner notice={notice} />

      <Grid container spacing={{ xs: 2.5, md: 3 }}>
        <Grid size={{ xs: 12, lg: 4 }}>
          <Card>
            <CardHeader title="User List" subheader="Filter and select a user" />
            <CardContent>
              <Stack spacing={2}>
                <TextField
                  label="Search"
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                />
                <List sx={{ maxHeight: 680, overflow: "auto", p: 0 }}>
                  {filteredUsers.map((user) => (
                    <ListItemButton
                      key={user.id}
                      selected={selectedUserId === user.id}
                      onClick={() => setSelectedUserId(user.id)}
                      sx={{ borderRadius: 2, mb: 1 }}
                    >
                      <ListItemText
                        primary={user.display_name || user.username}
                        secondary={`${user.email} · ${user.roles.join(", ")}`}
                      />
                    </ListItemButton>
                  ))}
                </List>
              </Stack>
            </CardContent>
          </Card>
        </Grid>

        <Grid size={{ xs: 12, lg: 8 }}>
          {selectedUser ? (
            <Card>
              <CardHeader
                title={selectedUser.display_name || selectedUser.username}
                subheader={`User #${selectedUser.id}`}
                action={
                  <Stack direction={{ xs: "column", sm: "row" }} spacing={1}>
                    <Button variant="outlined" onClick={() => void toggleUserActive()}>
                      {selectedUser.is_active ? "Disable" : "Enable"}
                    </Button>
                    <Button variant="contained" onClick={() => void saveSelectedUser()}>
                      Save
                    </Button>
                  </Stack>
                }
              />
              <CardContent>
                <Grid container spacing={2.5}>
                  <Grid size={{ xs: 12, md: 6 }}>
                    <TextField
                      label="Email"
                      value={adminForm.email}
                      onChange={(event) =>
                        setAdminForm({ ...adminForm, email: event.target.value })
                      }
                    />
                  </Grid>
                  <Grid size={{ xs: 12, md: 6 }}>
                    <TextField
                      label="Username"
                      value={adminForm.username}
                      onChange={(event) =>
                        setAdminForm({ ...adminForm, username: event.target.value })
                      }
                    />
                  </Grid>
                  <Grid size={{ xs: 12 }}>
                    <TextField
                      label="Display Name"
                      value={adminForm.display_name}
                      onChange={(event) =>
                        setAdminForm({ ...adminForm, display_name: event.target.value })
                      }
                    />
                  </Grid>
                  <Grid size={{ xs: 12 }}>
                    <Stack direction="row" spacing={1} flexWrap="wrap">
                      {roleOptions.map((role) => (
                        <Chip
                          key={role}
                          label={role}
                          color={adminForm.roles.includes(role) ? "secondary" : "default"}
                          onClick={() =>
                            setAdminForm({
                              ...adminForm,
                              roles: toggleRole(adminForm.roles, role),
                            })
                          }
                        />
                      ))}
                    </Stack>
                  </Grid>
                  <Grid size={{ xs: 12, md: 6 }}>
                    <FormControlLabel
                      control={
                        <Switch
                          checked={adminForm.is_active}
                          onChange={(event) =>
                            setAdminForm({ ...adminForm, is_active: event.target.checked })
                          }
                        />
                      }
                      label="Active"
                    />
                  </Grid>
                  <Grid size={{ xs: 12, md: 6 }}>
                    <FormControlLabel
                      control={
                        <Switch
                          checked={adminForm.is_verified}
                          onChange={(event) =>
                            setAdminForm({ ...adminForm, is_verified: event.target.checked })
                          }
                        />
                      }
                      label="Verified"
                    />
                  </Grid>

                  <Grid size={{ xs: 12 }}>
                    <Divider sx={{ my: 1 }} />
                    <Typography variant="h6" gutterBottom>
                      Profile
                    </Typography>
                  </Grid>
                  <Grid size={{ xs: 12, md: 6 }}>
                    <Stack direction="row" spacing={2} alignItems="center">
                      <Avatar
                        src={selectedUser.profile?.avatar_url || undefined}
                        sx={{ width: 56, height: 56, bgcolor: "secondary.main" }}
                      >
                        {(selectedUser.display_name || selectedUser.username).slice(0, 1).toUpperCase()}
                      </Avatar>
                      <Typography variant="body2" color="text.secondary">
                        Avatar preview only. Uploads are user-managed and stored behind a controlled API route.
                      </Typography>
                    </Stack>
                  </Grid>
                  <Grid size={{ xs: 12, md: 6 }}>
                    <TextField
                      label="Locale"
                      value={adminForm.profile.locale}
                      onChange={(event) =>
                        setAdminForm({
                          ...adminForm,
                          profile: { ...adminForm.profile, locale: event.target.value },
                        })
                      }
                    />
                  </Grid>
                  <Grid size={{ xs: 12 }}>
                    <TextField
                      label="Bio"
                      multiline
                      minRows={3}
                      value={adminForm.profile.bio}
                      onChange={(event) =>
                        setAdminForm({
                          ...adminForm,
                          profile: { ...adminForm.profile, bio: event.target.value },
                        })
                      }
                    />
                  </Grid>
                  <Grid size={{ xs: 12 }}>
                    <TextField
                      label="Timezone"
                      value={adminForm.profile.timezone}
                      onChange={(event) =>
                        setAdminForm({
                          ...adminForm,
                          profile: { ...adminForm.profile, timezone: event.target.value },
                        })
                      }
                    />
                  </Grid>

                  <Grid size={{ xs: 12 }}>
                    <Divider sx={{ my: 1 }} />
                    <Typography variant="h6" gutterBottom>
                      Contact and Preferences
                    </Typography>
                  </Grid>
                  <Grid size={{ xs: 12, md: 6 }}>
                    <TextField
                      label="Phone"
                      value={adminForm.contact.phone}
                      onChange={(event) =>
                        setAdminForm({
                          ...adminForm,
                          contact: { ...adminForm.contact, phone: event.target.value },
                        })
                      }
                    />
                  </Grid>
                  <Grid size={{ xs: 12, md: 6 }}>
                    <TextField
                      label="Website"
                      value={adminForm.contact.website}
                      onChange={(event) =>
                        setAdminForm({
                          ...adminForm,
                          contact: { ...adminForm.contact, website: event.target.value },
                        })
                      }
                    />
                  </Grid>
                  <Grid size={{ xs: 12 }}>
                    <TextField
                      label="Social Links JSON"
                      multiline
                      minRows={3}
                      value={adminForm.contact.social_links}
                      onChange={(event) =>
                        setAdminForm({
                          ...adminForm,
                          contact: { ...adminForm.contact, social_links: event.target.value },
                        })
                      }
                    />
                  </Grid>
                  <Grid size={{ xs: 12, md: 6 }}>
                    <TextField
                      label="Theme"
                      value={adminForm.preferences.theme}
                      onChange={(event) =>
                        setAdminForm({
                          ...adminForm,
                          preferences: { ...adminForm.preferences, theme: event.target.value },
                        })
                      }
                    />
                  </Grid>
                  <Grid size={{ xs: 12, md: 6 }}>
                    <TextField
                      label="Language"
                      value={adminForm.preferences.language}
                      onChange={(event) =>
                        setAdminForm({
                          ...adminForm,
                          preferences: { ...adminForm.preferences, language: event.target.value },
                        })
                      }
                    />
                  </Grid>
                  <Grid size={{ xs: 12 }}>
                    <TextField
                      label="Notification Settings JSON"
                      multiline
                      minRows={3}
                      value={adminForm.preferences.notification_settings}
                      onChange={(event) =>
                        setAdminForm({
                          ...adminForm,
                          preferences: {
                            ...adminForm.preferences,
                            notification_settings: event.target.value,
                          },
                        })
                      }
                    />
                  </Grid>

                  <Grid size={{ xs: 12 }}>
                    <Divider sx={{ my: 1 }} />
                    <Alert severity="info" variant="outlined">
                      Direct security internals stay server-side. This admin surface only exposes status changes, roles and password resets.
                    </Alert>
                  </Grid>

                  <Grid size={{ xs: 12 }}>
                    <Divider sx={{ my: 1 }} />
                    <Typography variant="h6" gutterBottom>
                      Password Reset
                    </Typography>
                    <Stack direction={{ xs: "column", md: "row" }} spacing={2}>
                      <TextField
                        label="New password"
                        type="password"
                        value={resetPassword}
                        onChange={(event) => setResetPassword(event.target.value)}
                      />
                      <Button variant="outlined" color="secondary" onClick={() => void submitResetPassword()}>
                        Reset password
                      </Button>
                    </Stack>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
          ) : (
            <Paper sx={{ p: 4 }}>
              <Typography variant="h5">Select a user from the list.</Typography>
            </Paper>
          )}
        </Grid>
      </Grid>

      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>Create admin-managed user</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            <TextField
              label="Email"
              value={createForm.email}
              onChange={(event) => setCreateForm({ ...createForm, email: event.target.value })}
            />
            <TextField
              label="Username"
              value={createForm.username}
              onChange={(event) =>
                setCreateForm({ ...createForm, username: event.target.value })
              }
            />
            <TextField
              label="Display Name"
              value={createForm.display_name}
              onChange={(event) =>
                setCreateForm({ ...createForm, display_name: event.target.value })
              }
            />
            <TextField
              label="Password"
              type="password"
              value={createForm.password}
              onChange={(event) =>
                setCreateForm({ ...createForm, password: event.target.value })
              }
            />
            <Stack direction="row" spacing={1} flexWrap="wrap">
              {roleOptions.map((role) => (
                <Chip
                  key={role}
                  label={role}
                  color={createForm.roles.includes(role) ? "secondary" : "default"}
                  onClick={() =>
                    setCreateForm({
                      ...createForm,
                      roles: toggleRole(createForm.roles, role),
                    })
                  }
                />
              ))}
            </Stack>
            <FormControlLabel
              control={
                <Checkbox
                  checked={createForm.is_active}
                  onChange={(event) =>
                    setCreateForm({ ...createForm, is_active: event.target.checked })
                  }
                />
              }
              label="Active"
            />
            <FormControlLabel
              control={
                <Checkbox
                  checked={createForm.is_verified}
                  onChange={(event) =>
                    setCreateForm({ ...createForm, is_verified: event.target.checked })
                  }
                />
              }
              label="Verified"
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateOpen(false)}>Cancel</Button>
          <Button variant="contained" color="secondary" onClick={() => void createUser()}>
            Create
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}

function getErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    return error.message;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return "Unexpected error";
}

function formatDateTime(value: string | null): string {
  if (!value) {
    return "never";
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function normalizeDefaultAddresses(addresses: UserAddress[]): UserAddress[] {
  return [...addresses].sort((left, right) => {
    if (left.is_default === right.is_default) {
      return left.id - right.id;
    }
    return left.is_default ? -1 : 1;
  });
}

function parseJsonOrThrow<T extends Record<string, unknown>>(value: string, label: string): T {
  try {
    const parsed = JSON.parse(value) as T;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed;
    }
    throw new Error(`${label} must be a JSON object.`);
  } catch {
    throw new Error(`${label} must be valid JSON.`);
  }
}

function adminFormFromDetail(detail: AdminUserDetail): AdminFormState {
  return {
    email: detail.email,
    username: detail.username,
    display_name: detail.display_name ?? "",
    roles: detail.roles,
    is_active: detail.is_active,
    is_verified: detail.is_verified,
    profile: {
      bio: detail.profile?.bio ?? "",
      locale: detail.profile?.locale ?? "",
      timezone: detail.profile?.timezone ?? "",
    },
    contact: {
      phone: detail.contact?.phone ?? "",
      website: detail.contact?.website ?? "",
      social_links: JSON.stringify(detail.contact?.social_links ?? {}, null, 2),
    },
    preferences: {
      theme: detail.preferences?.theme ?? "",
      language: detail.preferences?.language ?? "",
      notification_settings: JSON.stringify(detail.preferences?.notification_settings ?? {}, null, 2),
    },
  };
}

function toggleRole(roles: UserRole[], role: UserRole): UserRole[] {
  if (roles.includes(role)) {
    const nextRoles = roles.filter((currentRole) => currentRole !== role);
    return nextRoles.length > 0 ? nextRoles : roles;
  }
  return [...roles, role];
}

export default App;
