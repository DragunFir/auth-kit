export type UserRole = "user" | "admin" | "owner";

export interface UserProfile {
  avatar_url: string | null;
  bio: string | null;
  locale: string | null;
  timezone: string | null;
  created_at: string;
  updated_at: string;
}

export interface UserAddress {
  id: number;
  type: string;
  name: string | null;
  street_line_1: string;
  street_line_2: string | null;
  postal_code: string;
  city: string;
  state: string | null;
  country: string;
  is_default: boolean;
  created_at: string;
  updated_at: string;
}

export interface UserContact {
  phone: string | null;
  website: string | null;
  social_links: Record<string, string>;
  created_at: string;
  updated_at: string;
}

export interface UserPreferences {
  theme: string | null;
  language: string | null;
  notification_settings: Record<string, boolean | string | number>;
  created_at: string;
  updated_at: string;
}

export interface UserSecurity {
  two_factor_enabled: boolean;
  passkeys_enabled: boolean;
  recovery_codes_enabled: boolean;
  trusted_devices_enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface UserPublic {
  id: number;
  email: string;
  username: string;
  display_name: string | null;
  roles: UserRole[];
  is_active: boolean;
  is_verified: boolean;
  created_at: string;
  updated_at: string;
  last_login_at: string | null;
}

export interface MeResponse extends UserPublic {
  profile: UserProfile | null;
  preferences: UserPreferences | null;
}

export interface SessionInfo {
  id: string;
  created_at: string;
  updated_at: string;
  expires_at: string;
  revoked_at: string | null;
  user_agent: string | null;
  ip_address: string | null;
  is_current: boolean;
}

export interface AdminUserDetail extends UserPublic {
  profile: UserProfile | null;
  addresses: UserAddress[];
  contact: UserContact | null;
  preferences: UserPreferences | null;
  security: UserSecurity | null;
}

export interface ApiErrorShape {
  error_code?: string;
  message?: string;
  detail?: string;
  details?: Array<Record<string, unknown>>;
}

export interface StatusMessageResponse {
  ok: boolean;
  message: string;
}

export interface SetupStatusResponse {
  needs_setup: boolean;
  has_owner: boolean;
}
