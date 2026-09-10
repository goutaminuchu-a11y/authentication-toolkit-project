import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { Session, User } from "@supabase/supabase-js";
import { useQueryClient } from "@tanstack/react-query";

import { supabase } from "@/integrations/supabase/client";
import { getDeviceId } from "@/lib/device";
import { endSession, touchSession } from "@/lib/account.functions";

export type Profile = {
  id: string;
  full_name: string;
  email: string;
  created_at: string;
  updated_at: string;
};

type AuthValue = {
  user: User | null;
  session: Session | null;
  profile: Profile | null;
  role: "USER" | "ADMIN" | null;
  loading: boolean;
  isAuthenticated: boolean;
  isAdmin: boolean;
  refreshUser: () => Promise<void>;
  logout: (options?: { all?: boolean }) => Promise<void>;
};

const AuthContext = createContext<AuthValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [role, setRole] = useState<"USER" | "ADMIN" | null>(null);
  const [loading, setLoading] = useState(true);
  const queryClient = useQueryClient();

  const loadAccount = useCallback(async (activeUser: User | null) => {
    if (!activeUser) {
      setProfile(null);
      setRole(null);
      return;
    }
    const [{ data: profileRow }, { data: roleRows }] = await Promise.all([
      supabase.from("profiles").select("*").eq("id", activeUser.id).maybeSingle(),
      supabase.from("user_roles").select("role").eq("user_id", activeUser.id),
    ]);
    setProfile((profileRow as Profile | null) ?? null);
    const roles = (roleRows ?? []).map((r) => r.role);
    setRole(roles.includes("ADMIN") ? "ADMIN" : roles.length > 0 ? "USER" : null);
  }, []);

  const refreshUser = useCallback(async () => {
    const { data } = await supabase.auth.getUser();
    setUser(data.user ?? null);
    await loadAccount(data.user ?? null);
  }, [loadAccount]);

  useEffect(() => {
    let mounted = true;

    const { data: subscription } = supabase.auth.onAuthStateChange((event, nextSession) => {
      if (!mounted) return;
      setSession(nextSession);
      setUser(nextSession?.user ?? null);
      if (event === "SIGNED_OUT") {
        setProfile(null);
        setRole(null);
      }
    });

    void (async () => {
      const { data } = await supabase.auth.getSession();
      if (!mounted) return;
      setSession(data.session);
      const { data: userData } = await supabase.auth.getUser();
      if (!mounted) return;
      setUser(userData.user ?? null);
      await loadAccount(userData.user ?? null);
      if (mounted) setLoading(false);
    })();

    return () => {
      mounted = false;
      subscription.subscription.unsubscribe();
    };
  }, [loadAccount]);

  // Load profile/role whenever the signed-in identity changes.
  useEffect(() => {
    if (!user) return;
    void loadAccount(user);
    void touchSession({ data: { deviceId: getDeviceId() } }).catch(() => undefined);
  }, [user?.id, loadAccount, user]);

  const logout = useCallback(
    async ({ all = false }: { all?: boolean } = {}) => {
      try {
        await endSession({ data: { deviceId: getDeviceId(), all } });
      } catch {
        // Sign out locally even if the audit call fails.
      }
      await queryClient.cancelQueries();
      queryClient.clear();
      await supabase.auth.signOut({ scope: all ? "global" : "local" });
      setProfile(null);
      setRole(null);
    },
    [queryClient],
  );

  const value = useMemo<AuthValue>(
    () => ({
      user,
      session,
      profile,
      role,
      loading,
      isAuthenticated: Boolean(user),
      isAdmin: role === "ADMIN",
      refreshUser,
      logout,
    }),
    [user, session, profile, role, loading, refreshUser, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
