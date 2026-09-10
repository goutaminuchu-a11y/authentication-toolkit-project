/**
 * Authenticated server functions. Every handler runs behind
 * requireSupabaseAuth, so the caller's identity comes from a verified token
 * rather than from anything the browser claims.
 */
import { createServerFn } from "@tanstack/react-start";
import { getRequestHeader, getRequestIP, setResponseStatus } from "@tanstack/react-start/server";
import { createClient } from "@supabase/supabase-js";
import { z } from "zod";

import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { analyzePassword } from "./password";
import { parseUserAgent } from "./device";

function requestContext() {
  let ip = "unknown";
  try {
    ip = getRequestIP({ xForwardedFor: true }) ?? "unknown";
  } catch {
    ip = "unknown";
  }
  return { ip, userAgent: getRequestHeader("user-agent") ?? "unknown" };
}

function publishableClient() {
  const url = process.env["SUPABASE_URL"]!;
  const key = process.env["SUPABASE_PUBLISHABLE_KEY"]!;
  return createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
    global: {
      fetch: (input, init) => {
        const h = new Headers(init?.headers);
        if (key.startsWith("sb_") && h.get("Authorization") === `Bearer ${key}`) {
          h.delete("Authorization");
        }
        h.set("apikey", key);
        return fetch(input, { ...init, headers: h });
      },
    },
  });
}

/** Keeps the current session row fresh (last active time / device labels). */
export const touchSession = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { deviceId: string }) => input)
  .handler(async ({ data, context }) => {
    const deviceId = String(data?.deviceId ?? "").slice(0, 64);
    if (!deviceId) return { ok: false };
    const { ip, userAgent } = requestContext();
    const { browser, os } = parseUserAgent(userAgent);
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");

    const { data: existing } = await supabaseAdmin
      .from("user_sessions")
      .select("id")
      .eq("user_id", context.userId)
      .eq("device_id", deviceId)
      .maybeSingle();

    if (existing) {
      await supabaseAdmin
        .from("user_sessions")
        .update({ last_active_at: new Date().toISOString(), revoked_at: null, browser, os })
        .eq("id", existing.id);
    } else {
      await supabaseAdmin.from("user_sessions").insert({
        user_id: context.userId,
        device_id: deviceId,
        browser,
        os,
        ip_address: ip,
      });
    }
    return { ok: true };
  });

/** Signs out: revokes the session row(s) and records the event. */
export const endSession = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { deviceId: string; all?: boolean }) => input)
  .handler(async ({ data, context }) => {
    const { ip, userAgent } = requestContext();
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const now = new Date().toISOString();

    if (data?.all) {
      await supabaseAdmin
        .from("user_sessions")
        .update({ revoked_at: now })
        .eq("user_id", context.userId)
        .is("revoked_at", null);
    } else {
      await supabaseAdmin
        .from("user_sessions")
        .update({ revoked_at: now })
        .eq("user_id", context.userId)
        .eq("device_id", String(data?.deviceId ?? "").slice(0, 64))
        .is("revoked_at", null);
    }

    await supabaseAdmin.from("security_events").insert([
      {
        user_id: context.userId,
        event_type: "LOGOUT",
        description: data?.all ? "Signed out of all sessions." : "Signed out of this session.",
        ip_address: ip,
        user_agent: userAgent,
      },
      {
        user_id: context.userId,
        event_type: "SESSION_REVOKED",
        description: data?.all ? "All session records revoked." : "Session record revoked.",
        ip_address: ip,
        user_agent: userAgent,
      },
    ]);

    return { ok: true };
  });

/** Revokes one specific session row belonging to the caller. */
export const revokeSession = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { sessionId: string }) => input)
  .handler(async ({ data, context }) => {
    const parsed = z.object({ sessionId: z.string().uuid() }).safeParse(data);
    if (!parsed.success) {
      setResponseStatus(400);
      return { ok: false };
    }
    const { ip, userAgent } = requestContext();
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");

    const { error } = await supabaseAdmin
      .from("user_sessions")
      .update({ revoked_at: new Date().toISOString() })
      .eq("id", parsed.data.sessionId)
      .eq("user_id", context.userId);

    if (error) {
      setResponseStatus(400);
      return { ok: false };
    }

    await supabaseAdmin.from("security_events").insert({
      user_id: context.userId,
      event_type: "SESSION_REVOKED",
      description: "A session was revoked by the account owner.",
      ip_address: ip,
      user_agent: userAgent,
    });
    return { ok: true };
  });

export type ChangePasswordResult =
  | { ok: true }
  | { ok: false; code: "WRONG_CURRENT" | "WEAK" | "SAME" | "ERROR"; message: string };

export const changePassword = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { currentPassword: string; newPassword: string }) => input)
  .handler(async ({ data, context }): Promise<ChangePasswordResult> => {
    const parsed = z
      .object({
        currentPassword: z.string().min(1).max(128),
        newPassword: z.string().min(8).max(128),
      })
      .safeParse(data);

    if (!parsed.success) {
      setResponseStatus(400);
      return { ok: false, code: "ERROR", message: "Please check the values you entered." };
    }
    const { currentPassword, newPassword } = parsed.data;

    if (currentPassword === newPassword) {
      setResponseStatus(400);
      return {
        ok: false,
        code: "SAME",
        message: "The new password must be different from the current one.",
      };
    }

    if (!analyzePassword(newPassword).valid) {
      setResponseStatus(400);
      return {
        ok: false,
        code: "WEAK",
        message: "The new password does not meet the security requirements.",
      };
    }

    const { data: userData } = await context.supabase.auth.getUser();
    const email = userData.user?.email;
    if (!email) {
      setResponseStatus(401);
      return { ok: false, code: "ERROR", message: "Your session could not be verified." };
    }

    // Re-verify the current password against the auth service.
    const { error: verifyError } = await publishableClient().auth.signInWithPassword({
      email,
      password: currentPassword,
    });
    if (verifyError) {
      setResponseStatus(400);
      return { ok: false, code: "WRONG_CURRENT", message: "Your current password is incorrect." };
    }

    const { ip, userAgent } = requestContext();
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");

    const { error: updateError } = await supabaseAdmin.auth.admin.updateUserById(context.userId, {
      password: newPassword,
    });
    if (updateError) {
      setResponseStatus(400);
      return { ok: false, code: "ERROR", message: "The password could not be updated." };
    }

    await supabaseAdmin
      .from("user_sessions")
      .update({ revoked_at: new Date().toISOString() })
      .eq("user_id", context.userId)
      .is("revoked_at", null);

    await supabaseAdmin.from("security_events").insert([
      {
        user_id: context.userId,
        event_type: "PASSWORD_CHANGED",
        description: "Password changed after verifying the current password.",
        ip_address: ip,
        user_agent: userAgent,
      },
      {
        user_id: context.userId,
        event_type: "SESSION_REVOKED",
        description: "All sessions revoked following a password change.",
        ip_address: ip,
        user_agent: userAgent,
      },
    ]);

    return { ok: true };
  });
