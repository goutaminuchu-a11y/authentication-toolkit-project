/**
 * Public authentication server functions.
 *
 * All credential handling, validation, rate limiting and security logging
 * happens here on the server. The browser never sees hashes, secrets, or
 * privileged keys — only the resulting session and a safe status code.
 */
import { createServerFn } from "@tanstack/react-start";
import {
  getRequestHeader,
  getRequestIP,
  setResponseStatus,
} from "@tanstack/react-start/server";
import { createClient } from "@supabase/supabase-js";
import { z } from "zod";

import { analyzePassword } from "./password";
import { parseUserAgent } from "./device";

const MAX_FAILED_ATTEMPTS = 5;
const WINDOW_MINUTES = 10;

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

function requestContext() {
  let ip = "unknown";
  try {
    ip = getRequestIP({ xForwardedFor: true }) ?? "unknown";
  } catch {
    ip = "unknown";
  }
  const userAgent = getRequestHeader("user-agent") ?? "unknown";
  return { ip, userAgent };
}

const registerSchema = z.object({
  fullName: z.string().trim().min(2).max(80),
  email: z.string().trim().toLowerCase().email(),
  password: z.string().min(8).max(128),
  deviceId: z.string().min(1).max(64),
});

const loginSchema = z.object({
  email: z.string().trim().toLowerCase().min(3).max(160),
  password: z.string().min(1).max(128),
  deviceId: z.string().min(1).max(64),
});

export type LoginResult =
  | { ok: true; accessToken: string; refreshToken: string }
  | { ok: false; code: "INVALID" | "RATE_LIMITED" | "ERROR"; message: string };

export type RegisterResult =
  | { ok: true }
  | { ok: false; code: "DUPLICATE" | "WEAK" | "INVALID" | "RATE_LIMITED" | "ERROR"; message: string };

export const registerAccount = createServerFn({ method: "POST" })
  .inputValidator((input: unknown) => input)
  .handler(async ({ data }): Promise<RegisterResult> => {
    const parsed = registerSchema.safeParse(data);
    if (!parsed.success) {
      setResponseStatus(400);
      return { ok: false, code: "INVALID", message: "Please check the details you entered." };
    }
    const { fullName, email, password } = parsed.data;

    // Server-side password policy — the client meter is only a convenience.
    const analysis = analyzePassword(password);
    if (!analysis.valid) {
      setResponseStatus(400);
      return {
        ok: false,
        code: "WEAK",
        message: "Password does not meet the security requirements.",
      };
    }

    const { ip, userAgent } = requestContext();
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");

    // Rate limit registrations per source address.
    const since = new Date(Date.now() - WINDOW_MINUTES * 60_000).toISOString();
    const { count } = await supabaseAdmin
      .from("login_attempts")
      .select("id", { count: "exact", head: true })
      .eq("ip_address", ip)
      .eq("email_key", "register")
      .gte("created_at", since);

    if ((count ?? 0) >= MAX_FAILED_ATTEMPTS) {
      await supabaseAdmin.from("security_events").insert({
        event_type: "RATE_LIMITED",
        description: "Registration blocked: too many attempts from this source.",
        ip_address: ip,
        user_agent: userAgent,
      });
      setResponseStatus(429);
      return {
        ok: false,
        code: "RATE_LIMITED",
        message: "Too many authentication attempts. Please try again later.",
      };
    }

    await supabaseAdmin
      .from("login_attempts")
      .insert({ ip_address: ip, email_key: "register", success: false });

    // Password is handed straight to the auth service, which stores only a
    // salted hash. It is never written to any application table or log.
    const { data: created, error } = await supabaseAdmin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { full_name: fullName },
    });

    if (error || !created?.user) {
      const message = (error?.message ?? "").toLowerCase();
      if (message.includes("already") || message.includes("registered") || message.includes("exists")) {
        setResponseStatus(409);
        return {
          ok: false,
          code: "DUPLICATE",
          message: "An account with this email address already exists.",
        };
      }
      setResponseStatus(400);
      return { ok: false, code: "ERROR", message: "Registration could not be completed." };
    }

    const userId = created.user.id;

    await supabaseAdmin.from("profiles").insert({
      id: userId,
      full_name: fullName,
      email,
    });

    // Role is assigned by the server. Clients can never choose it.
    await supabaseAdmin.from("user_roles").insert({ user_id: userId, role: "USER" });

    await supabaseAdmin.from("security_events").insert({
      user_id: userId,
      event_type: "REGISTER",
      description: "Account created with the USER role.",
      ip_address: ip,
      user_agent: userAgent,
    });

    return { ok: true };
  });

export const loginWithPassword = createServerFn({ method: "POST" })
  .inputValidator((input: unknown) => input)
  .handler(async ({ data }): Promise<LoginResult> => {
    const parsed = loginSchema.safeParse(data);
    const { ip, userAgent } = requestContext();
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");

    if (!parsed.success) {
      setResponseStatus(400);
      return { ok: false, code: "INVALID", message: "Invalid email or password." };
    }
    const { email, password, deviceId } = parsed.data;

    const since = new Date(Date.now() - WINDOW_MINUTES * 60_000).toISOString();
    const { count } = await supabaseAdmin
      .from("login_attempts")
      .select("id", { count: "exact", head: true })
      .eq("ip_address", ip)
      .eq("success", false)
      .neq("email_key", "register")
      .gte("created_at", since);

    if ((count ?? 0) >= MAX_FAILED_ATTEMPTS) {
      await supabaseAdmin.from("security_events").insert({
        event_type: "RATE_LIMITED",
        description: `Sign-in blocked after ${MAX_FAILED_ATTEMPTS} failed attempts within ${WINDOW_MINUTES} minutes.`,
        ip_address: ip,
        user_agent: userAgent,
      });
      setResponseStatus(429);
      return {
        ok: false,
        code: "RATE_LIMITED",
        message: "Too many authentication attempts. Please try again later.",
      };
    }

    const { data: signIn, error } = await publishableClient().auth.signInWithPassword({
      email,
      password,
    });

    if (error || !signIn?.session || !signIn.user) {
      await supabaseAdmin
        .from("login_attempts")
        .insert({ ip_address: ip, email_key: email, success: false });

      // Attribute the failure to an account when one exists, without ever
      // telling the caller whether the email is registered.
      const { data: profile } = await supabaseAdmin
        .from("profiles")
        .select("id")
        .eq("email", email)
        .maybeSingle();

      await supabaseAdmin.from("security_events").insert({
        user_id: profile?.id ?? null,
        event_type: "LOGIN_FAILED",
        description: "Failed authentication attempt (credentials rejected).",
        ip_address: ip,
        user_agent: userAgent,
      });

      setResponseStatus(401);
      return { ok: false, code: "INVALID", message: "Invalid email or password." };
    }

    const userId = signIn.user.id;
    const { browser, os } = parseUserAgent(userAgent);

    await supabaseAdmin
      .from("login_attempts")
      .insert({ ip_address: ip, email_key: email, success: true });

    // Keep a profile row for accounts created outside the app (e.g. seeded admin).
    await supabaseAdmin.from("profiles").upsert(
      {
        id: userId,
        email,
        full_name:
          (signIn.user.user_metadata?.["full_name"] as string | undefined) ?? email.split("@")[0]!,
      },
      { onConflict: "id", ignoreDuplicates: true },
    );
    const { data: existingRole } = await supabaseAdmin
      .from("user_roles")
      .select("id")
      .eq("user_id", userId)
      .limit(1);
    if (!existingRole || existingRole.length === 0) {
      await supabaseAdmin.from("user_roles").insert({ user_id: userId, role: "USER" });
    }

    const { data: existingSession } = await supabaseAdmin
      .from("user_sessions")
      .select("id")
      .eq("user_id", userId)
      .eq("device_id", deviceId)
      .maybeSingle();

    const expiresAt = new Date(Date.now() + 7 * 24 * 3600_000).toISOString();
    if (existingSession) {
      await supabaseAdmin
        .from("user_sessions")
        .update({
          browser,
          os,
          ip_address: ip,
          last_active_at: new Date().toISOString(),
          expires_at: expiresAt,
          revoked_at: null,
        })
        .eq("id", existingSession.id);
    } else {
      await supabaseAdmin.from("user_sessions").insert({
        user_id: userId,
        device_id: deviceId,
        browser,
        os,
        ip_address: ip,
        expires_at: expiresAt,
      });
    }

    await supabaseAdmin.from("security_events").insert([
      {
        user_id: userId,
        event_type: "LOGIN_SUCCESS",
        description: "Credentials verified and session established.",
        ip_address: ip,
        user_agent: userAgent,
      },
      {
        user_id: userId,
        event_type: "SESSION_CREATED",
        description: `Session started on ${browser} • ${os}.`,
        ip_address: ip,
        user_agent: userAgent,
      },
    ]);

    return {
      ok: true,
      accessToken: signIn.session.access_token,
      refreshToken: signIn.session.refresh_token,
    };
  });
