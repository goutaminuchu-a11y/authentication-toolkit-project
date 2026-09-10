-- Roles
CREATE TYPE public.app_role AS ENUM ('USER', 'ADMIN');

-- Profiles
CREATE TABLE public.profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  full_name TEXT NOT NULL DEFAULT '',
  email TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
GRANT SELECT, UPDATE ON public.profiles TO authenticated;
GRANT ALL ON public.profiles TO service_role;
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

-- User roles
CREATE TABLE public.user_roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role public.app_role NOT NULL DEFAULT 'USER',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, role)
);
GRANT SELECT ON public.user_roles TO authenticated;
GRANT ALL ON public.user_roles TO service_role;
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION public.has_role(_user_id UUID, _role public.app_role)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.user_roles WHERE user_id = _user_id AND role = _role
  )
$$;

-- Security events
CREATE TABLE public.security_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  event_type TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  ip_address TEXT,
  user_agent TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX security_events_user_idx ON public.security_events (user_id, created_at DESC);
CREATE INDEX security_events_type_idx ON public.security_events (event_type, created_at DESC);
GRANT SELECT ON public.security_events TO authenticated;
GRANT ALL ON public.security_events TO service_role;
ALTER TABLE public.security_events ENABLE ROW LEVEL SECURITY;

-- Login attempts (rate limiting source data)
CREATE TABLE public.login_attempts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ip_address TEXT NOT NULL DEFAULT 'unknown',
  email_key TEXT NOT NULL,
  success BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX login_attempts_idx ON public.login_attempts (ip_address, created_at DESC);
GRANT SELECT ON public.login_attempts TO authenticated;
GRANT ALL ON public.login_attempts TO service_role;
ALTER TABLE public.login_attempts ENABLE ROW LEVEL SECURITY;

-- User sessions (safe metadata only)
CREATE TABLE public.user_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL,
  browser TEXT NOT NULL DEFAULT 'Unknown',
  os TEXT NOT NULL DEFAULT 'Unknown',
  ip_address TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_active_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '7 days',
  revoked_at TIMESTAMPTZ
);
CREATE INDEX user_sessions_user_idx ON public.user_sessions (user_id, last_active_at DESC);
GRANT SELECT ON public.user_sessions TO authenticated;
GRANT ALL ON public.user_sessions TO service_role;
ALTER TABLE public.user_sessions ENABLE ROW LEVEL SECURITY;

-- Policies: profiles
CREATE POLICY "profiles_select_own" ON public.profiles
  FOR SELECT TO authenticated USING (id = auth.uid());
CREATE POLICY "profiles_select_admin" ON public.profiles
  FOR SELECT TO authenticated USING (public.has_role(auth.uid(), 'ADMIN'));
CREATE POLICY "profiles_update_own" ON public.profiles
  FOR UPDATE TO authenticated USING (id = auth.uid()) WITH CHECK (id = auth.uid());

-- Policies: user_roles (read only from client; writes are service_role only)
CREATE POLICY "user_roles_select_own" ON public.user_roles
  FOR SELECT TO authenticated USING (user_id = auth.uid());
CREATE POLICY "user_roles_select_admin" ON public.user_roles
  FOR SELECT TO authenticated USING (public.has_role(auth.uid(), 'ADMIN'));

-- Policies: security_events
CREATE POLICY "security_events_select_own" ON public.security_events
  FOR SELECT TO authenticated USING (user_id = auth.uid());
CREATE POLICY "security_events_select_admin" ON public.security_events
  FOR SELECT TO authenticated USING (public.has_role(auth.uid(), 'ADMIN'));

-- Policies: login_attempts (admin monitoring only)
CREATE POLICY "login_attempts_select_admin" ON public.login_attempts
  FOR SELECT TO authenticated USING (public.has_role(auth.uid(), 'ADMIN'));

-- Policies: user_sessions
CREATE POLICY "user_sessions_select_own" ON public.user_sessions
  FOR SELECT TO authenticated USING (user_id = auth.uid());
CREATE POLICY "user_sessions_select_admin" ON public.user_sessions
  FOR SELECT TO authenticated USING (public.has_role(auth.uid(), 'ADMIN'));

-- updated_at trigger
CREATE OR REPLACE FUNCTION public.touch_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;
CREATE TRIGGER profiles_touch_updated_at BEFORE UPDATE ON public.profiles
  FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();

-- Admin statistics, computed server-side and gated on the caller's role
CREATE OR REPLACE FUNCTION public.admin_stats()
RETURNS JSON
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE result JSON;
BEGIN
  IF NOT public.has_role(auth.uid(), 'ADMIN') THEN
    RAISE EXCEPTION 'forbidden';
  END IF;

  SELECT json_build_object(
    'total_users', (SELECT count(*) FROM public.profiles),
    'active_sessions', (SELECT count(*) FROM public.user_sessions WHERE revoked_at IS NULL AND expires_at > now()),
    'login_success', (SELECT count(*) FROM public.security_events WHERE event_type = 'LOGIN_SUCCESS'),
    'login_failed', (SELECT count(*) FROM public.security_events WHERE event_type = 'LOGIN_FAILED'),
    'rate_limited', (SELECT count(*) FROM public.security_events WHERE event_type = 'RATE_LIMITED'),
    'total_events', (SELECT count(*) FROM public.security_events),
    'admins', (SELECT count(*) FROM public.user_roles WHERE role = 'ADMIN'),
    'events_last_7_days', (
      SELECT COALESCE(json_agg(row_to_json(d) ORDER BY d.day), '[]'::json) FROM (
        SELECT to_char(date_trunc('day', created_at), 'Mon DD') AS day,
               count(*) FILTER (WHERE event_type = 'LOGIN_SUCCESS') AS success,
               count(*) FILTER (WHERE event_type = 'LOGIN_FAILED') AS failed
        FROM public.security_events
        WHERE created_at > now() - interval '7 days'
        GROUP BY date_trunc('day', created_at)
      ) d
    )
  ) INTO result;
  RETURN result;
END;
$$;
REVOKE ALL ON FUNCTION public.admin_stats() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.admin_stats() TO authenticated;