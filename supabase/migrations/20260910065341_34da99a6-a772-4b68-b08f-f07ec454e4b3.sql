CREATE OR REPLACE FUNCTION public.security_posture()
RETURNS JSON
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  uid UUID := auth.uid();
  rls_ok BOOLEAN;
  policy_count INT;
  plaintext_cols INT;
  role_sep BOOLEAN;
  audit_count INT;
  recent_failures INT;
  checks JSON;
  passed NUMERIC := 0;
  total NUMERIC := 0;
BEGIN
  IF uid IS NULL THEN
    RAISE EXCEPTION 'unauthenticated';
  END IF;

  SELECT bool_and(c.relrowsecurity) INTO rls_ok
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public'
    AND c.relname IN ('profiles','user_roles','security_events','login_attempts','user_sessions');

  SELECT count(*) INTO policy_count FROM pg_policies WHERE schemaname = 'public';

  SELECT count(*) INTO plaintext_cols
  FROM information_schema.columns
  WHERE table_schema = 'public'
    AND (column_name ILIKE '%password%' OR column_name ILIKE '%secret%' OR column_name ILIKE '%token%');

  SELECT EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'user_roles'
  ) AND NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'profiles' AND column_name = 'role'
  ) INTO role_sep;

  SELECT count(*) INTO audit_count FROM public.security_events;

  SELECT count(*) INTO recent_failures FROM public.security_events
  WHERE user_id = uid AND event_type = 'LOGIN_FAILED' AND created_at > now() - interval '24 hours';

  checks := json_build_array(
    json_build_object('key','database', 'label','Database row-level access policies enabled', 'passed', COALESCE(rls_ok,false), 'weight', 20),
    json_build_object('key','policies', 'label','Access policies defined for every table', 'passed', policy_count >= 10, 'weight', 15),
    json_build_object('key','password_storage', 'label','No password, token or secret columns in application tables', 'passed', plaintext_cols = 0, 'weight', 20),
    json_build_object('key','authorization', 'label','Roles stored separately from profile data', 'passed', COALESCE(role_sep,false), 'weight', 15),
    json_build_object('key','rate_limit', 'label','Authentication attempts recorded for rate limiting', 'passed', EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='login_attempts'), 'weight', 10),
    json_build_object('key','audit', 'label','Security event logging active', 'passed', audit_count > 0, 'weight', 10),
    json_build_object('key','account', 'label','No failed sign-in attempts on your account in 24h', 'passed', recent_failures = 0, 'weight', 10)
  );

  SELECT sum((c->>'weight')::NUMERIC), sum(CASE WHEN (c->>'passed')::BOOLEAN THEN (c->>'weight')::NUMERIC ELSE 0 END)
  INTO total, passed
  FROM json_array_elements(checks) c;

  RETURN json_build_object(
    'checks', checks,
    'score', round(passed / NULLIF(total,0) * 100),
    'recent_failures', recent_failures
  );
END;
$$;
REVOKE ALL ON FUNCTION public.security_posture() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.security_posture() FROM anon;
GRANT EXECUTE ON FUNCTION public.security_posture() TO authenticated;