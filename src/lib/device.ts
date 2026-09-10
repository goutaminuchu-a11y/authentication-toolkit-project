/** Best-effort browser/OS labels from a user-agent string (display only). */
export function parseUserAgent(ua: string | undefined | null) {
  const s = ua ?? "";
  const browser = /Edg\//.test(s)
    ? "Edge"
    : /OPR\//.test(s)
      ? "Opera"
      : /Chrome\//.test(s)
        ? "Chrome"
        : /Firefox\//.test(s)
          ? "Firefox"
          : /Safari\//.test(s)
            ? "Safari"
            : "Unknown browser";

  const os = /Windows/.test(s)
    ? "Windows"
    : /Android/.test(s)
      ? "Android"
      : /iPhone|iPad/.test(s)
        ? "iOS"
        : /Mac OS X/.test(s)
          ? "macOS"
          : /Linux/.test(s)
            ? "Linux"
            : "Unknown OS";

  return { browser, os };
}

const DEVICE_KEY = "secureauth.device-id";

/**
 * Non-secret identifier for this browser, used only to label session rows.
 * It is not an authentication credential and grants no access on its own.
 */
export function getDeviceId(): string {
  if (typeof window === "undefined") return "server";
  let id = window.localStorage.getItem(DEVICE_KEY);
  if (!id) {
    id = crypto.randomUUID();
    window.localStorage.setItem(DEVICE_KEY, id);
  }
  return id;
}
