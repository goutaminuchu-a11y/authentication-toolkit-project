/**
 * Password policy + strength analysis.
 * Shared by the browser (live feedback) and the server (authoritative validation).
 * Nothing here stores or transmits a password.
 */

export type PasswordAnalysis = {
  length: number;
  hasMinLength: boolean;
  hasUppercase: boolean;
  hasLowercase: boolean;
  hasNumber: boolean;
  hasSpecial: boolean;
  hasCommonPattern: boolean;
  satisfied: number;
  level: 0 | 1 | 2 | 3 | 4;
  label: "Very Weak" | "Weak" | "Medium" | "Strong" | "Very Strong";
  valid: boolean;
  recommendations: string[];
};

const COMMON_PATTERNS = [
  "password",
  "123456",
  "qwerty",
  "admin",
  "letmein",
  "welcome",
  "iloveyou",
  "abc123",
  "111111",
];

export const POLICY_TEXT = [
  "At least 8 characters",
  "An uppercase letter",
  "A lowercase letter",
  "A number",
  "A special character",
];

export function analyzePassword(password: string): PasswordAnalysis {
  const lower = password.toLowerCase();
  const hasMinLength = password.length >= 8;
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecial = /[^A-Za-z0-9]/.test(password);
  const hasCommonPattern =
    password.length > 0 && COMMON_PATTERNS.some((p) => lower.includes(p));

  const satisfied = [hasMinLength, hasUppercase, hasLowercase, hasNumber, hasSpecial].filter(
    Boolean,
  ).length;

  let raw = satisfied;
  if (password.length >= 12) raw += 1;
  if (password.length >= 16) raw += 1;
  if (hasCommonPattern) raw -= 2;
  if (password.length === 0) raw = 0;

  const level = Math.max(0, Math.min(4, raw - 1)) as 0 | 1 | 2 | 3 | 4;
  const labels = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"] as const;

  const recommendations: string[] = [];
  if (!hasMinLength) recommendations.push("Increase the length to at least 8 characters");
  else if (password.length < 12) recommendations.push("Increase length — 12+ characters is stronger");
  if (!hasUppercase) recommendations.push("Add uppercase characters");
  if (!hasLowercase) recommendations.push("Add lowercase characters");
  if (!hasNumber) recommendations.push("Add numbers");
  if (!hasSpecial) recommendations.push("Add symbols such as ! @ # $ %");
  if (hasCommonPattern) recommendations.push("Avoid common patterns and dictionary words");

  return {
    length: password.length,
    hasMinLength,
    hasUppercase,
    hasLowercase,
    hasNumber,
    hasSpecial,
    hasCommonPattern,
    satisfied,
    level,
    label: labels[level] ?? "Very Weak",
    valid: satisfied === 5 && !hasCommonPattern,
    recommendations,
  };
}
