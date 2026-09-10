# SecureAuth Gateway

BUILD A COMPLETE FULL-STACK APPLICATION

Build a complete, production-quality academic prototype called:

SecureAuth Toolkit

Cybersecurity Authentication & Security Control Platform

This is NOT a static frontend project.

I need a genuinely functional full-stack application with:

Frontend

Backend

Database

Real authentication

Secure password hashing

Session management

Role-based authorization

Password strength checking

Rate limiting

Security event logging

Protected routes

Security dashboard

Admin monitoring

Every button, form, dashboard statistic, authentication state, session state, and security event shown in the UI must come from real application logic.

DO NOT create fake/mock authentication.

DO NOT use fake dashboard statistics.

DO NOT use hardcoded users for normal operation.

1. TECHNOLOGY

Use Lovable's recommended full-stack architecture.

Frontend:

React

TypeScript

Tailwind CSS

shadcn/ui

React Router

TanStack Query where useful

Backend:

Use Lovable's supported backend/database architecture.

Use Supabase for database and authentication infrastructure if available.

Use server-side/Edge Functions for security-sensitive operations that cannot safely run in the browser.

Database:

PostgreSQL/Supabase

Security:

Secure password authentication

Proper password hashing

HTTP-only/session-based authentication where supported

Row Level Security

Rate limiting for sensitive endpoints

Server-side validation

Security event logging

Role-based authorization

Do not add unnecessary dependencies.

Keep the architecture simple enough for a student to understand and explain.

2. VERY IMPORTANT SECURITY RULE

Do NOT implement a fake authentication system using:

localStorage user objects

hardcoded passwords

frontend-only authentication

fake JWT strings

mock API responses

static JSON users

client-side-only authorization

Authentication and authorization must be enforced by the backend/database.

The frontend only displays the authenticated state returned by the backend.

3. APPLICATION USERS

Support two roles:

USER
ADMIN

Normal users can:

Register

Login

View dashboard

Check password strength

View their sessions

Change password

Logout

View their own security activity

Admins can additionally:

View system statistics

View registered users

View authentication events

View failed login activity

View active sessions

Monitor security controls

Never allow a normal USER to access admin functionality merely by manipulating frontend state.

Admin authorization must be enforced server-side/database-side.

4. DATABASE

Create the necessary database tables.

profiles

Fields:

id

full_name

email

role

created_at

updated_at

Role:

USER or ADMIN

security_events

Fields:

id

user_id nullable

event_type

description

ip_address where safely available

user_agent where appropriate

created_at

Possible event types:

REGISTER
LOGIN_SUCCESS
LOGIN_FAILED
LOGOUT
PASSWORD_CHANGED
RATE_LIMITED
SESSION_CREATED
SESSION_REVOKED

NEVER store:

plaintext passwords

password hashes

session secrets

authentication tokens

sessions

If the chosen authentication architecture provides session management, integrate with it rather than creating an insecure duplicate.

Expose only safe session information to the frontend.

Possible display information:

device/browser

created time

last active time

expiration

current session

5. ROW LEVEL SECURITY

If using Supabase:

Enable Row Level Security.

Users must only be able to access their own:

profile information

sessions

security events

Admins can access appropriate monitoring information.

Do not simply enable RLS and then create policies that allow everyone to read everything.

Test the policies.

6. LANDING PAGE

Route:

/

Create a clean professional cybersecurity landing page.

Brand:

SecureAuth Toolkit

Subtitle:

"Secure Authentication & Cybersecurity Demonstration Platform"

Short description:

"A full-stack authentication toolkit demonstrating secure password protection, authentication, session management, authorization, and security monitoring."

Show 5 feature cards:

Secure Registration

Password Security

Authentication

Session Management

Security Monitoring

Buttons:

Create Account
Login

Add a small security architecture section:

User
↓
Authentication
↓
Session
↓
Protected API
↓
Database

Do not use cheesy hacker graphics or excessive neon effects.

7. REGISTRATION

Route:

/register

Fields:

Full Name
Email
Password
Confirm Password

Real-time password strength indicator.

Requirements:

At least 8 characters

Uppercase

Lowercase

Number

Special character

Display:

Very Weak
Weak
Medium
Strong
Very Strong

Use a visual strength meter.

Validation must happen:

Client side

Server side

Registration must actually create a user account.

After successful registration:

Create profile

Assign USER role by default

Record REGISTER event

Redirect to login

Never allow the client to select ADMIN during registration.

8. LOGIN

Route:

/login

Fields:

Email
Password

Features:

Show/hide password

Remember-me only if implemented securely

Login button

Link to registration

On successful login:

Establish authenticated session

Record LOGIN_SUCCESS

Redirect to dashboard

On failure:

Show only:

"Invalid email or password."

Do NOT say:

"Email doesn't exist."

Do NOT say:

"Wrong password."

This prevents account enumeration.

Record failed authentication events without storing the password.

9. AUTHENTICATED DASHBOARD

Route:

/dashboard

This must be protected.

If the user is not authenticated:

redirect to /login.

Dashboard should display real data.

Header:

Welcome, [User Name]

Cards:

Authentication
● Active

Password Security
● Protected

Session
● Active

Account Role
● USER / ADMIN

Security score:

Calculate the score from actual security controls.

Do NOT simply hardcode "100".

10. SECURITY DASHBOARD

Route:

/security

Create a professional security-control dashboard.

Display:

Password Protection

Status: ENABLED

Description:

"Passwords are protected using secure password authentication mechanisms and are never exposed in the application interface."

Authentication

Status: ENABLED

Description:

"User credentials are verified before an authenticated session is established."

Session Protection

Status: ENABLED

Description:

"Authenticated access is maintained using secure session mechanisms."

Input Validation

Status: ENABLED

Description:

"Authentication input is validated before processing."

Rate Limiting

Status: ENABLED

Description:

"Repeated authentication attempts are restricted to reduce brute-force attacks."

Authorization

Status: ENABLED

Description:

"Protected resources require appropriate authentication and role permissions."

Database Security

Status: ENABLED

Description:

"Database access is protected using row-level access policies."

11. PASSWORD LAB

Route:

/password-lab

This is an educational tool.

User can enter a demonstration password.

Display:

Password strength
Length
Uppercase
Lowercase
Number
Special character

Recommendations:

Increase length

Add uppercase characters

Add numbers

Add symbols

Avoid common patterns

Important:

The password entered here must NOT be stored.

Prefer performing password-strength analysis entirely in the browser.

Add educational explanation:

"Password strength checking is performed locally for this demonstration. Passwords entered here are not stored."

12. HASHING / PASSWORD SECURITY PAGE

Route:

/hash-demo

Create an educational visualization:

Password
↓
Secure Password Hashing
↓
Password Hash
↓
Database

Explain:

Passwords should never be stored as plaintext.

Password hashing is different from encryption.

Hashing is designed to be one-way.

Unique salts protect against precomputed attacks.

Password verification compares a supplied password against the stored password representation.

Do NOT expose real user password hashes.

Do NOT show the current user's password.

If the demo allows an example password, clearly label it:

"Educational demonstration only."

13. CHANGE PASSWORD

Route:

/change-password

Fields:

Current Password
New Password
Confirm New Password

Requirements:

User must be authenticated.

Current password must be verified.

New password must satisfy strength requirements.

New password must not be returned or displayed.

Record PASSWORD_CHANGED.

After changing the password:

Invalidate existing sessions where appropriate and require re-authentication.

14. SESSION MANAGEMENT

Route:

/sessions

Display the user's active sessions.

Example:

Current Session
Chrome • Windows
Active

Other Session
Edge • Windows
Last active: 20 minutes ago

Actions:

Logout Current Session
Logout All Sessions

All session changes must be processed by the backend/authentication system.

Do not fake session data.

15. SECURITY ACTIVITY

Route:

/security-log

Show the current user's security events.

Examples:

Successful login
Failed login
Logout
Password changed
Session created

Display:

Event
Date
Time
Status

Users must only see their own events.

16. ADMIN DASHBOARD

Route:

/admin

ONLY ADMIN users can access this page.

Enforce admin access on the backend/database layer.

Dashboard cards:

Total Users
Active Sessions
Successful Logins
Failed Logins
Rate Limited Attempts
Security Events

Use REAL database queries.

Do not use fake numbers.

Add charts if useful, but keep them simple.

17. ADMIN USER MANAGEMENT

Route:

/admin/users

Display:

Name

Email

Role

Account creation date

Status

Do not expose:

password

password hash

session token

sensitive authentication information

Allow only safe administrative actions.

Do not build unnecessary destructive functionality.

18. ADMIN SECURITY LOG

Route:

/admin/security-events

Display recent system authentication/security events.

Filters:

Event type
Date
User
Success/Failure

Example event types:

LOGIN_SUCCESS
LOGIN_FAILED
REGISTER
LOGOUT
PASSWORD_CHANGED
RATE_LIMITED

Use pagination.

Do not expose passwords or secrets.

19. RATE LIMITING

Protect login and other sensitive authentication operations.

Example:

Limit repeated login attempts from the same source over a short period.

When triggered:

HTTP 429

Message:

"Too many authentication attempts. Please try again later."

Do not reveal whether an account exists.

Implement this on the backend/server side.

Do not implement rate limiting only in React.

20. SECURITY HEADERS

Where the deployment architecture allows it, configure appropriate security headers.

Use sensible protections against:

clickjacking

MIME sniffing

unsafe framing

insecure content loading

Do not claim a security control is active in the UI unless it is actually configured.

21. AUTHENTICATION STATE

Create a reusable authentication context/hook.

It should provide:

user
loading
isAuthenticated
isAdmin
login
logout
refreshUser

Avoid duplicating authentication logic across pages.

22. PROTECTED ROUTES

Create:

ProtectedRoute

and:

AdminRoute

Behavior:

Unauthenticated:

→ /login

Authenticated USER:

→ allowed user pages

Authenticated ADMIN:

→ allowed user + admin pages

USER attempting:

/admin

→ access denied

Do not rely solely on hiding the admin navigation item.

23. NAVIGATION

Authenticated layout:

Sidebar:

Dashboard
Password Lab
Hash Demo
Sessions
Security Activity
Security Controls
Change Password

Admin section:

Admin Dashboard
Users
Security Events

Bottom:

Profile
Logout

On mobile:

Use responsive navigation.

24. UI DESIGN

Use a professional modern cybersecurity SaaS style.

Design principles:

Minimal

Clean

Professional

Strong typography

Excellent spacing

Clear cards

Subtle borders

Neutral background

Accessible contrast

Small amount of accent color

Responsive

Avoid:

Matrix rain

Excessive neon

Hacker skulls

Overly dramatic gradients

Excessive animations

Fake terminal screens

Clutter

The project should look like a serious security product, not a gaming website.

25. STATUS INDICATORS

Use consistent indicators:

✓ Enabled
✓ Protected
✓ Active

For failures:

× Failed
⚠ Warning

Use accessible labels in addition to color.

26. ERROR STATES

Every API operation must have:

loading state

success state

error state

Examples:

Registration failure
Login failure
Network error
Unauthorized
Forbidden
Rate limited

Never show raw backend/database errors to users.

27. EMPTY STATES

Create useful empty states.

Example:

"No security events yet."

"No active sessions found."

Do not leave blank screens.

28. SECURITY PRINCIPLES

Follow these rules throughout the application:

NEVER:

Store plaintext passwords.

Put passwords into logs.

Expose password hashes.

Put secrets in frontend source code.

Put service-role keys in frontend code.

Trust role information supplied by the client.

Trust frontend-only authorization.

Use localStorage as the authentication mechanism.

Use fake authentication.

Use hardcoded production credentials.

Expose database credentials.

29. ENVIRONMENT VARIABLES

Use environment variables for secrets/configuration.

Create:

.env.example

Never expose privileged server-side secrets to the browser.

If using Supabase:

Public client configuration may be used where appropriate.

Service-role credentials MUST remain server-side.

30. DATABASE SECURITY

Implement proper policies.

Test:

USER A cannot read USER B's private security activity.

USER cannot modify their role to ADMIN.

USER cannot access admin data.

USER cannot directly manipulate protected fields.

ADMIN can access authorized monitoring data.

31. SECURITY SCORE

Create a calculated security score based on implemented controls.

Example categories:

Authentication
Password Security
Session Security
Authorization
Input Validation
Rate Limiting
Database Security

Display:

Security Score
92/100

But calculate it from actual configuration/status.

Never hardcode the score just to make the dashboard look impressive.

32. DEMO MODE / SEED ADMIN

Create a safe development/seed process for an administrator.

Do not allow public registration to select ADMIN.

Document how the developer can create the initial admin account.

Keep demo credentials outside source code where possible.

33. TESTING

Before considering the project complete, test these flows:

Registration

✓ Valid registration

✓ Duplicate email

✓ Invalid email

✓ Weak password

✓ Password mismatch

Login

✓ Correct credentials

✓ Wrong password

✓ Unknown email

✓ Rate limiting

Authorization

✓ USER can access dashboard

✓ USER cannot access admin

✓ ADMIN can access admin

✓ Unauthenticated user cannot access dashboard

Sessions

✓ Login creates session

✓ Logout invalidates session

✓ Protected route fails after logout

✓ Logout all sessions works

Password

✓ Password strength checker works

✓ Password change works

✓ Old password must be correct

✓ New password meets requirements

Security

✓ Passwords are not exposed

✓ Password hashes are not exposed

✓ Secrets are not exposed

✓ RLS/policies work

✓ Security events are generated

34. README

Create a README containing:

Project overview
Features
Architecture
Technology stack
Database schema
Authentication flow
Security controls
Environment setup
Local development
Testing
Deployment considerations
Known limitations
Future improvements

Also include a simple architecture diagram using Markdown.

35. PROJECT DEMONSTRATION FLOW

Make the application suitable for a 5–10 minute college demonstration.

I should be able to demonstrate:

Register user

Show password strength

Login

Open dashboard

Show security controls

Show session

Show security event

Attempt invalid login

Show failed-login event

Demonstrate rate limiting

Change password

Logout

Show protected route blocking

Login as admin

Show security monitoring dashboard

36. PERFORMANCE

Keep the application lightweight.

Avoid unnecessary:

animations

API calls

dependencies

database queries

duplicated components

Use caching/query management where useful.

Paginate large tables.

37. FINAL QUALITY REQUIREMENT

Before finishing:

Run/build the frontend.

Check all routes.

Check all forms.

Check database connectivity.

Check authentication.

Check authorization.

Check session behavior.

Check security events.

Check admin access.

Check responsive design.

Fix all TypeScript errors.

Fix all runtime errors.

Remove mock data.

Remove placeholder content.

Remove unused dependencies.

Remove fake security claims.

Verify that every dashboard statistic comes from actual data.

Do NOT tell me that something works if you did not actually implement it.

IMPORTANT LOVABLE INSTRUCTION

Do not rebuild the entire application unnecessarily if parts already exist.

If a component or feature is already correct, reuse it.

When fixing bugs, make the smallest necessary change.

Prioritize:

FUNCTIONALITY
SECURITY
CORRECTNESS
SIMPLICITY
UI QUALITY

in that order.

The final result must be a genuinely working full-stack cybersecurity authentication prototype, not a visual mockup.

START IMPLEMENTING NOW.

This project was built with [Lovable](https://lovable.dev).

**Live app**: https://authshield-pro.lovable.app

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/45b4cf2f-3d46-4f5d-9f62-7ceb5251c7a2).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
