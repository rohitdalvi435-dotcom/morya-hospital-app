# Morya Balrugnaly App — starter package

## Included
- `index.html`: mobile-friendly front-end shell and department navigation.
- `supabase_setup.sql`: separate `app_*` tables and starter role-based RLS policies.
- This package does **not** delete or modify the old 19 tables.

## Important safety limits
This is a starter, not a production-ready hospital system. Do not enter real patient information until:
1. A developer reviews and tests every RLS policy with separate test accounts for each role.
2. Authentication, password reset, staff onboarding, patient portal identity verification, audit logging, secure file storage, backup/restore and consent flows are completed.
3. Clinical workflows are reviewed by the responsible doctor. The app must never calculate/prescribe a pediatric dose autonomously.
4. The medical shop vendor confirms an official API/integration or safe export method. Never share the vendor's password or API secret in chat or frontend code.

## Supabase setup
Run `supabase_setup.sql` only in the intended Supabase project's SQL Editor after taking a backup. The SQL creates new `app_*` tables and does not drop old tables. It does not create the first `main_doctor` profile automatically. A trusted administrator must create the first staff profile securely after verifying the Auth user ID. Never expose the service-role key in browser code.

## GitHub Pages
GitHub Pages can host the static front-end, but it is not a secure backend and must never contain patient records, secrets, service-role keys, or private exports. The current `index.html` is only a UI shell; login and data features are not connected yet.
