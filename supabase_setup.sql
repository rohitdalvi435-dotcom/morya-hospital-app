-- Morya Balrugnaly: सुरक्षित backend साठी प्रारंभिक schema
-- हा SQL जुन्या tables delete/overwrite करत नाही. आधी Supabase चे backup घ्या.
-- Production मध्ये वापरण्यापूर्वी डॉक्टर/administrator आणि developer ने review करणे आवश्यक.

create extension if not exists pgcrypto;

create table if not exists public.app_staff_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null,
  role text not null check (role in ('main_doctor','doctor','nurse','receptionist','medical_staff')),
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.app_patients (
  id uuid primary key default gen_random_uuid(),
  patient_code text unique not null,
  full_name text not null,
  date_of_birth date,
  sex text,
  primary_mobile text,
  guardian_name text,
  created_at timestamptz not null default now(),
  created_by uuid references auth.users(id)
);

create table if not exists public.app_patient_contacts (
  id uuid primary key default gen_random_uuid(),
  patient_id uuid not null references public.app_patients(id) on delete cascade,
  mobile text not null,
  relation text,
  verified_at timestamptz,
  created_at timestamptz not null default now(),
  unique(patient_id,mobile)
);

create table if not exists public.app_encounters (
  id uuid primary key default gen_random_uuid(),
  patient_id uuid not null references public.app_patients(id) on delete cascade,
  encounter_type text not null check (encounter_type in ('OPD','IPD')),
  encounter_at timestamptz not null default now(),
  doctor_id uuid references auth.users(id),
  diagnosis text,
  clinical_notes text,
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now()
);

create table if not exists public.app_medicine_catalog (
  id uuid primary key default gen_random_uuid(),
  generic_name text not null,
  brand_name text,
  strength text,
  dosage_form text,
  concentration text,
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.app_prescriptions (
  id uuid primary key default gen_random_uuid(),
  patient_id uuid not null references public.app_patients(id) on delete cascade,
  encounter_id uuid references public.app_encounters(id) on delete set null,
  medicine_id uuid references public.app_medicine_catalog(id),
  medicine_text text not null,
  dose_text text not null,
  route text,
  frequency text,
  duration_text text,
  instructions text,
  prescribed_by uuid not null references auth.users(id),
  approved_by uuid references auth.users(id),
  approved_at timestamptz,
  status text not null default 'draft' check (status in ('draft','approved','cancelled')),
  created_at timestamptz not null default now(),
  check ((status <> 'approved') or (approved_by is not null and approved_at is not null))
);

create table if not exists public.app_bills (
  id uuid primary key default gen_random_uuid(),
  patient_id uuid not null references public.app_patients(id) on delete cascade,
  bill_number text unique not null,
  bill_type text not null check (bill_type in ('OPD','IPD','MEDICINE','LAB')),
  total_amount numeric(12,2) not null check (total_amount >= 0),
  paid_amount numeric(12,2) not null default 0 check (paid_amount >= 0),
  status text not null default 'pending' check (status in ('pending','partial','paid')),
  created_at timestamptz not null default now(),
  created_by uuid references auth.users(id),
  check (paid_amount <= total_amount)
);

create table if not exists public.app_appointments (
  id uuid primary key default gen_random_uuid(),
  patient_id uuid not null references public.app_patients(id) on delete cascade,
  doctor_id uuid references auth.users(id),
  scheduled_at timestamptz not null,
  status text not null default 'booked' check (status in ('booked','completed','cancelled','missed')),
  notes text,
  created_at timestamptz not null default now()
);

create table if not exists public.app_followups (
  id uuid primary key default gen_random_uuid(),
  patient_id uuid not null references public.app_patients(id) on delete cascade,
  doctor_id uuid references auth.users(id),
  due_at timestamptz not null,
  message text,
  status text not null default 'scheduled' check (status in ('scheduled','sent','completed','cancelled')),
  created_at timestamptz not null default now()
);

create table if not exists public.app_audit_log (
  id bigint generated always as identity primary key,
  actor_id uuid references auth.users(id),
  action text not null,
  table_name text not null,
  record_id text,
  created_at timestamptz not null default now()
);

-- Role helper. Security-definer function avoids recursive RLS checks on staff profile.
create or replace function public.app_my_role()
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select role from public.app_staff_profiles
  where user_id = (select auth.uid()) and active = true
  limit 1;
$$;

revoke all on function public.app_my_role() from public;
grant execute on function public.app_my_role() to authenticated;

alter table public.app_staff_profiles enable row level security;
alter table public.app_patients enable row level security;
alter table public.app_patient_contacts enable row level security;
alter table public.app_encounters enable row level security;
alter table public.app_medicine_catalog enable row level security;
alter table public.app_prescriptions enable row level security;
alter table public.app_bills enable row level security;
alter table public.app_appointments enable row level security;
alter table public.app_followups enable row level security;
alter table public.app_audit_log enable row level security;

-- Main doctor and staff can read staff list; only main doctor can manage roles.
drop policy if exists "staff read profiles" on public.app_staff_profiles;
create policy "staff read profiles" on public.app_staff_profiles
for select to authenticated
using (public.app_my_role() in ('main_doctor','doctor','nurse','receptionist','medical_staff'));

drop policy if exists "main doctor manage profiles" on public.app_staff_profiles;
create policy "main doctor manage profiles" on public.app_staff_profiles
for all to authenticated
using (public.app_my_role() = 'main_doctor')
with check (public.app_my_role() = 'main_doctor');

-- Patient records: main doctor/doctor/nurse/receptionist. Medical staff excluded.
drop policy if exists "clinical staff read patients" on public.app_patients;
create policy "clinical staff read patients" on public.app_patients
for select to authenticated
using (public.app_my_role() in ('main_doctor','doctor','nurse','receptionist'));

drop policy if exists "authorized staff add patients" on public.app_patients;
create policy "authorized staff add patients" on public.app_patients
for insert to authenticated
with check (public.app_my_role() in ('main_doctor','doctor','receptionist'));

drop policy if exists "main doctor update patients" on public.app_patients;
create policy "main doctor update patients" on public.app_patients
for update to authenticated
using (public.app_my_role() = 'main_doctor')
with check (public.app_my_role() = 'main_doctor');

-- Related clinical records.
do $$
declare t text;
begin
  foreach t in array array['app_patient_contacts','app_encounters','app_prescriptions','app_appointments','app_followups'] loop
    execute format('drop policy if exists "clinical read %1$s" on public.%1$s', t);
    execute format('create policy "clinical read %1$s" on public.%1$s for select to authenticated using (public.app_my_role() in (''main_doctor'',''doctor'',''nurse'',''receptionist''))', t);
    execute format('drop policy if exists "clinical write %1$s" on public.%1$s', t);
    execute format('create policy "clinical write %1$s" on public.%1$s for all to authenticated using (public.app_my_role() in (''main_doctor'',''doctor'')) with check (public.app_my_role() in (''main_doctor'',''doctor''))', t);
  end loop;
end $$;

-- Pharmacy catalog visible to clinical + medical staff; only main doctor manages it.
drop policy if exists "staff read medicine catalog" on public.app_medicine_catalog;
create policy "staff read medicine catalog" on public.app_medicine_catalog
for select to authenticated
using (public.app_my_role() in ('main_doctor','doctor','nurse','medical_staff'));

drop policy if exists "main doctor manage medicine catalog" on public.app_medicine_catalog;
create policy "main doctor manage medicine catalog" on public.app_medicine_catalog
for all to authenticated
using (public.app_my_role() = 'main_doctor')
with check (public.app_my_role() = 'main_doctor');

-- Only main doctor/doctor may read/write bills; receptionist may read and add bills.
drop policy if exists "authorized staff read bills" on public.app_bills;
create policy "authorized staff read bills" on public.app_bills
for select to authenticated
using (public.app_my_role() in ('main_doctor','doctor','receptionist'));

drop policy if exists "authorized staff add bills" on public.app_bills;
create policy "authorized staff add bills" on public.app_bills
for insert to authenticated
with check (public.app_my_role() in ('main_doctor','doctor','receptionist'));

drop policy if exists "main doctor update bills" on public.app_bills;
create policy "main doctor update bills" on public.app_bills
for update to authenticated
using (public.app_my_role() = 'main_doctor')
with check (public.app_my_role() = 'main_doctor');

-- Audit logs are visible only to the main doctor. No client insert policy is granted here.
drop policy if exists "main doctor read audit log" on public.app_audit_log;
create policy "main doctor read audit log" on public.app_audit_log
for select to authenticated
using (public.app_my_role() = 'main_doctor');

-- Important: do not grant anon access. Patient portal access and pharmacy integration
-- require separate, reviewed policies and should not be opened by broad public rules.
