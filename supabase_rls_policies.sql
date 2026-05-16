-- WARNING: This schema is for context only and is not meant to be run.
-- Table order and constraints may not be valid for execution.

CREATE TABLE public.auth_codes (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  authorization_code text NOT NULL UNIQUE,
  user_id text NOT NULL,
  code_challenge text NOT NULL,
  redirect_uri text NOT NULL,
  expires_at timestamp with time zone NOT NULL,
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT auth_codes_pkey PRIMARY KEY (id)
);
CREATE TABLE public.connections (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  initiator_user_id text NOT NULL,
  target_user_id text NOT NULL,
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT connections_pkey PRIMARY KEY (id)
);
CREATE TABLE public.devices (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  user_id text NOT NULL,
  device_name text NOT NULL,
  public_hik text NOT NULL,
  is_active boolean DEFAULT true,
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT devices_pkey PRIMARY KEY (id)
);
CREATE TABLE public.key_broker (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  owner_user_id text NOT NULL,
  target_device_id uuid,
  wrapped_pnk text NOT NULL,
  version integer DEFAULT 1,
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT key_broker_pkey PRIMARY KEY (id),
  CONSTRAINT key_broker_target_device_id_fkey FOREIGN KEY (target_device_id) REFERENCES public.devices(id)
);