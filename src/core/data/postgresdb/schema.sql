-- Goiabada PostgreSQL Schema
-- This file represents the current database schema after all migrations.
-- Generated from migrations, not intended for direct execution in production.
-- Use migrations for schema changes.
--
-- PostgreSQL database dump
--


-- Dumped from database version 18.1 (Debian 18.1-1.pgdg13+2)
-- Dumped by pg_dump version 18.1

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: clients; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.clients (
    id bigint NOT NULL,
    created_at timestamp(6) without time zone,
    updated_at timestamp(6) without time zone,
    client_identifier character varying(40) NOT NULL,
    client_secret_encrypted bytea,
    description character varying(128),
    website_url character varying(256) NOT NULL DEFAULT '',
    display_name VARCHAR(100) NOT NULL DEFAULT '',
    enabled boolean NOT NULL,
    consent_required boolean NOT NULL,
    show_logo BOOLEAN NOT NULL DEFAULT FALSE,
    show_display_name BOOLEAN NOT NULL DEFAULT FALSE,
    show_description BOOLEAN NOT NULL DEFAULT FALSE,
    show_website_url BOOLEAN NOT NULL DEFAULT FALSE,
    is_public boolean NOT NULL,
    authorization_code_enabled boolean NOT NULL,
    client_credentials_enabled boolean NOT NULL,
    token_expiration_in_seconds integer NOT NULL,
    refresh_token_offline_idle_timeout_in_seconds integer NOT NULL,
    refresh_token_offline_max_lifetime_in_seconds integer NOT NULL,
    include_open_id_connect_claims_in_access_token character varying(16) NOT NULL,
    default_acr_level character varying(128) NOT NULL,
    pkce_required boolean,
    implicit_grant_enabled boolean,
    resource_owner_password_credentials_enabled boolean,
    include_open_id_connect_claims_in_id_token character varying(10) DEFAULT 'default'::character varying NOT NULL
);


--
-- Name: clients_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.clients_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: clients_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.clients_id_seq OWNED BY public.clients.id;


--
-- Name: clients_permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.clients_permissions (
    id bigint NOT NULL,
    created_at timestamp(6) without time zone,
    updated_at timestamp(6) without time zone,
    client_id bigint NOT NULL,
    permission_id bigint NOT NULL
);


--
-- Name: clients_permissions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.clients_permissions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: clients_permissions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.clients_permissions_id_seq OWNED BY public.clients_permissions.id;


--
-- Name: codes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.codes (
    id bigint NOT NULL,
    created_at timestamp(6) without time zone,
    updated_at timestamp(6) without time zone,
    code_hash character varying(64) NOT NULL,
    client_id bigint NOT NULL,
    code_challenge character varying(256),
    code_challenge_method character varying(10),
    scope character varying(512) NOT NULL,
    state character varying(512) NOT NULL,
    nonce character varying(512) NOT NULL,
    redirect_uri character varying(256) NOT NULL,
    user_id bigint NOT NULL,
    ip_address character varying(64) NOT NULL,
    user_agent character varying(512) NOT NULL,
    response_mode character varying(16) NOT NULL,
    authenticated_at timestamp(6) without time zone NOT NULL,
    session_identifier character varying(64) NOT NULL,
    acr_level character varying(128) NOT NULL,
    auth_methods character varying(64) NOT NULL,
    used boolean NOT NULL
);


--
-- Name: codes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.codes_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: codes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.codes_id_seq OWNED BY public.codes.id;


--
-- Name: group_attributes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.group_attributes (
    id bigint NOT NULL,
    created_at timestamp(6) without time zone,
    updated_at timestamp(6) without time zone,
    key character varying(32) NOT NULL,
    value character varying(256) NOT NULL,
    include_in_id_token boolean NOT NULL,
    include_in_access_token boolean NOT NULL,
    group_id bigint NOT NULL
);


--
-- Name: group_attributes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.group_attributes_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: group_attributes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.group_attributes_id_seq OWNED BY public.group_attributes.id;


--
-- Name: groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.groups (
    id bigint NOT NULL,
    created_at timestamp(6) without time zone,
    updated_at timestamp(6) without time zone,
    group_identifier character varying(40) NOT NULL,
    description character varying(128),
    include_in_id_token boolean NOT NULL,
    include_in_access_token boolean NOT NULL
);


--
-- Name: groups_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.groups_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: groups_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.groups_id_seq OWNED BY public.groups.id;


--
-- Name: groups_permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.groups_permissions (
    id bigint NOT NULL,
    created_at timestamp(6) without time zone,
    updated_at timestamp(6) without time zone,
    group_id bigint NOT NULL,
    permission_id bigint NOT NULL
);


--
-- Name: groups_permissions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.groups_permissions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: groups_permissions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.groups_permissions_id_seq OWNED BY public.groups_permissions.id;


--
-- Name: http_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.http_sessions (
    id bigint NOT NULL,
    created_at timestamp(6) without time zone,
    updated_at timestamp(6) without time zone,
    data text,
    expires_on timestamp(6) without time zone
);


--
-- Name: http_sessions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.http_sessions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: http_sessions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.http_sessions_id_seq OWNED BY public.http_sessions.id;


--
-- Name: key_pairs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.key_pairs (
    id bigint NOT NULL,
    created_at timestamp(6) without time zone,
    updated_at timestamp(6) without time zone,
    state character varying(191) NOT NULL,
    key_identifier character varying(64) NOT NULL,
    type character varying(16) NOT NULL,
    algorithm character varying(16) NOT NULL,
    private_key_pem bytea,
    public_key_pem bytea,
    public_key_asn1_der bytea,
    public_key_jwk bytea
);


--
-- Name: key_pairs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.key_pairs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: key_pairs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.key_pairs_id_seq OWNED BY public.key_pairs.id;


--
-- Name: permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.permissions (
    id bigint NOT NULL,
    created_at timestamp(6) without time zone,
    updated_at timestamp(6) without time zone,
    permission_identifier character varying(40) NOT NULL,
    description character varying(128),
    resource_id bigint NOT NULL
);


--
-- Name: permissions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.permissions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: permissions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.permissions_id_seq OWNED BY public.permissions.id;


--
-- Name: pre_registrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.pre_registrations (
    id bigint NOT NULL,
    created_at timestamp(6) without time zone,
    updated_at timestamp(6) without time zone,
    email character varying(64),
    password_hash character varying(64) NOT NULL,
    verification_code_encrypted bytea,
    verification_code_issued_at timestamp(6) without time zone
);


--
-- Name: pre_registrations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.pre_registrations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: pre_registrations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.pre_registrations_id_seq OWNED BY public.pre_registrations.id;


--
-- Name: redirect_uris; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.redirect_uris (
    id bigint NOT NULL,
    created_at timestamp(6) without time zone,
    uri character varying(256) NOT NULL,
    client_id bigint NOT NULL
);


--
-- Name: redirect_uris_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.redirect_uris_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: redirect_uris_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.redirect_uris_id_seq OWNED BY public.redirect_uris.id;


--
-- Name: refresh_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.refresh_tokens (
    id bigint NOT NULL,
    created_at timestamp(6) without time zone,
    updated_at timestamp(6) without time zone,
    code_id bigint,
    user_id bigint,
    client_id bigint,
    refresh_token_jti character varying(64) NOT NULL,
    previous_refresh_token_jti character varying(64) NOT NULL,
    first_refresh_token_jti character varying(64) NOT NULL,
    session_identifier character varying(64) NOT NULL,
    refresh_token_type character varying(16) NOT NULL,
    scope character varying(512) NOT NULL,
    issued_at timestamp(6) without time zone,
    expires_at timestamp(6) without time zone,
    max_lifetime timestamp(6) without time zone,
    revoked boolean NOT NULL
);


--
-- Name: refresh_tokens_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.refresh_tokens_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: refresh_tokens_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.refresh_tokens_id_seq OWNED BY public.refresh_tokens.id;


--
-- Name: resources; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.resources (
    id bigint NOT NULL,
    created_at timestamp(6) without time zone,
    updated_at timestamp(6) without time zone,
    resource_identifier character varying(40) NOT NULL,
    description character varying(128)
);


--
-- Name: resources_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.resources_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: resources_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.resources_id_seq OWNED BY public.resources.id;


--
-- Name: schema_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.schema_migrations (
    version bigint NOT NULL,
    dirty boolean NOT NULL
);


--
-- Name: settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.settings (
    id bigint NOT NULL,
    created_at timestamp(6) without time zone,
    updated_at timestamp(6) without time zone,
    app_name character varying(32) NOT NULL,
    issuer character varying(64) NOT NULL,
    ui_theme character varying(32) NOT NULL,
    password_policy integer,
    self_registration_enabled boolean NOT NULL,
    self_registration_requires_email_verification boolean NOT NULL,
    token_expiration_in_seconds integer NOT NULL,
    refresh_token_offline_idle_timeout_in_seconds integer NOT NULL,
    refresh_token_offline_max_lifetime_in_seconds integer NOT NULL,
    user_session_idle_timeout_in_seconds integer NOT NULL,
    user_session_max_lifetime_in_seconds integer NOT NULL,
    include_open_id_connect_claims_in_access_token boolean CONSTRAINT settings_include_open_id_connect_claims_in_access_toke_not_null NOT NULL,
    aes_encryption_key bytea NOT NULL,
    smtp_host character varying(128),
    smtp_port integer,
    smtp_username character varying(64),
    smtp_password_encrypted bytea,
    smtp_from_name character varying(64),
    smtp_from_email character varying(64),
    smtp_encryption character varying(16),
    smtp_enabled boolean NOT NULL,
    dynamic_client_registration_enabled boolean DEFAULT false NOT NULL,
    pkce_required boolean DEFAULT true NOT NULL,
    implicit_flow_enabled boolean DEFAULT false NOT NULL,
    resource_owner_password_credentials_enabled boolean DEFAULT false NOT NULL,
    include_open_id_connect_claims_in_id_token boolean DEFAULT true NOT NULL
);


--
-- Name: settings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.settings_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: settings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.settings_id_seq OWNED BY public.settings.id;


--
-- Name: user_attributes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_attributes (
    id bigint NOT NULL,
    created_at timestamp(6) without time zone,
    updated_at timestamp(6) without time zone,
    key character varying(32) NOT NULL,
    value character varying(256) NOT NULL,
    include_in_id_token boolean NOT NULL,
    include_in_access_token boolean NOT NULL,
    user_id bigint NOT NULL
);


--
-- Name: user_attributes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.user_attributes_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: user_attributes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.user_attributes_id_seq OWNED BY public.user_attributes.id;


--
-- Name: user_consents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_consents (
    id bigint NOT NULL,
    created_at timestamp(6) without time zone,
    updated_at timestamp(6) without time zone,
    user_id bigint NOT NULL,
    client_id bigint NOT NULL,
    scope character varying(512) NOT NULL,
    granted_at timestamp(6) without time zone
);


--
-- Name: user_consents_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.user_consents_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: user_consents_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.user_consents_id_seq OWNED BY public.user_consents.id;


--
-- Name: user_profile_pictures; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_profile_pictures (
    id bigint NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    user_id bigint NOT NULL,
    picture bytea NOT NULL,
    content_type character varying(64) NOT NULL
);


--
-- Name: user_profile_pictures_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.user_profile_pictures_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: user_profile_pictures_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.user_profile_pictures_id_seq OWNED BY public.user_profile_pictures.id;


--
-- Name: client_logos; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.client_logos (
    id bigint NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    client_id bigint NOT NULL,
    logo bytea NOT NULL,
    content_type character varying(64) NOT NULL
);


--
-- Name: client_logos_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.client_logos_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: client_logos_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.client_logos_id_seq OWNED BY public.client_logos.id;


--
-- Name: user_session_clients; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_session_clients (
    id bigint NOT NULL,
    created_at timestamp(6) without time zone,
    updated_at timestamp(6) without time zone,
    user_session_id bigint NOT NULL,
    client_id bigint NOT NULL,
    started timestamp(6) without time zone NOT NULL,
    last_accessed timestamp(6) without time zone NOT NULL
);


--
-- Name: user_session_clients_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.user_session_clients_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: user_session_clients_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.user_session_clients_id_seq OWNED BY public.user_session_clients.id;


--
-- Name: user_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_sessions (
    id bigint NOT NULL,
    created_at timestamp(6) without time zone,
    updated_at timestamp(6) without time zone,
    session_identifier character varying(64) NOT NULL,
    started timestamp(6) without time zone NOT NULL,
    last_accessed timestamp(6) without time zone NOT NULL,
    auth_methods character varying(64) NOT NULL,
    acr_level character varying(128) NOT NULL,
    auth_time timestamp(6) without time zone NOT NULL,
    ip_address character varying(512) NOT NULL,
    device_name character varying(256) NOT NULL,
    device_type character varying(32) NOT NULL,
    device_os character varying(64) NOT NULL,
    level2_auth_config_has_changed boolean NOT NULL,
    user_id bigint NOT NULL
);


--
-- Name: user_sessions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.user_sessions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: user_sessions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.user_sessions_id_seq OWNED BY public.user_sessions.id;


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id bigint NOT NULL,
    created_at timestamp(6) without time zone,
    updated_at timestamp(6) without time zone,
    enabled boolean NOT NULL,
    subject character varying(64) NOT NULL,
    username character varying(32) NOT NULL,
    given_name character varying(64),
    middle_name character varying(64),
    family_name character varying(64),
    nickname character varying(64),
    website character varying(128),
    gender character varying(16),
    email character varying(64),
    email_verified boolean NOT NULL,
    email_verification_code_encrypted bytea,
    email_verification_code_issued_at timestamp(6) without time zone,
    zone_info_country_name character varying(128),
    zone_info character varying(128),
    locale character varying(32),
    birth_date timestamp(6) without time zone,
    phone_number character varying(32),
    phone_number_country_uniqueid character varying(16),
    phone_number_country_callingcode character varying(16),
    phone_number_verified boolean NOT NULL,
    phone_number_verification_code_encrypted bytea,
    phone_number_verification_code_issued_at timestamp(6) without time zone,
    address_line1 character varying(64),
    address_line2 character varying(64),
    address_locality character varying(64),
    address_region character varying(64),
    address_postal_code character varying(32),
    address_country character varying(32),
    password_hash character varying(64) NOT NULL,
    otp_secret character varying(64),
    otp_enabled boolean NOT NULL,
    forgot_password_code_encrypted bytea,
    forgot_password_code_issued_at timestamp(6) without time zone
);


--
-- Name: users_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users_groups (
    id bigint NOT NULL,
    created_at timestamp(6) without time zone,
    updated_at timestamp(6) without time zone,
    group_id bigint NOT NULL,
    user_id bigint NOT NULL
);


--
-- Name: users_groups_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.users_groups_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: users_groups_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.users_groups_id_seq OWNED BY public.users_groups.id;


--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.users_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: users_permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users_permissions (
    id bigint NOT NULL,
    created_at timestamp(6) without time zone,
    updated_at timestamp(6) without time zone,
    user_id bigint NOT NULL,
    permission_id bigint NOT NULL
);


--
-- Name: users_permissions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.users_permissions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: users_permissions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.users_permissions_id_seq OWNED BY public.users_permissions.id;


--
-- Name: web_origins; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.web_origins (
    id bigint NOT NULL,
    created_at timestamp(6) without time zone,
    origin character varying(256) NOT NULL,
    client_id bigint NOT NULL
);


--
-- Name: web_origins_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.web_origins_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: web_origins_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.web_origins_id_seq OWNED BY public.web_origins.id;


--
-- Name: clients id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.clients ALTER COLUMN id SET DEFAULT nextval('public.clients_id_seq'::regclass);


--
-- Name: clients_permissions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.clients_permissions ALTER COLUMN id SET DEFAULT nextval('public.clients_permissions_id_seq'::regclass);


--
-- Name: codes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.codes ALTER COLUMN id SET DEFAULT nextval('public.codes_id_seq'::regclass);


--
-- Name: group_attributes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_attributes ALTER COLUMN id SET DEFAULT nextval('public.group_attributes_id_seq'::regclass);


--
-- Name: groups id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups ALTER COLUMN id SET DEFAULT nextval('public.groups_id_seq'::regclass);


--
-- Name: groups_permissions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups_permissions ALTER COLUMN id SET DEFAULT nextval('public.groups_permissions_id_seq'::regclass);


--
-- Name: http_sessions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.http_sessions ALTER COLUMN id SET DEFAULT nextval('public.http_sessions_id_seq'::regclass);


--
-- Name: key_pairs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.key_pairs ALTER COLUMN id SET DEFAULT nextval('public.key_pairs_id_seq'::regclass);


--
-- Name: permissions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permissions ALTER COLUMN id SET DEFAULT nextval('public.permissions_id_seq'::regclass);


--
-- Name: pre_registrations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pre_registrations ALTER COLUMN id SET DEFAULT nextval('public.pre_registrations_id_seq'::regclass);


--
-- Name: redirect_uris id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.redirect_uris ALTER COLUMN id SET DEFAULT nextval('public.redirect_uris_id_seq'::regclass);


--
-- Name: refresh_tokens id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens ALTER COLUMN id SET DEFAULT nextval('public.refresh_tokens_id_seq'::regclass);


--
-- Name: resources id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resources ALTER COLUMN id SET DEFAULT nextval('public.resources_id_seq'::regclass);


--
-- Name: settings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.settings ALTER COLUMN id SET DEFAULT nextval('public.settings_id_seq'::regclass);


--
-- Name: user_attributes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_attributes ALTER COLUMN id SET DEFAULT nextval('public.user_attributes_id_seq'::regclass);


--
-- Name: user_consents id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_consents ALTER COLUMN id SET DEFAULT nextval('public.user_consents_id_seq'::regclass);


--
-- Name: user_profile_pictures id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_profile_pictures ALTER COLUMN id SET DEFAULT nextval('public.user_profile_pictures_id_seq'::regclass);


--
-- Name: client_logos id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.client_logos ALTER COLUMN id SET DEFAULT nextval('public.client_logos_id_seq'::regclass);


--
-- Name: user_session_clients id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_session_clients ALTER COLUMN id SET DEFAULT nextval('public.user_session_clients_id_seq'::regclass);


--
-- Name: user_sessions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_sessions ALTER COLUMN id SET DEFAULT nextval('public.user_sessions_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Name: users_groups id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users_groups ALTER COLUMN id SET DEFAULT nextval('public.users_groups_id_seq'::regclass);


--
-- Name: users_permissions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users_permissions ALTER COLUMN id SET DEFAULT nextval('public.users_permissions_id_seq'::regclass);


--
-- Name: web_origins id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.web_origins ALTER COLUMN id SET DEFAULT nextval('public.web_origins_id_seq'::regclass);


--
-- Name: clients_permissions clients_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.clients_permissions
    ADD CONSTRAINT clients_permissions_pkey PRIMARY KEY (id);


--
-- Name: clients clients_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.clients
    ADD CONSTRAINT clients_pkey PRIMARY KEY (id);


--
-- Name: codes codes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.codes
    ADD CONSTRAINT codes_pkey PRIMARY KEY (id);


--
-- Name: group_attributes group_attributes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_attributes
    ADD CONSTRAINT group_attributes_pkey PRIMARY KEY (id);


--
-- Name: groups_permissions groups_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups_permissions
    ADD CONSTRAINT groups_permissions_pkey PRIMARY KEY (id);


--
-- Name: groups groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_pkey PRIMARY KEY (id);


--
-- Name: http_sessions http_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.http_sessions
    ADD CONSTRAINT http_sessions_pkey PRIMARY KEY (id);


--
-- Name: key_pairs key_pairs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.key_pairs
    ADD CONSTRAINT key_pairs_pkey PRIMARY KEY (id);


--
-- Name: permissions permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_pkey PRIMARY KEY (id);


--
-- Name: pre_registrations pre_registrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pre_registrations
    ADD CONSTRAINT pre_registrations_pkey PRIMARY KEY (id);


--
-- Name: redirect_uris redirect_uris_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.redirect_uris
    ADD CONSTRAINT redirect_uris_pkey PRIMARY KEY (id);


--
-- Name: refresh_tokens refresh_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_pkey PRIMARY KEY (id);


--
-- Name: resources resources_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resources
    ADD CONSTRAINT resources_pkey PRIMARY KEY (id);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);


--
-- Name: settings settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.settings
    ADD CONSTRAINT settings_pkey PRIMARY KEY (id);


--
-- Name: user_attributes user_attributes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_attributes
    ADD CONSTRAINT user_attributes_pkey PRIMARY KEY (id);


--
-- Name: user_consents user_consents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_consents
    ADD CONSTRAINT user_consents_pkey PRIMARY KEY (id);


--
-- Name: user_profile_pictures user_profile_pictures_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_profile_pictures
    ADD CONSTRAINT user_profile_pictures_pkey PRIMARY KEY (id);


--
-- Name: user_profile_pictures user_profile_pictures_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_profile_pictures
    ADD CONSTRAINT user_profile_pictures_user_id_key UNIQUE (user_id);


--
-- Name: client_logos client_logos_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.client_logos
    ADD CONSTRAINT client_logos_pkey PRIMARY KEY (id);


--
-- Name: client_logos client_logos_client_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.client_logos
    ADD CONSTRAINT client_logos_client_id_key UNIQUE (client_id);


--
-- Name: user_session_clients user_session_clients_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_session_clients
    ADD CONSTRAINT user_session_clients_pkey PRIMARY KEY (id);


--
-- Name: user_sessions user_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_sessions
    ADD CONSTRAINT user_sessions_pkey PRIMARY KEY (id);


--
-- Name: users_groups users_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users_groups
    ADD CONSTRAINT users_groups_pkey PRIMARY KEY (id);


--
-- Name: users_permissions users_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users_permissions
    ADD CONSTRAINT users_permissions_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: web_origins web_origins_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.web_origins
    ADD CONSTRAINT web_origins_pkey PRIMARY KEY (id);


--
-- Name: idx_client_identifier; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_client_identifier ON public.clients USING btree (client_identifier);


--
-- Name: idx_code_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_code_hash ON public.codes USING btree (code_hash);


--
-- Name: idx_email; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_email ON public.users USING btree (email);


--
-- Name: idx_family_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_family_name ON public.users USING btree (family_name);


--
-- Name: idx_given_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_given_name ON public.users USING btree (given_name);


--
-- Name: idx_group_identifier; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_group_identifier ON public.groups USING btree (group_identifier);


--
-- Name: idx_httpsess_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_httpsess_expires ON public.http_sessions USING btree (expires_on);


--
-- Name: idx_middle_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_middle_name ON public.users USING btree (middle_name);


--
-- Name: idx_permission_identifier_resource; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_permission_identifier_resource ON public.permissions USING btree (permission_identifier, resource_id);


--
-- Name: idx_pre_reg_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pre_reg_email ON public.pre_registrations USING btree (email);


--
-- Name: idx_refresh_token_jti; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_refresh_token_jti ON public.refresh_tokens USING btree (refresh_token_jti);


--
-- Name: idx_refresh_tokens_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_refresh_tokens_user_id ON public.refresh_tokens USING btree (user_id);


--
-- Name: idx_refresh_tokens_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_refresh_tokens_client_id ON public.refresh_tokens USING btree (client_id);


--
-- Name: idx_resource_identifier; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_resource_identifier ON public.resources USING btree (resource_identifier);


--
-- Name: idx_session_identifier; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_session_identifier ON public.user_sessions USING btree (session_identifier);


--
-- Name: idx_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_state ON public.key_pairs USING btree (state);


--
-- Name: idx_subject; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_subject ON public.users USING btree (subject);


--
-- Name: idx_username; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_username ON public.users USING btree (username);


--
-- Name: clients_permissions fk_clients_permissions_client; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.clients_permissions
    ADD CONSTRAINT fk_clients_permissions_client FOREIGN KEY (client_id) REFERENCES public.clients(id) ON DELETE CASCADE;


--
-- Name: clients_permissions fk_clients_permissions_permission; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.clients_permissions
    ADD CONSTRAINT fk_clients_permissions_permission FOREIGN KEY (permission_id) REFERENCES public.permissions(id) ON DELETE CASCADE;


--
-- Name: redirect_uris fk_clients_redirect_uris; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.redirect_uris
    ADD CONSTRAINT fk_clients_redirect_uris FOREIGN KEY (client_id) REFERENCES public.clients(id) ON DELETE CASCADE;


--
-- Name: web_origins fk_clients_web_origins; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.web_origins
    ADD CONSTRAINT fk_clients_web_origins FOREIGN KEY (client_id) REFERENCES public.clients(id) ON DELETE CASCADE;


--
-- Name: codes fk_codes_client; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.codes
    ADD CONSTRAINT fk_codes_client FOREIGN KEY (client_id) REFERENCES public.clients(id) ON DELETE CASCADE;


--
-- Name: codes fk_codes_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.codes
    ADD CONSTRAINT fk_codes_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: group_attributes fk_groups_attributes; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_attributes
    ADD CONSTRAINT fk_groups_attributes FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE CASCADE;


--
-- Name: groups_permissions fk_groups_permissions_group; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups_permissions
    ADD CONSTRAINT fk_groups_permissions_group FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE CASCADE;


--
-- Name: groups_permissions fk_groups_permissions_permission; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups_permissions
    ADD CONSTRAINT fk_groups_permissions_permission FOREIGN KEY (permission_id) REFERENCES public.permissions(id) ON DELETE CASCADE;


--
-- Name: permissions fk_permissions_resource; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT fk_permissions_resource FOREIGN KEY (resource_id) REFERENCES public.resources(id) ON DELETE CASCADE;


--
-- Name: refresh_tokens fk_refresh_tokens_code; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT fk_refresh_tokens_code FOREIGN KEY (code_id) REFERENCES public.codes(id) ON DELETE CASCADE;


--
-- Name: refresh_tokens fk_refresh_tokens_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: refresh_tokens fk_refresh_tokens_client; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT fk_refresh_tokens_client FOREIGN KEY (client_id) REFERENCES public.clients(id) ON DELETE CASCADE;


--
-- Name: user_consents fk_user_consents_client; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_consents
    ADD CONSTRAINT fk_user_consents_client FOREIGN KEY (client_id) REFERENCES public.clients(id) ON DELETE CASCADE;


--
-- Name: user_consents fk_user_consents_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_consents
    ADD CONSTRAINT fk_user_consents_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_profile_pictures fk_user_profile_pictures_user_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_profile_pictures
    ADD CONSTRAINT fk_user_profile_pictures_user_id FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: client_logos fk_client_logos_client_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.client_logos
    ADD CONSTRAINT fk_client_logos_client_id FOREIGN KEY (client_id) REFERENCES public.clients(id) ON DELETE CASCADE;


--
-- Name: user_session_clients fk_user_session_clients_client; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_session_clients
    ADD CONSTRAINT fk_user_session_clients_client FOREIGN KEY (client_id) REFERENCES public.clients(id) ON DELETE CASCADE;


--
-- Name: user_session_clients fk_user_sessions_clients; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_session_clients
    ADD CONSTRAINT fk_user_sessions_clients FOREIGN KEY (user_session_id) REFERENCES public.user_sessions(id) ON DELETE CASCADE;


--
-- Name: user_sessions fk_user_sessions_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_sessions
    ADD CONSTRAINT fk_user_sessions_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_attributes fk_users_attributes; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_attributes
    ADD CONSTRAINT fk_users_attributes FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: users_groups fk_users_groups_group; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users_groups
    ADD CONSTRAINT fk_users_groups_group FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE CASCADE;


--
-- Name: users_groups fk_users_groups_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users_groups
    ADD CONSTRAINT fk_users_groups_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: users_permissions fk_users_permissions_permission; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users_permissions
    ADD CONSTRAINT fk_users_permissions_permission FOREIGN KEY (permission_id) REFERENCES public.permissions(id) ON DELETE CASCADE;


--
-- Name: users_permissions fk_users_permissions_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users_permissions
    ADD CONSTRAINT fk_users_permissions_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--


