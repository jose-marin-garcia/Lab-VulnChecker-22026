-- V6: Añadir tabla agent_credentials y nuevos campos a users para el sistema de asignación de agentes

CREATE TABLE IF NOT EXISTS public.agent_credentials (
    id BIGSERIAL PRIMARY KEY,
    agent_id VARCHAR(255) NOT NULL UNIQUE,
    credential_id BIGINT NOT NULL
);

ALTER TABLE public.users ADD COLUMN IF NOT EXISTS assigned_agent_id VARCHAR(255);
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS assigned_agent_name VARCHAR(255);
