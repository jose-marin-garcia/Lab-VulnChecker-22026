-- V7: Remover restricción UNIQUE de agent_id en agent_credentials
-- Esto permite que un mismo agente pueda estar asociado a múltiples credenciales
-- (la credencial original del ADMIN y las credenciales clonadas para los USERs)

ALTER TABLE public.agent_credentials DROP CONSTRAINT IF EXISTS uk_agent_id;
ALTER TABLE public.agent_credentials DROP CONSTRAINT IF EXISTS agent_credentials_agent_id_key;
