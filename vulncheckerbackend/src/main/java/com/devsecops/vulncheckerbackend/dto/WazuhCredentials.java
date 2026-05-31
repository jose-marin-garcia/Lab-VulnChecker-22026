package com.devsecops.vulncheckerbackend.dto;

/** Agrupa las credenciales necesarias para autenticarse en Wazuh. */
public record WazuhCredentials(
        String wazuhHost,
        String wazuhUser,
        String wazuhPassword
) {}