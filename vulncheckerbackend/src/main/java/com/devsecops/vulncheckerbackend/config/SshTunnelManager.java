package com.devsecops.vulncheckerbackend.config;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Properties;

@Component
public class SshTunnelManager {
    @Value("${wazuh.indexer.port}")
    private int wazuhApiPort;       // puerto por defecto de Wazuh Indexer
    
    @Value("${wazuh.tunnel.local-port}")
    private int localPort;        // puerto local del tunnel (Indexer)

    /**
     * Abre un SSH tunnel hacia el servidor donde corre Wazuh.
     * Devuelve la sesión activa — el caller DEBE cerrarla cuando termine.
     *
     * @param sshHost     IP/hostname del servidor SSH
     * @param sshPort     Puerto SSH (normalmente 22)
     * @param sshUser     Usuario SSH
     * @param sshPassword Contraseña SSH
     */
    public Session openTunnel(String sshHost, int sshPort, String sshUser, String sshPassword) throws Exception {
        JSch jsch = new JSch();

        Session session = jsch.getSession(sshUser, sshHost, sshPort);
        session.setPassword(sshPassword);

        Properties config = new Properties();
        config.put("StrictHostKeyChecking", "no");   // en producción usa known_hosts
        session.setConfig(config);

        try {
            session.connect(10_000); // timeout 10 s
            session.setPortForwardingL(localPort, "127.0.0.1", wazuhApiPort);
        } catch (Exception e) {
            System.err.println("Error: La conexión SSH falló - " + e.getMessage());
            throw e;
        }

        return session;
    }

    /** Cierra la sesión SSH (y el tunnel) de forma segura. */
    public void closeTunnel(Session session) {
        if (session != null && session.isConnected()) {
            session.disconnect();
        }
    }

    public int getLocalPort() {
        return localPort;
    }
}