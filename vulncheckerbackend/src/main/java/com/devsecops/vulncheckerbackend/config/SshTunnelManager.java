package com.devsecops.vulncheckerbackend.config;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Properties;

@Component
public class SshTunnelManager {
    @Value("${wazuh.indexer.port}")
    private int wazuhIndexerPort;

    @Value("${wazuh.tunnel.local-port}")
    private int indexerLocalPort;

    @Value("${wazuh.api.port}")
    private int wazuhApiPort;

    @Value("${wazuh.api.local-port}")
    private int apiLocalPort;

    public Session openTunnel(String sshHost, int sshPort, String sshUser, String sshPassword) throws Exception {
        JSch jsch = new JSch();

        Session session = jsch.getSession(sshUser, sshHost, sshPort);
        session.setPassword(sshPassword);

        Properties config = new Properties();
        config.put("StrictHostKeyChecking", "no");
        session.setConfig(config);

        try {
            session.connect(10_000);
            session.setPortForwardingL(indexerLocalPort, "127.0.0.1", wazuhIndexerPort);
        } catch (Exception e) {
            System.err.println("Error: La conexión SSH falló - " + e.getMessage());
            throw e;
        }

        return session;
    }

    public Session openTunnel(String sshHost, int sshPort, String sshUser, String sshPassword, int localPort, int remotePort) throws Exception {
        JSch jsch = new JSch();

        Session session = jsch.getSession(sshUser, sshHost, sshPort);
        session.setPassword(sshPassword);

        Properties config = new Properties();
        config.put("StrictHostKeyChecking", "no");
        session.setConfig(config);

        session.connect(10_000);
        session.setPortForwardingL(localPort, "127.0.0.1", remotePort);

        return session;
    }

    public void closeTunnel(Session session) {
        if (session != null && session.isConnected()) {
            session.disconnect();
        }
    }

    public int getLocalPort() {
        return indexerLocalPort;
    }

    public int getApiLocalPort() {
        return apiLocalPort;
    }
}
