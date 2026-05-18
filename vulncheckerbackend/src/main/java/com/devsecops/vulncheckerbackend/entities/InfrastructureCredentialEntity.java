package com.devsecops.vulncheckerbackend.entities;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;

@Entity
@Table(name = "infrastructure_credentials")
public class InfrastructureCredentialEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name; // Ej: "Laboratorio Ethical Hacking"

    // Credenciales SSH
    @Column(name = "ssh_user")
    private String sshUser;

    @Column(name = "ssh_password")
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String sshPassword;

    // Credenciales Wazuh API (JWT)
    @Column(name = "wazuh_user")
    private String wazuhUser;

    @Column(name = "wazuh_password")
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String wazuhPassword;

    // Credenciales Wazuh Indexer (Basic Auth)
    @Column(name = "indexer_user")
    private String indexerUser;

    @Column(name = "indexer_password")
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String indexerPassword;

    @Column(name = "user_id", nullable = false)
    private Long userId; 

    public InfrastructureCredentialEntity() {
        // Constructor vacío requerido por JPA
    }
    // Getters y Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getSshUser() { return sshUser; }
    public void setSshUser(String sshUser) { this.sshUser = sshUser; }
    public String getSshPassword() { return sshPassword; }
    public void setSshPassword(String sshPassword) { this.sshPassword = sshPassword; }
    public String getWazuhUser() { return wazuhUser; }
    public void setWazuhUser(String wazuhUser) { this.wazuhUser = wazuhUser; }
    public String getWazuhPassword() { return wazuhPassword; }
    public void setWazuhPassword(String wazuhPassword) { this.wazuhPassword = wazuhPassword; }
    public String getIndexerUser() { return indexerUser; }
    public void setIndexerUser(String indexerUser) { this.indexerUser = indexerUser; }
    public String getIndexerPassword() { return indexerPassword; }
    public void setIndexerPassword(String indexerPassword) { this.indexerPassword = indexerPassword; }
    public Long getUserId() { return userId; }
    public void setUserId(Long userId) { this.userId = userId; }
}