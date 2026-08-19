package com.devsecops.vulncheckerbackend.dto;

public class UserActivationRequest {
    private String agentId;
    private String agentName;

    public UserActivationRequest() {
    }

    // Getters y Setters
    public String getAgentId() { return agentId; }
    public void setAgentId(String agentId) { this.agentId = agentId; }

    public String getAgentName() { return agentName; }
    public void setAgentName(String agentName) { this.agentName = agentName; }
}
