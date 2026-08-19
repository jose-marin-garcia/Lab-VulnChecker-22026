package com.devsecops.vulncheckerbackend.dto;

public class AgentDto {
    private String agentId;
    private String agentName;
    private String agentGroup;

    public AgentDto() {
    }

    public AgentDto(String agentId, String agentName, String agentGroup) {
        this.agentId = agentId;
        this.agentName = agentName;
        this.agentGroup = agentGroup;
    }

    // Getters y Setters
    public String getAgentId() { return agentId; }
    public void setAgentId(String agentId) { this.agentId = agentId; }

    public String getAgentName() { return agentName; }
    public void setAgentName(String agentName) { this.agentName = agentName; }

    public String getAgentGroup() { return agentGroup; }
    public void setAgentGroup(String agentGroup) { this.agentGroup = agentGroup; }
}
