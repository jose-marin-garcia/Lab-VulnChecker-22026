package com.devsecops.vulncheckerbackend.dto;

public record AgentCveStatDto(String agentName, String cve, long count) {
}
