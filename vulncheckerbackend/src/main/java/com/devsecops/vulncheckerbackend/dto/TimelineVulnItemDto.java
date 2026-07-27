package com.devsecops.vulncheckerbackend.dto;

public record TimelineVulnItemDto(String cve, String severity, String agentName) {}
