package com.devsecops.vulncheckerbackend.dto;

import java.util.List;

public record TimelinePointDto(
        String syncDate,                        // "2026-07-01"
        String label,                           // "Jul 01" (legible para el eje X)
        int newCount,
        int resolvedCount,
        List<TimelineVulnItemDto> newVulns,
        List<TimelineVulnItemDto> resolvedVulns
) {}
