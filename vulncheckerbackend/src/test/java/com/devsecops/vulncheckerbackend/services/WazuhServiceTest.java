package com.devsecops.vulncheckerbackend.services;

import com.devsecops.vulncheckerbackend.repositories.VulnerabilityRepository;
import com.devsecops.vulncheckerbackend.dto.WazuhCredentials;
import com.devsecops.vulncheckerbackend.repositories.VulnerabilitySnapshotRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class WazuhServiceTest {

    @Mock
    private RestTemplate restTemplate;

    @Mock
    private VulnerabilityRepository vulnerabilityRepository;

    @Mock
    private VulnerabilitySnapshotRepository snapshotRepository;

    @Mock
    private NamedParameterJdbcTemplate namedJdbcTemplate;

    private WazuhService service;

    private static final WazuhCredentials CREDS = new WazuhCredentials(
            "10.0.0.1", "api-user", "api-pass"
    );

    @BeforeEach
    void setUp() {
        Executor directExecutor = Runnable::run;
        service = new WazuhService(restTemplate, vulnerabilityRepository, snapshotRepository, namedJdbcTemplate, directExecutor);
    }

    @Test
    void getAllVulnerabilities_queriesWazuhWithoutPersistingSnapshots() throws Exception {
        when(restTemplate.exchange(
                anyString(),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                ArgumentMatchers.<ParameterizedTypeReference<Map<String, Object>>>any()
        )).thenReturn(ResponseEntity.ok(searchResponse(List.of(singleHit("CVE-2026-1000", "High", "001", "openssl", List.of(1700000001L, "abc"))))));

        Map<String, Object> result = service.getAllVulnerabilities(CREDS, 6000, 10);

        assertNotNull(result);
        verifyNoInteractions(vulnerabilityRepository);
        verifyNoInteractions(snapshotRepository);
        verifyNoInteractions(namedJdbcTemplate);
        ArgumentCaptor<HttpEntity<String>> requestCaptor = ArgumentCaptor.forClass(HttpEntity.class);
        verify(restTemplate).exchange(
                anyString(),
                eq(HttpMethod.POST),
                requestCaptor.capture(),
                ArgumentMatchers.<ParameterizedTypeReference<Map<String, Object>>>any()
        );
        String queryBody = requestCaptor.getValue().getBody();
        assertNotNull(queryBody);
        assertTrue(queryBody.contains("\"from\": 10"));
        assertTrue(queryBody.contains("\"size\": 5000"));
    }

    @Test
    void getAllVulnerabilities_throwsExceptionWhenSearchFails() throws Exception {
        when(restTemplate.exchange(
                anyString(),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                ArgumentMatchers.<ParameterizedTypeReference<Map<String, Object>>>any()
        )).thenThrow(new RuntimeException("network error"));

        assertThrows(RuntimeException.class, () -> service.getAllVulnerabilities(CREDS, 100, 0));
    }

    @Test
    void getRemoteTotalCount_parsesCount() throws Exception {
        when(restTemplate.exchange(
                anyString(),
                eq(HttpMethod.GET),
                any(HttpEntity.class),
                ArgumentMatchers.<ParameterizedTypeReference<Map<String, Object>>>any()
        )).thenReturn(ResponseEntity.ok(Map.of("count", "42")));

        long count = service.getRemoteTotalCount(CREDS);

        assertEquals(42L, count);
    }

    @Test
    void syncAllVulnerabilitiesMasive_processesBatchAndStopsOnEmptyPage() throws Exception {
        Map<String, Object> agentGroupsResponse = Map.of("hits", Map.of("hits", List.of()));

        when(restTemplate.exchange(
                anyString(),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                eq(Map.class)
        )).thenReturn(ResponseEntity.ok(agentGroupsResponse));

        Map<String, Object> firstPage = searchResponse(List.of(singleHit("CVE-2026-2000", "Critical", "001", "openssl", List.of(1700000002L, "def"))));
        Map<String, Object> emptyPage = searchResponse(List.of());

        when(restTemplate.exchange(
                anyString(),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                ArgumentMatchers.<ParameterizedTypeReference<Map<String, Object>>>any()
        )).thenReturn(ResponseEntity.ok(firstPage), ResponseEntity.ok(emptyPage));

        service.syncAllVulnerabilitiesMasive(CREDS);

        verify(namedJdbcTemplate).batchUpdate(anyString(), any(SqlParameterSource[].class));
        verify(snapshotRepository).save(any());
        verify(vulnerabilityRepository).markAsResolvedForAgentsBefore(anyList(), any(), any());
        
        verify(restTemplate, times(2)).exchange(
                anyString(),
                eq(HttpMethod.POST),
                any(HttpEntity.class),
                ArgumentMatchers.<ParameterizedTypeReference<Map<String, Object>>>any()
        );
    }

    private static Map<String, Object> searchResponse(List<Map<String, Object>> hits) {
        return Map.of("hits", Map.of("hits", hits));
    }

    private static Map<String, Object> singleHit(String cve, String severity, String agentId, String pkg, List<Object> sortValues) {
        return Map.of(
                "_source", Map.of(
                        "vulnerability", Map.of(
                                "id", cve,
                                "severity", severity,
                                "score", Map.of("base", 8.4),
                                "detected_at", "2026-01-10T10:00:00Z",
                                "description", "Desc",
                                "title", "Title"
                        ),
                        "agent", Map.of(
                                "id", agentId,
                                "name", "agent-" + agentId
                        ),
                        "package", Map.of(
                                "name", pkg,
                                "version", "1.0.0"
                        )
                ),
                "sort", sortValues
        );
    }
}
