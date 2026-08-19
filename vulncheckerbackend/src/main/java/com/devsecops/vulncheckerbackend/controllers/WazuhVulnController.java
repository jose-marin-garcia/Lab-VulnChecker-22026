package com.devsecops.vulncheckerbackend.controllers;

import com.devsecops.vulncheckerbackend.repositories.VulnerabilityRepository;
import com.devsecops.vulncheckerbackend.dto.VulnerabilityRequest;
import com.devsecops.vulncheckerbackend.dto.WazuhCredentials;
import com.devsecops.vulncheckerbackend.entities.InfrastructureCredentialEntity;
import com.devsecops.vulncheckerbackend.repositories.InfrastructureCredentialRepository;
import com.devsecops.vulncheckerbackend.services.WazuhService;

import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;
import org.slf4j.Logger;

import java.util.Base64;
import java.util.Map;

@RestController
@RequestMapping("/api/vulns")
public class WazuhVulnController {

    private final WazuhService wazuhService;
    private final InfrastructureCredentialRepository infraRepo;
	private final VulnerabilityRepository vulnerabilityRepository;
    private static final Logger log = LoggerFactory.getLogger(WazuhVulnController.class);

    public WazuhVulnController(WazuhService wazuhService, 
                               InfrastructureCredentialRepository infraRepo,
                               VulnerabilityRepository vulnerabilityRepository) {
        this.wazuhService = wazuhService;
        this.infraRepo = infraRepo;
        this.vulnerabilityRepository = vulnerabilityRepository;
    }

    // ─── Helper ──────────────────────────────────────────────────────────────

    private WazuhCredentials creds(Long credentialId) {
        InfrastructureCredentialEntity credEntity = infraRepo.findById(credentialId)
                .orElseThrow(() -> new RuntimeException("Credencial no encontrada"));

        return new WazuhCredentials(
                credEntity.getWazuhIp(),
                credEntity.getWazuhUser(),
                credEntity.getWazuhPassword()
        );
    }

    // ─── 1. Todas (paginadas) ─────────────────────────────────────────────────
    @GetMapping("/{credentialId}/all")
    public ResponseEntity<Map<String, Object>> getAllLegacy(
            @PathVariable Long credentialId) throws Exception {
        return ResponseEntity.ok(wazuhService.getAllVulnerabilities(creds(credentialId), 100, 0));
    }

	@GetMapping("/count-local")
	public ResponseEntity<Map<String, Object>> getLocalCount() {
		long count = vulnerabilityRepository.count();
		log.info("Consulta de conteo local: {}", count);
		Map<String, Object> response = new java.util.HashMap<>();
		response.put("count", count);
		response.put("status", wazuhService.getCurrentSyncStatus());
		response.put("error", wazuhService.getCurrentSyncError());
		return ResponseEntity.ok(response);
	}
    
	// ─── 2. Top N ─────────────────────────────────────────────────────────────
    @GetMapping("/{credentialId}/top/{limit}")
    public ResponseEntity<Map<String, Object>> getTop(
            @PathVariable Long credentialId,
            @PathVariable int limit) throws Exception {

        return ResponseEntity.ok(
                wazuhService.getTopVulnerabilities(creds(credentialId), limit)
        );
    }

    // ─── 3. Críticas ──────────────────────────────────────────────────────────
    @GetMapping("/{credentialId}/critical")
    public ResponseEntity<Map<String, Object>> getCritical(
            @PathVariable Long credentialId) throws Exception {

        return ResponseEntity.ok(
                wazuhService.getCriticalVulnerabilities(creds(credentialId))
        );
    }

    // ─── 4. Por severidad ─────────────────────────────────────────────────────
    @GetMapping("/{credentialId}/severity/{severity}")
    public ResponseEntity<Map<String, Object>> getBySeverity(
            @PathVariable Long credentialId,
            @PathVariable String severity,
            @RequestParam(defaultValue = "100") int limit) throws Exception {

        return ResponseEntity.ok(
                wazuhService.getVulnerabilitiesBySeverity(creds(credentialId), severity, limit)
        );
    }

    // ─── 5. Por CVE ───────────────────────────────────────────────────────────
    @GetMapping("/{credentialId}/cve/{cve}")
    public ResponseEntity<Map<String, Object>> getByCve(
            @PathVariable Long credentialId,
            @PathVariable String cve) throws Exception {

        return ResponseEntity.ok(
                wazuhService.getVulnerabilitiesByCve(creds(credentialId), cve)
        );
    }

    // ─── 6. Por agente ────────────────────────────────────────────────────────
    @GetMapping("/{credentialId}/agent/{agentId}")
    public ResponseEntity<Map<String, Object>> getByAgent(
            @PathVariable Long credentialId,
            @PathVariable String agentId,
            @RequestParam(defaultValue = "100") int limit) throws Exception {

        return ResponseEntity.ok(
                wazuhService.getVulnerabilitiesByAgent(creds(credentialId), agentId, limit)
        );
    }

    // ─── 7. Resumen ───────────────────────────────────────────────────────────
    @GetMapping("/{credentialId}/summary")
    public ResponseEntity<Map<String, Object>> getSummary(
            @PathVariable Long credentialId) throws Exception {

        return ResponseEntity.ok(
                wazuhService.getVulnerabilitiesSummary(creds(credentialId))
        );
    }

	// ─── 8. Sincronización masiva (POST) ─────────────────────────────────────
    @PostMapping("/consume")
	public ResponseEntity<Map<String, Object>> consumeAll(
			@RequestBody VulnerabilityRequest request,
			@RequestHeader("Authorization") String auth) {

		InfrastructureCredentialEntity credEntity = infraRepo.findById(request.getInfrastructureCredentialId())
				.orElseThrow(() -> new RuntimeException("Credencial no encontrada"));

		WazuhCredentials credentials = new WazuhCredentials(
				credEntity.getWazuhIp(),
				credEntity.getWazuhUser(),
				credEntity.getWazuhPassword()
		);

		// Ejecución asíncrona delegada al servicio
		wazuhService.syncAllVulnerabilitiesMasive(credentials, request.getInfrastructureCredentialId());

		return ResponseEntity.ok(Map.of(
			"status", "processing",
			"message", "Sincronización de gran volumen iniciada. Esto puede tardar varios minutos."
		));
	}
	
	@PostMapping("/remote-count")
	public ResponseEntity<Map<String, Long>> getRemoteCount(@RequestBody VulnerabilityRequest request) throws Exception {
		InfrastructureCredentialEntity credEntity = infraRepo.findById(request.getInfrastructureCredentialId())
				.orElseThrow(() -> new RuntimeException("Credencial no encontrada"));

		WazuhCredentials credentials = new WazuhCredentials(
				credEntity.getWazuhIp(), 
				credEntity.getWazuhUser(), 
				credEntity.getWazuhPassword()
		);

		long total = wazuhService.getRemoteTotalCount(credentials);
		return ResponseEntity.ok(Map.of("total", total));
	}

    // ─── Manejo de errores ────────────────────────────────────────────────────
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> handleError(Exception e) {
        String msg = e.getMessage();
        String customMessage = msg;

        if (msg != null) {
            if (msg.contains("NoRouteToHostException") || msg.contains("Host is unreachable")) {
                customMessage = "La dirección IP no es accesible o no existe en la red. Verifica que la IP sea correcta y el servidor esté encendido.";
            } else if (msg.contains("Connection refused") || msg.contains("ConnectException")) {
                customMessage = "Conexión rechazada al Indexador de Wazuh. Verifica que el puerto 9200 esté abierto y accesible desde este servidor.";
            } else if (msg.contains("UnknownHostException")) {
                customMessage = "El nombre de host o la dirección IP no son válidos. Revisa la IP ingresada.";
            } else if (msg.contains("timeout: socket is not established")) {
                customMessage = "No se pudo establecer conexión SSH (Timeout). Verifica que la IP sea correcta y el puerto 22 esté abierto.";
            } else if (msg.contains("Auth fail")) {
                customMessage = "Credenciales SSH incorrectas.";
            }
        }

        if (e instanceof HttpClientErrorException httpEx
                && (httpEx.getStatusCode() == HttpStatus.UNAUTHORIZED || httpEx.getStatusCode() == HttpStatus.FORBIDDEN)) {
            customMessage = "No se pudieron obtener los datos. Es probable que la contraseña de Wazuh esté desactualizada. Verifica las credenciales de Wazuh en Ajustes.";
        }

        return ResponseEntity.status(500).body(Map.of(
                "error", e.getClass().getSimpleName(),
                "message", customMessage != null ? customMessage : "Error desconocido en el servidor"
        ));
    }
}
