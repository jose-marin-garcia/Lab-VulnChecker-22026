package com.devsecops.vulncheckerbackend.controllers;

import com.devsecops.vulncheckerbackend.config.JwtUtil;
import com.devsecops.vulncheckerbackend.dto.AgentDto;
import com.devsecops.vulncheckerbackend.dto.UserActivationRequest;
import com.devsecops.vulncheckerbackend.entities.AgentCredentialEntity;
import com.devsecops.vulncheckerbackend.entities.InfrastructureCredentialEntity;
import com.devsecops.vulncheckerbackend.entities.UserEntity;
import com.devsecops.vulncheckerbackend.repositories.AgentCredentialRepository;
import com.devsecops.vulncheckerbackend.repositories.UserRepository;
import com.devsecops.vulncheckerbackend.repositories.VulnerabilityRepository;
import com.devsecops.vulncheckerbackend.services.InfrastructureCredentialService;
import com.devsecops.vulncheckerbackend.services.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final AgentCredentialRepository agentCredentialRepository;
    private final InfrastructureCredentialService infraCredentialService;

    public UserController(UserService userService,
                          UserRepository userRepository,
                          JwtUtil jwtUtil,
                          VulnerabilityRepository vulnerabilityRepository,
                          AgentCredentialRepository agentCredentialRepository,
                          InfrastructureCredentialService infraCredentialService) {
        this.userService = userService;
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.agentCredentialRepository = agentCredentialRepository;
        this.infraCredentialService = infraCredentialService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody UserEntity loginRequest) {
        return userService.login(loginRequest.getEmail(), loginRequest.getPassword())
                .map(user -> {
                    String token = jwtUtil.generateToken(
                            user.getEmail(), user.getRole(), user.getId(), user.getFirstName());
                    return ResponseEntity.ok(Map.of(
                            "token", token,
                            "id", user.getId(),
                            "email", user.getEmail(),
                            "role", user.getRole(),
                            "firstName", user.getFirstName()
                    ));
                })
                .orElse(ResponseEntity.status(401).build());
    }

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(Authentication auth) {
        String email = auth.getName();
        return userService.findByEmail(email)
                .map(user -> ResponseEntity.ok(Map.of(
                        "id", user.getId(),
                        "email", user.getEmail(),
                        "role", user.getRole(),
                        "firstName", user.getFirstName()
                )))
                .orElse(ResponseEntity.status(401).body(Map.of("error", "Usuario no encontrado")));
    }

    @GetMapping
    public List<UserEntity> getAllUsers() {
        return userService.findAll();
    }

    @PostMapping
    public ResponseEntity<UserEntity> createUser(@RequestBody UserEntity user) {
        user.setActive(false);
        user.setRole("USER");
        UserEntity savedUser = userService.save(user);
        return ResponseEntity.ok(savedUser);
    }

    @GetMapping("/{id}")
    public ResponseEntity<UserEntity> getUserById(@PathVariable Long id) {
        return userService.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    // ─── Endpoint para obtener agentes únicos ─────────────────────────────
    @GetMapping("/agents")
    public ResponseEntity<List<AgentDto>> getDistinctAgents() {
        List<Object[]> raw = vulnerabilityRepository.findDistinctAgents();
        List<AgentDto> agents = raw.stream()
                .map(row -> new AgentDto(
                        (String) row[0],
                        (String) row[1],
                        (String) row[2]
                ))
                .collect(Collectors.toList());
        return ResponseEntity.ok(agents);
    }

    // ─── Activación con asignación de agente ──────────────────────────────
    @PatchMapping("/{id}/activate")
    public ResponseEntity<?> activateUser(@PathVariable Long id,
                                          @RequestBody UserActivationRequest request) {
        return userService.findById(id).map(user -> {
            // 1. Asignar agente al usuario
            user.setAssignedAgentId(request.getAgentId());
            user.setAssignedAgentName(request.getAgentName());
            user.setActive(true);

            // 2. Buscar la credencial asociada al agente y crear una copia para el usuario
            agentCredentialRepository.findFirstByAgentId(request.getAgentId()).ifPresent(agentCred -> {
                InfrastructureCredentialEntity original = infraCredentialService.getById(agentCred.getCredentialId());

                InfrastructureCredentialEntity copy = new InfrastructureCredentialEntity();
                copy.setName("Credencial Wazuh - Agente " + request.getAgentName());
                copy.setWazuhIp(original.getWazuhIp());
                copy.setWazuhUser(original.getWazuhUser());
                copy.setWazuhPassword(original.getWazuhPassword());
                copy.setUserId(user.getId());

                InfrastructureCredentialEntity savedCopy = infraCredentialService.save(copy);
                
                // Enlazar la nueva credencial con el agente
                AgentCredentialEntity userAgentCred = new AgentCredentialEntity();
                userAgentCred.setAgentId(request.getAgentId());
                userAgentCred.setCredentialId(savedCopy.getId());
                agentCredentialRepository.save(userAgentCred);
            });

            userService.saveDirectly(user);
            return ResponseEntity.ok(Map.of("message", "Usuario activado con agente " + request.getAgentName()));
        }).orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/pending")
    public List<UserEntity> getPendingUsers() {
        return userRepository.findByActiveFalse(); 
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        userService.deleteById(id);
        return ResponseEntity.noContent().build();
    }
}