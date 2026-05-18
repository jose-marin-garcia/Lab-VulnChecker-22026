package com.devsecops.vulncheckerbackend.controllers;

import com.devsecops.vulncheckerbackend.config.JwtUtil;
import com.devsecops.vulncheckerbackend.entities.UserEntity;
import com.devsecops.vulncheckerbackend.repositories.UserRepository;
import com.devsecops.vulncheckerbackend.services.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;

    public UserController(UserService userService, UserRepository userRepository, JwtUtil jwtUtil) {
        this.userService = userService;
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
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

    @PatchMapping("/{id}/activate")
    public ResponseEntity<?> activateUser(@PathVariable Long id) {
        return userService.findById(id).map(user -> {
            user.setActive(true);
            userService.saveDirectly(user);
            return ResponseEntity.ok("Usuario activado");
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