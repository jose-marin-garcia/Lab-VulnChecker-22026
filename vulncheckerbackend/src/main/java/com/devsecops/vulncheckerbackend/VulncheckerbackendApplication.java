package com.devsecops.vulncheckerbackend;

import com.devsecops.vulncheckerbackend.entities.UserEntity;
import com.devsecops.vulncheckerbackend.repositories.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import jakarta.annotation.PostConstruct;
import java.util.TimeZone;

@SpringBootApplication
public class VulncheckerbackendApplication {

    @PostConstruct
    public void init() {
        // Forzar el huso horario de todo el backend a la hora oficial de Chile.
        // Esto gestiona automáticamente los cambios de hora (verano/invierno).
        TimeZone.setDefault(TimeZone.getTimeZone("America/Santiago"));
    }

    public static void main(String[] args) {
        SpringApplication.run(VulncheckerbackendApplication.class, args);
    }

    @Bean
    CommandLineRunner initData(UserRepository userRepository, BCryptPasswordEncoder encoder) {
        return args -> {
            if (userRepository.count() == 0) {
                UserEntity admin = new UserEntity();
                admin.setFirstName("Admin");
                admin.setPaternalLastName("Sistema");
                admin.setMaternalLastName("Usach");
                admin.setEmail("admin.seguridad@usach.cl");
                admin.setPassword(encoder.encode("admin123")); 
                admin.setActive(true);
                admin.setRole("ADMIN");
                userRepository.save(admin);
                System.out.println("✅ Usuario sembrado: admin.seguridad@usach.cl / admin123");
            }
        };
    }
}