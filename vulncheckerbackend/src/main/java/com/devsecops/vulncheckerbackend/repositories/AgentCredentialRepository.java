package com.devsecops.vulncheckerbackend.repositories;

import com.devsecops.vulncheckerbackend.entities.AgentCredentialEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AgentCredentialRepository extends JpaRepository<AgentCredentialEntity, Long> {
    Optional<AgentCredentialEntity> findFirstByAgentId(String agentId);
}
