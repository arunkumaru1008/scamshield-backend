package com.scamshield_backend;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface ScamRuleRepository extends JpaRepository<ScamRule, Long> {
    List<ScamRule> findByActiveTrue();
}