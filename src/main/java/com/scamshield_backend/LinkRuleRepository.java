package com.scamshield_backend;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface LinkRuleRepository extends JpaRepository<LinkRule, Long> {
    List<LinkRule> findByActiveTrue();
}