package com.scamshield_backend;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DocRuleRepository extends JpaRepository<DocRule, Long> {
    List<DocRule> findByActiveTrue();
}