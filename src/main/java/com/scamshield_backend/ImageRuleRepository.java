package com.scamshield_backend;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ImageRuleRepository extends JpaRepository<ImageRule, Long> {
    List<ImageRule> findByActiveTrue();
}