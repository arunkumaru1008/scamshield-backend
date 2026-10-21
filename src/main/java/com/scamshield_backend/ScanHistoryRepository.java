package com.scamshield_backend;

import org.springframework.data.jpa.repository.JpaRepository;

public interface ScanHistoryRepository extends JpaRepository<ScanHistory, Long> {
    long countByLevel(String level);
    long countByScanType(String scanType);
}