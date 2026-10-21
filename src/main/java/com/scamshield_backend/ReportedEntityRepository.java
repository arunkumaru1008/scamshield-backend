package com.scamshield_backend;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ReportedEntityRepository extends JpaRepository<ReportedEntity, Long> {
    List<ReportedEntity> findByEntityValueAndStatus(String entityValue, String status);
}