package com.scamshield_backend;

import java.time.LocalDateTime;
import jakarta.persistence.*;

@Entity
@Table(name = "reported_entities")
public class ReportedEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 50)
    private String entityType; // "PHONE" or "UPI"

    @Column(nullable = false, length = 100)
    private String entityValue;

    @Column(length = 500)
    private String reason;

    @Column(nullable = false)
    private String status = "PENDING"; // PENDING, APPROVED, REJECTED

    @Column(nullable = false)
    private LocalDateTime reportedAt = LocalDateTime.now();

    public ReportedEntity() {}

    public ReportedEntity(String entityType, String entityValue, String reason) {
        this.entityType = entityType;
        this.entityValue = entityValue;
        this.reason = reason;
    }

    public Long getId() { return id; }
    public String getEntityType() { return entityType; }
    public String getEntityValue() { return entityValue; }
    public String getReason() { return reason; }
    public String getStatus() { return status; }

    public void setStatus(String status) { this.status = status; }
}