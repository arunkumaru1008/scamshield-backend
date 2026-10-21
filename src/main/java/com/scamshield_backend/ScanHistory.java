package com.scamshield_backend;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "scan_history")
public class ScanHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "scan_type")
    private String scanType;

    @Column(name = "score")
    private int score;

    @Column(name = "level")
    private String level;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    public ScanHistory() {}

    public ScanHistory(String scanType, int score, String level) {
        this.scanType = scanType;
        this.score = score;
        this.level = level;
        this.createdAt = LocalDateTime.now();
    }

    public Long getId() { return id; }
    public String getScanType() { return scanType; }
    public int getScore() { return score; }
    public String getLevel() { return level; }
    public LocalDateTime getCreatedAt() { return createdAt; }
}