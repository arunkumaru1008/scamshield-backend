package com.scamshield_backend;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class StatsController {

    public record Stats(long total, long high, long medium, long low,
                        long messages, long links, long emails) {}

    private final ScanHistoryRepository repository;

    public StatsController(ScanHistoryRepository repository) {
        this.repository = repository;
    }

    @GetMapping("/stats")
    public Stats stats() {
        return new Stats(
            repository.count(),
            repository.countByLevel("HIGH"),
            repository.countByLevel("MEDIUM"),
            repository.countByLevel("LOW"),
            repository.countByScanType("MESSAGE"),
            repository.countByScanType("LINK"),
            repository.countByScanType("EMAIL"));
    }
}