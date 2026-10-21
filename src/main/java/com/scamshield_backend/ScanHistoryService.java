package com.scamshield_backend;

import org.springframework.stereotype.Service;

@Service
public class ScanHistoryService {

    private final ScanHistoryRepository repository;

    public ScanHistoryService(ScanHistoryRepository repository) {
        this.repository = repository;
    }

    /** Saves only the type, score and level. The text the user pasted is never stored. */
    public void record(String scanType, int score, String level) {
        try {
            repository.save(new ScanHistory(scanType, score, level));
        } catch (Exception e) {
            // A history problem must never break a scan.
            System.out.println("Could not save scan history: " + e.getMessage());
        }
    }
}