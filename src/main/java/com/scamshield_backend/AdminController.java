package com.scamshield_backend;

import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final ReportedEntityRepository repository;

    public AdminController(ReportedEntityRepository repository) {
        this.repository = repository;
    }

    @GetMapping("/reports")
    public List<ReportedEntity> getAllReports() {
        return repository.findAll();
    }

    @PostMapping("/reports/{id}/status")
    public ReportedEntity updateStatus(@PathVariable Long id, @RequestBody StatusRequest request) {
        ReportedEntity entity = repository.findById(id).orElseThrow(() -> new RuntimeException("Report not found"));
        entity.setStatus(request.status());
        return repository.save(entity);
    }

    public record StatusRequest(String status) {}
}