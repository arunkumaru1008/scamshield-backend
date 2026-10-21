package com.scamshield_backend;

import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/community")
public class CommunityReportController {

    private final ReportedEntityRepository repository;

    public CommunityReportController(ReportedEntityRepository repository) {
        this.repository = repository;
    }

    @PostMapping("/search")
    public SearchResponse searchEntity(@RequestBody SearchRequest request) {
        if (request.value() == null || request.value().trim().isEmpty()) {
            return new SearchResponse(0, List.of());
        }
        
        // Only return reports that an admin has APPROVED
        List<ReportedEntity> approvedReports = repository.findByEntityValueAndStatus(request.value().trim(), "APPROVED");
        
        List<String> reasons = approvedReports.stream()
            .map(ReportedEntity::getReason)
            .collect(Collectors.toList());
            
        return new SearchResponse(approvedReports.size(), reasons);
    }

    @PostMapping("/report")
    public ReportResponse submitReport(@RequestBody ReportRequest request) {
        if (request.value() == null || request.value().trim().isEmpty()) {
            return new ReportResponse(false, "Value is required.");
        }
        
        ReportedEntity entity = new ReportedEntity(
            request.type() != null ? request.type() : "UNKNOWN",
            request.value().trim(),
            request.reason()
        );
        repository.save(entity); // Saves as PENDING by default
        
        return new ReportResponse(true, "Report submitted successfully. It will be reviewed before appearing in search results.");
    }

    public record SearchRequest(String value) {}
    public record SearchResponse(int reportCount, List<String> reasons) {}
    public record ReportRequest(String type, String value, String reason) {}
    public record ReportResponse(boolean success, String message) {}
}