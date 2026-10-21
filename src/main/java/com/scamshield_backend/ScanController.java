package com.scamshield_backend;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/scan")
public class ScanController {

    private final ScamRuleRepository scamRuleRepository;
    private final ScanHistoryService history;

    public ScanController(ScamRuleRepository scamRuleRepository, ScanHistoryService history) {
        this.scamRuleRepository = scamRuleRepository;
        this.history = history;
    }

    @PostMapping("/message")
    public ScanResult scanMessage(@RequestBody ScanRequest request) {
        String text = request.message() == null
                ? ""
                : request.message().toLowerCase(Locale.ROOT).replaceAll("\\s+", " ").trim();

        int score = 0;
        List<RuleMatch> matches = new ArrayList<>();

        for (ScamRule rule : scamRuleRepository.findByActiveTrue()) {
            String pattern = rule.getKeywordOrPattern();
            if (pattern != null && !pattern.isEmpty()) {
                String lowerPattern = pattern.toLowerCase(Locale.ROOT).trim();
                if (text.contains(lowerPattern)) {
                    score += rule.getWeight();
                    matches.add(new RuleMatch(
                            rule.getDescriptionEn(),
                            rule.getSourceUrl()
                    ));
                }
            }
        }

        score = Math.min(score, 100);
        String level = score < 30 ? "LOW" : score < 60 ? "MEDIUM" : "HIGH";

        if (matches.isEmpty()) {
            matches.add(new RuleMatch(
                    "No reviewed warning rules matched. This does not prove the message is safe.",
                    ""
            ));
        }

        history.record("MESSAGE", score, level);
        return new ScanResult(score, level, matches);
    }

    public record ScanRequest(String message) {}
    public record RuleMatch(String explanation, String sourceUrl) {}
    public record ScanResult(int score, String level, List<RuleMatch> matches) {}
}