package com.scamshield_backend;

import java.net.URI;
import java.util.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/scan")
public class LinkController {

    record LinkRequest(String url) {}
    record LinkFinding(String reason, int points) {}
    record LinkResult(int score, String level, List<LinkFinding> findings) {}

    private final LinkRuleRepository linkRuleRepository;
    private final ScanHistoryService history;

    public LinkController(LinkRuleRepository linkRuleRepository, ScanHistoryService history) {
        this.linkRuleRepository = linkRuleRepository;
        this.history = history;
    }

    @PostMapping("/link")
    public LinkResult scanLink(@RequestBody LinkRequest req) {
        LinkResult result = analyze(req.url());
        history.record("LINK", result.score(), result.level());
        return result;
    }

    /** Does the checking without saving history, so the Email Checker can reuse it. */
    public LinkResult analyze(String url) {
        List<LinkFinding> found = new ArrayList<>();
        String raw = url == null ? "" : url.trim().toLowerCase();
        String withScheme = raw.contains("://") ? raw : "http://" + raw;

        String parsedHost = null;
        try {
            parsedHost = URI.create(withScheme).getHost();
        } catch (Exception e) {
            // invalid link, handled below
        }
        final String host = parsedHost;

        if (host == null || host.isBlank()) {
            found.add(new LinkFinding("This is not a valid link", 20));
        } else {
            // Checks that are built into the code (they look at the shape of the link)
            if (withScheme.startsWith("http://"))
                found.add(new LinkFinding("Link does not use secure https", 15));
            if (host.matches("\\d+\\.\\d+\\.\\d+\\.\\d+"))
                found.add(new LinkFinding("Link uses an IP address instead of a name", 40));
            if (raw.contains("@"))
                found.add(new LinkFinding("Link contains '@', a common trick to hide the real site", 30));
            if (host.chars().filter(c -> c == '-').count() >= 2)
                found.add(new LinkFinding("Domain has many hyphens", 15));
            if (host.split("\\.").length > 4)
                found.add(new LinkFinding("Domain has too many sub-parts", 15));
            if (raw.length() > 75)
                found.add(new LinkFinding("Link is unusually long", 10));

            // Checks that come from the link_rules table in MySQL
            boolean riskyEndingDone = false;
            boolean pressureWordDone = false;
            for (LinkRule rule : linkRuleRepository.findByActiveTrue()) {
                String type = rule.getRuleType();
                String value = rule.getRuleValue() == null ? "" : rule.getRuleValue().toLowerCase();
                if (value.isEmpty()) continue;

                if ("SHORTENER".equals(type) && host.equals(value)) {
                    found.add(new LinkFinding(rule.getDescriptionEn(), rule.getWeight()));

                } else if ("RISKY_ENDING".equals(type) && !riskyEndingDone && host.endsWith(value)) {
                    found.add(new LinkFinding(rule.getDescriptionEn(), rule.getWeight()));
                    riskyEndingDone = true;

                } else if ("PRESSURE_WORD".equals(type) && !pressureWordDone && raw.contains(value)) {
                    found.add(new LinkFinding(rule.getDescriptionEn(), rule.getWeight()));
                    pressureWordDone = true;

                } else if ("BRAND".equals(type) && host.contains(value)) {
                    boolean official = false;
                    if (rule.getOfficialDomains() != null) {
                        for (String d : rule.getOfficialDomains().split(",")) {
                            String domain = d.trim().toLowerCase();
                            if (!domain.isEmpty() && (host.equals(domain) || host.endsWith("." + domain))) {
                                official = true;
                                break;
                            }
                        }
                    }
                    if (!official)
                        found.add(new LinkFinding(rule.getDescriptionEn(), rule.getWeight()));
                }
            }
        }

        int score = Math.min(100, found.stream().mapToInt(LinkFinding::points).sum());
        String level = score < 30 ? "LOW" : score < 60 ? "MEDIUM" : "HIGH";
        if (found.isEmpty())
            found.add(new LinkFinding("No warning signs found. This does not prove the link is safe.", 0));
        return new LinkResult(score, level, found);
    }
}