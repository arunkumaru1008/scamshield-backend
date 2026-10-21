package com.scamshield_backend;

import java.util.*;
import java.util.regex.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/scan")
public class EmailController {

    record EmailRequest(String email) {}
    record EmailFinding(String reason, int points, String sourceUrl) {}
    record EmailResult(int score, String level, List<EmailFinding> findings) {}

    private static final Pattern FROM_LINE = Pattern.compile("(?im)^from:[ \\t]*(.+)$");
    private static final Pattern REPLY_TO_LINE = Pattern.compile("(?im)^reply-to:[ \\t]*(.+)$");
    private static final Pattern ADDRESS =
        Pattern.compile("([a-z0-9._%+-]+)@([a-z0-9.-]+\\.[a-z]{2,})", Pattern.CASE_INSENSITIVE);
    private static final Pattern URL_IN_TEXT = Pattern.compile("(?i)\\bhttps?://[^\\s<>\"')\\]]+");
    private static final Pattern SPF =
        Pattern.compile("(?i)\\bspf\\s*[:=]\\s*'?(pass|fail|softfail|neutral|none)");
    private static final Pattern DKIM =
        Pattern.compile("(?i)\\bdkim\\s*[:=]\\s*'?(pass|fail|neutral|none)");
    private static final Pattern DMARC =
        Pattern.compile("(?i)\\bdmarc\\s*[:=]\\s*'?(pass|fail|none)");

    private final ScamRuleRepository scamRuleRepository;
    private final LinkRuleRepository linkRuleRepository;
    private final LinkController linkController;
    private final ScanHistoryService history;

    public EmailController(ScamRuleRepository scamRuleRepository,
                           LinkRuleRepository linkRuleRepository,
                           LinkController linkController,
                           ScanHistoryService history) {
        this.scamRuleRepository = scamRuleRepository;
        this.linkRuleRepository = linkRuleRepository;
        this.linkController = linkController;
        this.history = history;
    }

    @PostMapping("/email")
    public EmailResult scanEmail(@RequestBody EmailRequest req) {
        List<EmailFinding> found = new ArrayList<>();
        String original = req.email() == null ? "" : req.email().trim();

        if (original.isEmpty()) {
            found.add(new EmailFinding("Nothing to check. Paste the email text first.", 0, null));
            return new EmailResult(0, "LOW", found);
        }

        // 1. Sender checks (From, Reply-To, SPF, DKIM, DMARC)
        Matcher fromMatcher = FROM_LINE.matcher(original);
        if (fromMatcher.find()) {
            String fromLine = fromMatcher.group(1).trim();
            Matcher addr = ADDRESS.matcher(fromLine);
            if (addr.find()) {
                String senderDomain = addr.group(2).toLowerCase();
                String displayName = fromLine.contains("<")
                    ? fromLine.substring(0, fromLine.indexOf('<')).replace("\"", "").trim().toLowerCase()
                    : "";

                // 1a. Is the sender domain itself suspicious? (same checks as the Link Checker)
                LinkController.LinkResult domainResult =
                    linkController.analyze("https://" + senderDomain);
                for (LinkController.LinkFinding f : domainResult.findings())
                    if (f.points() > 0)
                        found.add(new EmailFinding("Sender domain " + senderDomain + ": " + f.reason(), f.points(), null));

                // 1b. Does the sender name pretend to be a bank or government site?
                for (LinkRule rule : linkRuleRepository.findByActiveTrue()) {
                    if (!"BRAND".equals(rule.getRuleType()) || rule.getRuleValue() == null) continue;
                    String brand = rule.getRuleValue().toLowerCase();
                    if (!displayName.isEmpty() && displayName.contains(brand) && !isOfficial(senderDomain, rule))
                        found.add(new EmailFinding("Sender name mentions '" + brand
                            + "' but the email comes from " + senderDomain, rule.getWeight(), null));
                }

                // 1c. Do replies go to a different domain?
                Matcher replyLine = REPLY_TO_LINE.matcher(original);
                if (replyLine.find()) {
                    Matcher replyAddr = ADDRESS.matcher(replyLine.group(1));
                    if (replyAddr.find() && !replyAddr.group(2).equalsIgnoreCase(senderDomain))
                        found.add(new EmailFinding("Replies go to a different domain ("
                            + replyAddr.group(2).toLowerCase() + ") than the sender (" + senderDomain + ")", 25, null));
                }
            } else {
                found.add(new EmailFinding("The From line has no valid email address", 20, null));
            }

            // 1d. Sender authentication results, if the headers were pasted
            String spf = firstGroup(SPF, original);
            String dkim = firstGroup(DKIM, original);
            String dmarc = firstGroup(DMARC, original);
            if (spf == null && dkim == null && dmarc == null) {
                found.add(new EmailFinding("No SPF, DKIM or DMARC results found in the text, so sender authentication was not checked. "
                    + "Paste the full email headers for a deeper check.", 0, null));
            } else {
                boolean allPass = true;
                if (spf != null && spf.equals("fail")) {
                    found.add(new EmailFinding("SPF failed: the sending server is not approved by the sender's domain", 25, null));
                    allPass = false;
                } else if (spf != null && spf.equals("softfail")) {
                    found.add(new EmailFinding("SPF soft-failed: the sending server is probably not approved by the sender's domain", 15, null));
                    allPass = false;
                } else if (spf != null && !spf.equals("pass")) allPass = false;
                if (dkim != null && dkim.equals("fail")) {
                    found.add(new EmailFinding("DKIM failed: the email may have been changed or forged", 20, null));
                    allPass = false;
                } else if (dkim != null && !dkim.equals("pass")) allPass = false;
                if (dmarc != null && dmarc.equals("fail")) {
                    found.add(new EmailFinding("DMARC failed: the sender's domain rejects this email as not genuine", 30, null));
                    allPass = false;
                } else if (dmarc != null && !dmarc.equals("pass")) allPass = false;
                if (allPass)
                    found.add(new EmailFinding("Sender checks passed. This only shows the email came from the domain it claims, "
                        + "not that the domain is trustworthy.", 0, null));
            }
        } else {
            found.add(new EmailFinding("No From line found, so sender checks were skipped. "
                + "Paste the full email with headers for a deeper check.", 0, null));
        }

        // 2. Links inside the email (checked with the Link Checker)
        Set<String> urls = new LinkedHashSet<>();
        Matcher urlMatcher = URL_IN_TEXT.matcher(original);
        while (urlMatcher.find() && urls.size() < 10)
            urls.add(urlMatcher.group().replaceAll("[.,;]+$", ""));
        int linkPoints = 0;
        for (String url : urls) {
            LinkController.LinkResult lr = linkController.analyze(url);
            if (lr.score() >= 30 && linkPoints < 50) {
                int pts = Math.min(30, lr.score() / 2);
                linkPoints += pts;
                String shown = url.length() > 60 ? url.substring(0, 60) + "..." : url;
                found.add(new EmailFinding("Suspicious link in the email (" + lr.level() + "): " + shown, pts, null));
            }
        }

        // 3. Scam words in the email text (same rules as the Message Checker, from MySQL)
        String text = original.toLowerCase().replaceAll("\\s+", " ");
        for (ScamRule rule : scamRuleRepository.findByActiveTrue()) {
            String keyword = rule.getKeywordOrPattern() == null ? "" : rule.getKeywordOrPattern().toLowerCase();
            if (!keyword.isBlank() && text.contains(keyword))
                found.add(new EmailFinding(rule.getDescriptionEn(), rule.getWeight(), rule.getSourceUrl()));
        }

        found.sort(Comparator.comparingInt(EmailFinding::points).reversed());
        int score = Math.min(100, found.stream().mapToInt(EmailFinding::points).sum());
        String level = score < 30 ? "LOW" : score < 60 ? "MEDIUM" : "HIGH";
        if (score == 0)
            found.add(new EmailFinding("No warning signs found. This does not prove the email is safe.", 0, null));
        history.record("EMAIL", score, level);
        return new EmailResult(score, level, found);
    }

    private static String firstGroup(Pattern pattern, String text) {
        Matcher m = pattern.matcher(text);
        return m.find() ? m.group(1).toLowerCase() : null;
    }

    private static boolean isOfficial(String host, LinkRule rule) {
        if (rule.getOfficialDomains() == null) return false;
        for (String d : rule.getOfficialDomains().split(",")) {
            String domain = d.trim().toLowerCase();
            if (!domain.isEmpty() && (host.equals(domain) || host.endsWith("." + domain))) return true;
        }
        return false;
    }
}