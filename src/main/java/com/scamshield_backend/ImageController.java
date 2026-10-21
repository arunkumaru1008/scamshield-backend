package com.scamshield_backend;

import java.time.LocalDate;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/scan")
public class ImageController {

    record ImageFinding(String reason, int points, String sourceUrl) {}
    record ImageResult(int score, String level, String verdict, List<String> about, List<ImageFinding> findings) {}

    private static final Pattern URL_IN_TEXT =
            Pattern.compile("(?i)\\b(?:https?://|www\\.)[^\\s<>\"')\\]]+");
    private static final Set<String> EDIT_SIGNS =
            Set.of("IMG_ELA_INCONSISTENT", "IMG_EDITOR_SOFTWARE", "IMG_THUMBNAIL_MISMATCH");

    private final ImageRuleRepository imageRuleRepository;
    private final ScamRuleRepository scamRuleRepository;
    private final LinkController linkController;
    private final OcrService ocrService;
    private final ScanHistoryService history;

    public ImageController(ImageRuleRepository imageRuleRepository,
                           ScamRuleRepository scamRuleRepository,
                           LinkController linkController,
                           OcrService ocrService,
                           ScanHistoryService history) {
        this.imageRuleRepository = imageRuleRepository;
        this.scamRuleRepository = scamRuleRepository;
        this.linkController = linkController;
        this.ocrService = ocrService;
        this.history = history;
    }

    @PostMapping("/image")
    public ResponseEntity<?> scanImage(@RequestParam("file") MultipartFile file) {
        if (file == null || file.isEmpty())
        	
            return ResponseEntity.badRequest().body(Map.of("error", "Choose or capture an image first."));
        if (file.getSize() > ImageAnalyzer.MAX_FILE_BYTES)
            return ResponseEntity.badRequest().body(Map.of("error", "The image is too large. Maximum size is 10 MB."));

        String name = file.getOriginalFilename() == null ? "image" : file.getOriginalFilename();
        String lower = name.toLowerCase(Locale.ROOT);
        String ext = lower.contains(".") ? lower.substring(lower.lastIndexOf('.') + 1) : "";
        if (!ImageAnalyzer.SUPPORTED.contains(ext))
            return ResponseEntity.badRequest().body(Map.of("error",
                    "Only JPG and PNG images are supported. Please convert other types such as WebP or HEIC to JPG first."));

        byte[] data;
        try {
            data = file.getBytes();
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "The image could not be read."));
        }

        ImageAnalyzer.Facts facts = ImageAnalyzer.analyze(name, data);

        Map<String, ImageRule> byCode = new HashMap<>();
        List<ImageRule> keywordRules = new ArrayList<>();
        for (ImageRule r : imageRuleRepository.findByActiveTrue()) {
            if ("KEYWORD".equals(r.getDetection())) keywordRules.add(r);
            else byCode.put(r.getRuleCode(), r);
        }

        List<ImageFinding> found = new ArrayList<>();
        for (Map.Entry<String, String> e : facts.indicators.entrySet())
            addIndicator(found, byCode, e.getKey(), e.getValue());

        // Words inside the image (OCR)
        boolean readable = facts.type.equals("JPEG") || facts.type.equals("PNG");
        Optional<String> ocr = readable && !facts.indicators.containsKey("IMG_CORRUPT")
                ? ocrService.extractText(data, ext) : Optional.empty();
        String rawText = ocr.orElse("");
        String text = rawText.toLowerCase(Locale.ROOT).replaceAll("\\s+", " ").trim();

        Set<String> paymentWords = new HashSet<>();
        Set<String> keywordShown = new HashSet<>();
        for (ImageRule r : keywordRules) {
            if (r.getKeywordOrPattern() == null || r.getKeywordOrPattern().isBlank() || text.isEmpty()) continue;
            String kw = r.getKeywordOrPattern().toLowerCase(Locale.ROOT).trim();
            boolean hit = "WORD".equals(r.getMatchType())
                    ? Pattern.compile("\\b" + Pattern.quote(kw) + "\\b").matcher(text).find()
                    : text.contains(kw);
            if (!hit) continue;
            if ("PAYMENT_DETECT".equals(r.getCategory())) paymentWords.add(r.getRuleCode());
            else if (keywordShown.add(r.getRuleCode()))
                found.add(new ImageFinding(r.getDescriptionEn(), r.getWeight(), r.getSourceUrl()));
        }

        boolean payment = paymentWords.size() >= 2;
        if (payment) {
            addIndicator(found, byCode, "PAY_SCREENSHOT_DETECTED", "");
            addIndicator(found, byCode, "PAY_VERIFY_NOTE", "");
            for (Map.Entry<String, String> e : ImageAnalyzer.paymentIndicators(rawText, LocalDate.now()).entrySet())
                addIndicator(found, byCode, e.getKey(), e.getValue());
            if (facts.indicators.keySet().stream().anyMatch(EDIT_SIGNS::contains))
                addIndicator(found, byCode, "PAY_EDITED_SCREENSHOT", "");
        }

        // Links written inside the image
        Set<String> urls = new LinkedHashSet<>();
        Matcher um = URL_IN_TEXT.matcher(rawText);
        while (um.find() && urls.size() < 10) {
            String u = um.group().replaceAll("[.,;:]+$", "");
            urls.add(u.toLowerCase(Locale.ROOT).startsWith("www.") ? "https://" + u : u);
        }
        int linkPoints = 0;
        for (String url : urls) {
            LinkController.LinkResult lr = linkController.analyze(url);
            if (lr.score() >= 30 && linkPoints < 50) {
                int pts = Math.min(30, lr.score() / 2);
                linkPoints += pts;
                String shown = url.length() > 60 ? url.substring(0, 60) + "..." : url;
                found.add(new ImageFinding("Suspicious link written in the image (" + lr.level() + "): " + shown, pts, null));
            }
        }

        // Scam words in the image text (same rules as the Message Checker)
        for (ScamRule rule : scamRuleRepository.findByActiveTrue()) {
            String kw = rule.getKeywordOrPattern() == null ? "" : rule.getKeywordOrPattern().toLowerCase(Locale.ROOT);
            if (!kw.isBlank() && text.contains(kw))
                found.add(new ImageFinding(rule.getDescriptionEn(), rule.getWeight(), rule.getSourceUrl()));
        }

        found.sort(Comparator.comparingInt(ImageFinding::points).reversed());
        int score = Math.min(100, found.stream().mapToInt(ImageFinding::points).sum());
        String level = score < 30 ? "LOW" : score < 60 ? "MEDIUM" : "HIGH";

        boolean aiDeclared = facts.indicators.keySet().stream()
                .anyMatch(k -> k.equals("IMG_AI_C2PA") || k.equals("IMG_AI_SOURCE_TYPE") || k.equals("IMG_AI_GENERATOR_TAG"));
        boolean editSigns = facts.indicators.keySet().stream().anyMatch(EDIT_SIGNS::contains);

        String verdict;
        if (aiDeclared)
            verdict = "This is an AI-generated image. The image's own data says it was made by AI.";
        else if (payment && (score >= 30 || editSigns))
            verdict = "This looks like a payment screenshot with warning signs. Do not treat it as proof of payment.";
        else if (payment)
            verdict = "This looks like a payment screenshot. A screenshot is not proof of payment. Check your own bank or UPI app.";
        else if (level.equals("HIGH"))
            verdict = "This image has strong warning signs.";
        else if (level.equals("MEDIUM"))
            verdict = "This image has some warning signs.";
        else
            verdict = "No strong warning signs found. This does not prove the image is genuine.";

        List<String> about = new ArrayList<>();
        about.add(facts.type + " image" + (facts.width > 0 ? ", " + facts.width + " x " + facts.height + " pixels" : "")
                + ", " + Math.max(1, facts.size / 1024) + " KB");
        String camera = (facts.make + " " + facts.model).trim();
        if (!camera.isEmpty()) about.add("Camera: " + camera);
        if (facts.taken != null) about.add("Taken: " + facts.taken.toString().replace('T', ' '));
        if (!facts.software.isEmpty()) about.add("Made or last saved with: " + facts.software);
        if (facts.c2pa) about.add("Carries Content Credentials (a record of how it was made)");
        if (payment) about.add("Looks like a payment screenshot");
        else if (!camera.isEmpty()) about.add("Looks like a photo taken with a camera");
        if (ocr.isPresent()) {
            int words = text.isEmpty() ? 0 : text.split(" ").length;
            about.add(words == 0 ? "No readable text found in the image" : "Words read from the image: " + words);
        } else if (readable && !facts.indicators.containsKey("IMG_CORRUPT")) {
            about.add("Text reading (OCR) is not set up on this server, so words in the image were not checked");
        }

        if (score == 0)
            found.add(new ImageFinding("No warning signs found. This does not prove the image is genuine.", 0, null));
        found.add(new ImageFinding("Image fingerprint (SHA-256): " + facts.sha256
                + ". This tool checks the picture file and its text only. It is not a final proof either way.", 0, null));

        history.record("IMAGE", score, level);
        return ResponseEntity.ok(new ImageResult(score, level, verdict, about, found));
    }

    private static void addIndicator(List<ImageFinding> found, Map<String, ImageRule> byCode, String code, String detail) {
        ImageRule rule = byCode.get(code);
        if (rule == null) return;
        String reason = rule.getDescriptionEn()
                + (detail == null || detail.isBlank() ? "" : " (" + (detail.length() > 120 ? detail.substring(0, 120) : detail) + ")");
        found.add(new ImageFinding(reason, rule.getWeight(), rule.getSourceUrl()));
    }
}