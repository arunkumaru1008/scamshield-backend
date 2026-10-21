package com.scamshield_backend;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/scan")
public class DocumentController {

    record DocFinding(String reason, int points) {}
    record DocResult(String fileName, String fileType, int score, String level, List<DocFinding> findings) {}

    private static final Set<String> DOC_EXT = Set.of("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png");
    private static final Set<String> ZIP_EXT = Set.of("docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "dotm");
    private static final Set<String> OLE_EXT = Set.of("doc", "xls", "ppt");
    private static final int MAX_ENTRY_BYTES = 2_000_000;
    private static final int MAX_TOTAL_BYTES = 20_000_000;
    private static final int MAX_ENTRIES = 2000;
    private static final int SCAM_TEXT_CAP = 40;

    private final DocRuleRepository docRuleRepository;
    private final ScanHistoryService history;

    public DocumentController(DocRuleRepository docRuleRepository, ScanHistoryService history) {
        this.docRuleRepository = docRuleRepository;
        this.history = history;
    }
    @PostMapping(value = "/document", consumes = "multipart/form-data")
    public DocResult scanDocument(@RequestParam("file") MultipartFile file) throws IOException {
        List<DocFinding> found = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        List<DocRule> rules = docRuleRepository.findByActiveTrue();

        byte[] data = file.getBytes();
        String name = file.getOriginalFilename() == null ? "unknown" : file.getOriginalFilename();
        String lower = name.toLowerCase();
        String[] parts = lower.split("\\.");
        String ext = parts.length > 1 ? parts[parts.length - 1].trim() : "";
        String inner = parts.length > 2 ? parts[parts.length - 2].trim() : "";

        // ---------- 1. File name checks ----------
        if (name.contains("\u202e"))
            add(found, seen, "File name uses a hidden right-to-left character to disguise its real extension", 50);

        for (DocRule r : rules) {
            String v = r.getRuleValue().toLowerCase();
            if ("DANGEROUS_EXT".equals(r.getRuleType()) && v.equals(ext)) {
                if (DOC_EXT.contains(inner))
                    add(found, seen, "Double extension: looks like a ." + inner + " file but is really ." + ext, r.getWeight());
                else
                    add(found, seen, r.getDescriptionEn(), r.getWeight());
            } else if ("MACRO_EXT".equals(r.getRuleType()) && v.equals(ext)) {
                add(found, seen, r.getDescriptionEn(), r.getWeight());
            }
        }

        // ---------- 2. Real file type (from the first bytes, not the name) ----------
        String head = new String(data, 0, Math.min(1024, data.length), StandardCharsets.ISO_8859_1);
        boolean isPdf = head.contains("%PDF-");
        boolean isZip = data.length > 3 && data[0] == 0x50 && data[1] == 0x4B;
        boolean isOle = data.length > 7 && (data[0] & 0xFF) == 0xD0 && (data[1] & 0xFF) == 0xCF
                && (data[2] & 0xFF) == 0x11 && (data[3] & 0xFF) == 0xE0;
        boolean isExe = data.length > 1 && data[0] == 'M' && data[1] == 'Z';

        if (isExe)
            add(found, seen, "File is really a Windows program, whatever its name says", 60);

        boolean mismatch = ("pdf".equals(ext) && !isPdf)
                || (ZIP_EXT.contains(ext) && !isZip)
                || (OLE_EXT.contains(ext) && !isOle);
        if (mismatch)
            add(found, seen, "File content does not match its extension (a disguised file)", 30);

        // ---------- 3. Deep scan by real type ----------
        String type;
        if (isPdf) {
            type = "PDF";
            scanPdf(data, rules, found, seen);
        } else if (isZip) {
            type = "Office document (new format)";
            scanOffice(data, rules, found, seen);
        } else if (isOle) {
            type = "Office document (old format)";
            scanOle(data, rules, found, seen);
        } else {
            type = isExe ? "Program" : "Unknown";
            if (!isExe)
                add(found, seen, "Unsupported or unknown file type, so it could not be inspected", 20);
        }

        int score = Math.min(100, found.stream().mapToInt(DocFinding::points).sum());
        String level = score < 30 ? "LOW" : score < 60 ? "MEDIUM" : "HIGH";
        if (found.isEmpty())
            found.add(new DocFinding("No warning signs found. This does not prove the file is safe.", 0));

        history.record("DOCUMENT", score, level);
        return new DocResult(name, type, score, level, found);
    }

    // ---------------- PDF ----------------
    private void scanPdf(byte[] data, List<DocRule> rules, List<DocFinding> found, Set<String> seen) {
        String raw = new String(data, StandardCharsets.ISO_8859_1);
        for (DocRule r : rules) {
            if (!"PDF_TOKEN".equals(r.getRuleType())) continue;
            Pattern p = Pattern.compile(Pattern.quote(r.getRuleValue()) + "(?![A-Za-z0-9])");
            if (p.matcher(raw).find())
                add(found, seen, r.getDescriptionEn(), r.getWeight());
        }
        String text = "";
        try (PDDocument doc = Loader.loadPDF(data)) {
            PDFTextStripper stripper = new PDFTextStripper();
            stripper.setEndPage(20);
            text = stripper.getText(doc);
            if (text.trim().length() < 20)
                add(found, seen, "PDF has almost no readable text (may be a scanned image)", 5);
        } catch (Exception e) {
            add(found, seen, "Could not read the text of this PDF (damaged or protected)", 10);
        }
        scanText(text, rules, found, seen);
    }

    // ---------------- Word / Excel / PowerPoint (zip based) ----------------
    private void scanOffice(byte[] data, List<DocRule> rules, List<DocFinding> found, Set<String> seen) {
        StringBuilder blob = new StringBuilder();
        StringBuilder text = new StringBuilder();
        int total = 0, count = 0;
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(data))) {
            ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                if (++count > MAX_ENTRIES) {
                    add(found, seen, "Document contains an unusually large number of parts", 15);
                    break;
                }
                String n = e.getName().toLowerCase();
                blob.append(n).append('\n');
                if (e.isDirectory() || !(n.endsWith(".xml") || n.endsWith(".rels"))) continue;

                byte[] buf = readCapped(zis, MAX_ENTRY_BYTES);
                if (buf == null) {
                    add(found, seen, "Document contains an unusually large part (possible zip bomb)", 20);
                    break;
                }
                total += buf.length;
                if (total > MAX_TOTAL_BYTES) break;

                String s = new String(buf, StandardCharsets.UTF_8).toLowerCase();
                blob.append(s).append('\n');
                if (n.equals("word/document.xml") || n.equals("xl/sharedstrings.xml") || n.startsWith("ppt/slides/slide"))
                    text.append(stripXml(s)).append(' ');
            }
        } catch (IOException ex) {
            add(found, seen, "Document is damaged or not a valid Office file", 15);
        }

        String all = blob.toString();
        for (DocRule r : rules) {
            if (!"OFFICE_PART".equals(r.getRuleType())) continue;
            if (all.contains(r.getRuleValue().toLowerCase()))
                add(found, seen, r.getDescriptionEn(), r.getWeight());
        }
        scanText(text.toString(), rules, found, seen);
    }

    // ---------------- Old .doc / .xls / .ppt ----------------
    private void scanOle(byte[] data, List<DocRule> rules, List<DocFinding> found, Set<String> seen) {
        String raw = new String(data, StandardCharsets.ISO_8859_1);
        add(found, seen, "Old Office format cannot be fully inspected", 10);
        if (raw.contains("V\0B\0A\0") || raw.contains("M\0a\0c\0r\0o\0s\0")) {
            int w = 50;
            for (DocRule r : rules)
                if ("OFFICE_PART".equals(r.getRuleType()) && "vbaproject.bin".equalsIgnoreCase(r.getRuleValue()))
                    w = r.getWeight();
            add(found, seen, "Document contains VBA macros", w);
        }
        scanText(raw.replace("\0", ""), rules, found, seen);
    }

    // ---------------- Scam wording (shared) ----------------
    private void scanText(String text, List<DocRule> rules, List<DocFinding> found, Set<String> seen) {
        String t = text.toLowerCase().replaceAll("\\s+", " ");
        int used = 0;
        for (DocRule r : rules) {
            if (!"SCAM_TEXT".equals(r.getRuleType())) continue;
            Pattern p = Pattern.compile("\\b" + Pattern.quote(r.getRuleValue().toLowerCase()) + "\\b");
            if (p.matcher(t).find()) {
                int pts = Math.min(r.getWeight(), SCAM_TEXT_CAP - used);
                used += pts;
                add(found, seen, r.getDescriptionEn(), pts);
            }
        }
    }

    // ---------------- Helpers ----------------
    private static void add(List<DocFinding> found, Set<String> seen, String reason, int pts) {
        if (seen.add(reason)) found.add(new DocFinding(reason, pts));
    }

    private static byte[] readCapped(ZipInputStream in, int max) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            out.write(buf, 0, n);
            if (out.size() > max) return null;
        }
        return out.toByteArray();
    }

    private static String stripXml(String x) {
        return x.replaceAll("</w:p>|</a:p>|<w:br/>|<w:tab/>", " ")
                .replaceAll("<[^>]+>", "")
                .replace("&amp;", "&");
    }
}