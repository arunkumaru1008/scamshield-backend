package com.scamshield_backend;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import javax.imageio.IIOImage;
import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.ImageWriteParam;
import javax.imageio.ImageWriter;
import javax.imageio.stream.ImageInputStream;
import javax.imageio.stream.MemoryCacheImageOutputStream;

/**
 * Looks inside a JPEG or PNG file and reports "indicators" (rule codes such as IMG_EDITOR_SOFTWARE).
 * It never saves the image and never runs anything inside it. Weights and messages come from MySQL.
 */
public final class ImageAnalyzer {

    private ImageAnalyzer() {}

    public static final long MAX_FILE_BYTES = 10L * 1024 * 1024;
    public static final Set<String> SUPPORTED = Set.of("jpg", "jpeg", "png");
    private static final long MAX_PIXELS = 40_000_000L;
    private static final long MAX_ELA_PIXELS = 16_000_000L;

    public static final class Facts {
        public String type = "UNKNOWN";
        public int width, height;
        public long size;
        public String sha256 = "";
        public final Map<String, String> indicators = new LinkedHashMap<>();
        public String make = "", model = "", software = "";
        public LocalDateTime taken, changed;
        public boolean hasExif, hasMpf, c2pa;
        public final StringBuilder metaText = new StringBuilder();
        public final StringBuilder c2paText = new StringBuilder();
        public final StringBuilder tools = new StringBuilder();
        byte[] thumb;

        public void flag(String code, String detail) {
            indicators.putIfAbsent(code, detail == null ? "" : detail);
        }
    }

    // ---------- entry point ----------

    public static Facts analyze(String filename, byte[] d) {
        Facts f = new Facts();
        f.size = d.length;
        f.sha256 = sha256(d);
        String lower = filename == null ? "" : filename.toLowerCase(Locale.ROOT);
        String ext = lower.contains(".") ? lower.substring(lower.lastIndexOf('.') + 1) : "";
        f.type = detectType(d);

        String expected = switch (ext) {
            case "jpg", "jpeg" -> "JPEG";
            case "png" -> "PNG";
            default -> null;
        };
        if (expected != null && !expected.equals(f.type))
            f.flag("IMG_TYPE_MISMATCH", "named ." + ext + " but the content is " + describe(f.type));
        if (!f.type.equals("JPEG") && !f.type.equals("PNG")) return f;

        try {
            readSize(d, f);
            if (f.width <= 0) return f;
            if ((long) f.width * f.height > MAX_PIXELS) {
                f.flag("IMG_CORRUPT", "the picture is too large to inspect safely");
                return f;
            }
            if (f.type.equals("JPEG")) parseJpeg(d, f); else parsePng(d, f);
            appendedDataCheck(d, f);
            aiChecks(f);
            editorCheck(f);
            dateChecks(f);
            if (f.type.equals("JPEG")) {
                if (!f.hasExif) f.flag("IMG_NO_EXIF", "");
                BufferedImage main = (long) f.width * f.height <= MAX_ELA_PIXELS ? readImage(d) : null;
                if (main != null) {
                    thumbnailCheck(f, main);
                    elaCheck(f, main);
                }
            }
            typicalSizeCheck(f);
        } catch (Exception e) {
            f.flag("IMG_CORRUPT", "the image file is damaged or unusual");
        }
        return f;
    }

    // ---------- file type ----------

    private static String detectType(byte[] d) {
        if (d.length >= 2 && d[0] == 'M' && d[1] == 'Z') return "EXE";
        if (d.length >= 3 && (d[0] & 0xFF) == 0xFF && (d[1] & 0xFF) == 0xD8 && (d[2] & 0xFF) == 0xFF) return "JPEG";
        if (d.length >= 8 && (d[0] & 0xFF) == 0x89 && d[1] == 'P' && d[2] == 'N' && d[3] == 'G') return "PNG";
        if (d.length >= 6 && d[0] == 'G' && d[1] == 'I' && d[2] == 'F' && d[3] == '8') return "GIF";
        if (d.length >= 12 && d[0] == 'R' && d[1] == 'I' && d[2] == 'F' && d[3] == 'F' && d[8] == 'W' && d[9] == 'E') return "WEBP";
        if (d.length >= 5 && d[0] == '%' && d[1] == 'P' && d[2] == 'D' && d[3] == 'F') return "PDF";
        if (d.length >= 4 && d[0] == 'P' && d[1] == 'K' && d[2] == 3 && d[3] == 4) return "ZIP";
        return "UNKNOWN";
    }

    private static String describe(String type) {
        return switch (type) {
            case "EXE" -> "a Windows program";
            case "PDF" -> "a PDF document";
            case "ZIP" -> "a ZIP archive";
            case "GIF" -> "a GIF image";
            case "WEBP" -> "a WebP image";
            case "JPEG" -> "a JPEG image";
            case "PNG" -> "a PNG image";
            default -> "unknown data, not a normal picture";
        };
    }

    private static void readSize(byte[] d, Facts f) throws IOException {
        try (ImageInputStream in = ImageIO.createImageInputStream(new ByteArrayInputStream(d))) {
            Iterator<ImageReader> it = ImageIO.getImageReaders(in);
            if (!it.hasNext()) {
                f.flag("IMG_CORRUPT", "the image could not be read");
                return;
            }
            ImageReader r = it.next();
            try {
                r.setInput(in);
                f.width = r.getWidth(0);
                f.height = r.getHeight(0);
            } finally {
                r.dispose();
            }
        }
    }

    private static BufferedImage readImage(byte[] d) {
        try {
            return ImageIO.read(new ByteArrayInputStream(d));
        } catch (Exception e) {
            return null;
        }
    }

    // ---------- JPEG ----------

    private static void parseJpeg(byte[] d, Facts f) {
        int n = d.length;
        int i = 2;
        StringBuilder jumbf = new StringBuilder();
        while (i + 4 <= n) {
            if ((d[i] & 0xFF) != 0xFF) break;
            int marker = d[i + 1] & 0xFF;
            if (marker == 0xFF) { i++; continue; }
            if (marker == 0xD8 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7)) { i += 2; continue; }
            if (marker == 0xD9 || marker == 0xDA) break;
            int len = ((d[i + 2] & 0xFF) << 8) | (d[i + 3] & 0xFF);
            if (len < 2 || i + 2 + len > n) break;
            int start = i + 4, end = i + 2 + len;
            if (marker == 0xE1) {
                if (startsWith(d, start, "Exif\0\0")) {
                    parseTiff(d, start + 6, end, f);
                } else if (startsWith(d, start, "http://ns.adobe.com/xap/1.0/\0")) {
                    String xmp = new String(d, start + 29, end - start - 29, StandardCharsets.UTF_8);
                    f.metaText.append(xmp).append('\n');
                    collectXmpTools(xmp, f);
                }
            } else if (marker == 0xE2 && startsWith(d, start, "MPF\0")) {
                f.hasMpf = true;
            } else if (marker == 0xEB) {
                String seg = new String(d, start, end - start, StandardCharsets.ISO_8859_1);
                jumbf.append(seg);
                if (seg.contains("jumb") || seg.contains("c2pa")) f.c2pa = true;
            } else if (marker == 0xFE) {
                f.metaText.append(new String(d, start, end - start, StandardCharsets.ISO_8859_1)).append('\n');
            }
            i = end;
        }
        if (f.c2pa) f.c2paText.append(printable(jumbf.toString()));
    }

    private static int jpegEnd(byte[] d) {
        int n = d.length, i = 2;
        while (i + 1 < n) {
            if ((d[i] & 0xFF) != 0xFF) { i++; continue; }
            int m = d[i + 1] & 0xFF;
            if (m == 0xFF) { i++; continue; }
            if (m == 0x00 || m == 0xD8 || m == 0x01 || (m >= 0xD0 && m <= 0xD7)) { i += 2; continue; }
            if (m == 0xD9) return i + 2;
            if (i + 3 >= n) return -1;
            int len = ((d[i + 2] & 0xFF) << 8) | (d[i + 3] & 0xFF);
            i += 2 + len;
            if (m == 0xDA) {
                while (i + 1 < n) {
                    if ((d[i] & 0xFF) == 0xFF) {
                        int nx = d[i + 1] & 0xFF;
                        if (nx == 0x00 || (nx >= 0xD0 && nx <= 0xD7)) { i += 2; continue; }
                        if (nx == 0xFF) { i++; continue; }
                        break;
                    }
                    i++;
                }
            }
        }
        return -1;
    }

    // ---------- EXIF (TIFF structure) ----------

    private static void parseTiff(byte[] d, int base, int end, Facts f) {
        if (end - base < 8 || end > d.length) return;
        boolean le;
        if (d[base] == 'I' && d[base + 1] == 'I') le = true;
        else if (d[base] == 'M' && d[base + 1] == 'M') le = false;
        else return;
        f.hasExif = true;
        long ifd0 = u32(d, base + 4, le);
        Map<Integer, Object> t0 = readIfd(d, base, end, ifd0, le);
        f.make = str(t0.get(0x010F));
        f.model = str(t0.get(0x0110));
        f.software = str(t0.get(0x0131));
        f.changed = exifDate(str(t0.get(0x0132)));
        for (int tag : new int[] {0x010E, 0x013B, 0x9286}) {
            String v = str(t0.get(tag));
            if (!v.isEmpty()) f.metaText.append(v).append('\n');
        }
        Object exifPtr = t0.get(0x8769);
        if (exifPtr instanceof Long p) {
            Map<Integer, Object> te = readIfd(d, base, end, p, le);
            f.taken = exifDate(str(te.get(0x9003)));
            String uc = str(te.get(0x9286));
            if (!uc.isEmpty()) f.metaText.append(uc).append('\n');
        }
        // IFD1 holds the small preview picture
        int n0 = (int) Math.min(u16(d, (int) (base + ifd0), le), 500);
        long next = u32(d, (int) (base + ifd0 + 2 + 12L * n0), le);
        if (next > 0 && base + next + 2 < end) {
            Map<Integer, Object> t1 = readIfd(d, base, end, next, le);
            if (t1.get(0x0201) instanceof Long off && t1.get(0x0202) instanceof Long len
                    && len > 100 && len < 200_000 && base + off + len <= end) {
                f.thumb = Arrays.copyOfRange(d, (int) (base + off), (int) (base + off + len));
            }
        }
    }

    private static Map<Integer, Object> readIfd(byte[] d, int base, int end, long ifdOffset, boolean le) {
        Map<Integer, Object> out = new HashMap<>();
        long pos = base + ifdOffset;
        if (ifdOffset < 8 || pos + 2 > end) return out;
        int count = u16(d, (int) pos, le);
        if (count > 500) return out;
        for (int k = 0; k < count; k++) {
            long e = pos + 2 + 12L * k;
            if (e + 12 > end) break;
            int tag = u16(d, (int) e, le);
            int type = u16(d, (int) e + 2, le);
            long cnt = u32(d, (int) e + 4, le);
            int unit = switch (type) { case 1, 2, 7 -> 1; case 3 -> 2; case 4 -> 4; default -> 0; };
            if (unit == 0 || cnt < 0 || cnt > 100_000) continue;
            long bytes = cnt * unit;
            long valPos = bytes <= 4 ? e + 8 : base + u32(d, (int) e + 8, le);
            if (valPos < 0 || valPos + bytes > end) continue;
            switch (type) {
                case 2, 7 -> {
                    int len = (int) bytes;
                    while (len > 0 && d[(int) valPos + len - 1] == 0) len--;
                    out.put(tag, new String(d, (int) valPos, len, StandardCharsets.ISO_8859_1));
                }
                case 3 -> out.put(tag, (long) u16(d, (int) valPos, le));
                case 4 -> out.put(tag, u32(d, (int) valPos, le));
                default -> { }
            }
        }
        return out;
    }

    private static LocalDateTime exifDate(String s) {
        if (s == null || s.length() < 19) return null;
        try {
            return LocalDateTime.parse(s.substring(0, 19), DateTimeFormatter.ofPattern("yyyy:MM:dd HH:mm:ss"));
        } catch (Exception e) {
            return null;
        }
    }

    // ---------- PNG ----------

    private static void parsePng(byte[] d, Facts f) {
        int n = d.length, i = 8;
        StringBuilder caBX = new StringBuilder();
        while (i + 12 <= n) {
            long len = u32(d, i, false);
            String type = new String(d, i + 4, 4, StandardCharsets.ISO_8859_1);
            int ds = i + 8;
            if (len < 0 || ds + len + 4 > n) break;
            int de = (int) (ds + len);
            switch (type) {
                case "tEXt" -> {
                    int z = indexOfByte(d, ds, de, (byte) 0);
                    if (z > ds) {
                        String key = new String(d, ds, z - ds, StandardCharsets.ISO_8859_1);
                        String val = new String(d, z + 1, de - z - 1, StandardCharsets.ISO_8859_1);
                        addPngText(f, key, val);
                    }
                }
                case "zTXt" -> {
                    int z = indexOfByte(d, ds, de, (byte) 0);
                    if (z > ds && z + 2 < de) {
                        String key = new String(d, ds, z - ds, StandardCharsets.ISO_8859_1);
                        addPngText(f, key, inflate(d, z + 2, de));
                    }
                }
                case "iTXt" -> {
                    int z = indexOfByte(d, ds, de, (byte) 0);
                    if (z > ds && z + 3 < de) {
                        String key = new String(d, ds, z - ds, StandardCharsets.ISO_8859_1);
                        boolean compressed = d[z + 1] == 1;
                        int p = indexOfByte(d, z + 3, de, (byte) 0);          // end of language tag
                        if (p > 0) p = indexOfByte(d, p + 1, de, (byte) 0);   // end of translated keyword
                        if (p > 0 && p + 1 <= de) {
                            String val = compressed ? inflate(d, p + 1, de)
                                    : new String(d, p + 1, de - p - 1, StandardCharsets.UTF_8);
                            addPngText(f, key, val);
                        }
                    }
                }
                case "eXIf" -> parseTiff(d, ds, de, f);
                case "caBX" -> {
                    f.c2pa = true;
                    caBX.append(new String(d, ds, de - ds, StandardCharsets.ISO_8859_1));
                }
                default -> { }
            }
            if (type.equals("IEND")) break;
            i = (int) (ds + len + 4);
        }
        if (f.c2pa) f.c2paText.append(printable(caBX.toString()));
    }

    private static void addPngText(Facts f, String key, String val) {
        if (val == null) val = "";
        if (val.length() > 20_000) val = val.substring(0, 20_000);
        f.metaText.append(key).append(": ").append(val).append('\n');
        if (key.equalsIgnoreCase("Software") && f.software.isEmpty()) f.software = val.trim();
        if (key.equals("XML:com.adobe.xmp")) collectXmpTools(val, f);
    }

    private static int pngEnd(byte[] d) {
        int n = d.length, i = 8;
        while (i + 12 <= n) {
            long len = u32(d, i, false);
            if (len < 0 || i + 12L + len > n) return -1;
            String type = new String(d, i + 4, 4, StandardCharsets.ISO_8859_1);
            i = (int) (i + 12 + len);
            if (type.equals("IEND")) return i;
        }
        return -1;
    }

    private static String inflate(byte[] d, int from, int to) {
        Inflater inf = new Inflater();
        try {
            inf.setInput(d, from, Math.max(0, to - from));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            while (!inf.finished() && out.size() < 1_000_000) {
                int r = inf.inflate(buf);
                if (r == 0 && (inf.needsInput() || inf.needsDictionary())) break;
                out.write(buf, 0, r);
            }
            return out.toString(StandardCharsets.UTF_8);
        } catch (DataFormatException e) {
            return "";
        } finally {
            inf.end();
        }
    }

    // ---------- checks ----------

    private static final Pattern AI_SOURCE = Pattern.compile(
            "(?i)(compositeWithTrainedAlgorithmicMedia|trainedAlgorithmicMedia|compositeSynthetic)");
    private static final Pattern AI_GENERATOR = Pattern.compile(
            "(?i)\\b(midjourney|dall[\\s\\u00B7\\-]?e|stable[\\s\\-]?diffusion|comfyui|automatic1111|novelai|adobe firefly"
            + "|leonardo\\.ai|bing image creator|dreamstudio|sdxl|playground ?ai|ideogram|craiyon|nightcafe"
            + "|openai|chatgpt|invokeai|fooocus|imagen|flux)\\b");
    private static final Pattern AI_PARAMS = Pattern.compile(
            "(?is)(Steps:\\s*\\d+.{0,300}Sampler:|\"class_type\"|Negative prompt:|sd-metadata)");
    private static final Pattern EDITOR = Pattern.compile(
            "(?i)photoshop|lightroom|gimp|canva|picsart|snapseed|pixlr|facetune|photopea|paint\\.net|affinity photo"
            + "|corel|fotor|polarr|remini|meitu|lensa|picsay|photoscape|illustrator|adobe express|vsco");

    private static void aiChecks(Facts f) {
        if (f.c2pa) {
            Matcher m = AI_SOURCE.matcher(f.c2paText);
            if (m.find()) f.flag("IMG_AI_C2PA", "label: " + m.group());
            else f.flag("IMG_C2PA_PRESENT", "");
        }
        if (!f.indicators.containsKey("IMG_AI_C2PA")) {
            Matcher s = AI_SOURCE.matcher(f.metaText);
            if (s.find()) f.flag("IMG_AI_SOURCE_TYPE", "label: " + s.group());
        }
        Matcher g = AI_GENERATOR.matcher(f.metaText + "\n" + f.c2paText);
        if (g.find()) f.flag("IMG_AI_GENERATOR_TAG", "found: " + g.group().toLowerCase(Locale.ROOT));
        else if (AI_PARAMS.matcher(f.metaText).find()) f.flag("IMG_AI_GENERATOR_TAG", "AI prompt settings found");
    }

    private static void editorCheck(Facts f) {
        Matcher m = EDITOR.matcher(f.software + "\n" + f.tools);
        if (m.find()) f.flag("IMG_EDITOR_SOFTWARE", "tool: " + m.group());
    }

    private static void dateChecks(Facts f) {
        LocalDateTime now = LocalDateTime.now();
        if ((f.taken != null && f.taken.isAfter(now.plusDays(1)))
                || (f.changed != null && f.changed.isAfter(now.plusDays(1))))
            f.flag("IMG_FUTURE_DATE", "date inside the image: " + (f.taken != null ? f.taken : f.changed));
        if (f.taken != null && f.changed != null && f.changed.isAfter(f.taken.plusDays(1)))
            f.flag("IMG_MODIFIED_AFTER_CAPTURE", "taken " + f.taken.toLocalDate() + ", changed " + f.changed.toLocalDate());
    }

    private static void typicalSizeCheck(Facts f) {
        if (!f.hasExif && f.width >= 512 && f.height >= 512 && f.width % 64 == 0 && f.height % 64 == 0
                && !f.indicators.keySet().stream().anyMatch(k -> k.startsWith("IMG_AI_")))
            f.flag("IMG_AI_TYPICAL_SIZE", f.width + "x" + f.height);
    }

    private static void appendedDataCheck(byte[] d, Facts f) {
        int end = f.type.equals("JPEG") ? jpegEnd(d) : pngEnd(d);
        if (end <= 0 || end >= d.length) return;
        int extra = d.length - end;
        if (extra < 32) return;
        String meta = f.metaText.toString();
        boolean secondJpegWithMpf = f.hasMpf && d.length > end + 3
                && (d[end] & 0xFF) == 0xFF && (d[end + 1] & 0xFF) == 0xD8;
        boolean motionPhoto = meta.contains("MotionPhoto") || meta.contains("MicroVideo")
                || meta.contains("GCamera") || meta.contains("hdrgm") || indexOf(d, end, Math.min(d.length, end + 64), "ftyp") >= 0;
        boolean samsung = indexOf(d, Math.max(end, d.length - 32), d.length, "SEFT") >= 0
                || indexOf(d, end, Math.min(d.length, end + 64), "SEFH") >= 0;
        if (!secondJpegWithMpf && !motionPhoto && !samsung)
            f.flag("IMG_APPENDED_DATA", extra + " extra bytes after the end of the image");
    }

    private static void thumbnailCheck(Facts f, BufferedImage main) {
        if (f.thumb == null) return;
        BufferedImage tb = readImage(f.thumb);
        if (tb == null) return;
        double a1 = aspect(main.getWidth(), main.getHeight());
        double a2 = aspect(tb.getWidth(), tb.getHeight());
        boolean aspectDiff = Math.abs(a1 - a2) / a1 > 0.10;
        int[][] g1 = grid(main, 32), g2 = grid(tb, 32);
        double sum = 0;
        for (int y = 0; y < 32; y++) for (int x = 0; x < 32; x++) sum += Math.abs(g1[y][x] - g2[y][x]);
        double diff = sum / (32 * 32);
        if (aspectDiff || diff > 35)
            f.flag("IMG_THUMBNAIL_MISMATCH", aspectDiff ? "different shape from the stored preview" : "different content from the stored preview");
    }

    private static double aspect(int w, int h) {
        return (double) Math.max(w, h) / Math.max(1, Math.min(w, h));
    }

    private static int[][] grid(BufferedImage img, int n) {
        long[][] sum = new long[n][n];
        long[][] cnt = new long[n][n];
        int w = img.getWidth(), h = img.getHeight();
        for (int y = 0; y < h; y++) {
            int cy = (int) ((long) y * n / h);
            for (int x = 0; x < w; x++) {
                int c = img.getRGB(x, y);
                int gray = (((c >> 16) & 0xFF) * 3 + ((c >> 8) & 0xFF) * 6 + (c & 0xFF)) / 10;
                int cx = (int) ((long) x * n / w);
                sum[cy][cx] += gray;
                cnt[cy][cx]++;
            }
        }
        int[][] out = new int[n][n];
        for (int y = 0; y < n; y++) for (int x = 0; x < n; x++) out[y][x] = cnt[y][x] == 0 ? 0 : (int) (sum[y][x] / cnt[y][x]);
        return out;
    }

    /** Error Level Analysis: save again at quality 90 and see which blocks change much more than the rest. */
    private static void elaCheck(Facts f, BufferedImage src) {
        try {
            int w = src.getWidth(), h = src.getHeight();
            if (w < 64 || h < 64) return;
            BufferedImage rgb = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
            rgb.getGraphics().drawImage(src, 0, 0, null);
            ImageWriter writer = ImageIO.getImageWritersByFormatName("jpeg").next();
            ImageWriteParam param = writer.getDefaultWriteParam();
            param.setCompressionMode(ImageWriteParam.MODE_EXPLICIT);
            param.setCompressionQuality(0.90f);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try (MemoryCacheImageOutputStream out = new MemoryCacheImageOutputStream(bos)) {
                writer.setOutput(out);
                writer.write(null, new IIOImage(rgb, null, null), param);
            } finally {
                writer.dispose();
            }
            BufferedImage re = ImageIO.read(new ByteArrayInputStream(bos.toByteArray()));
            if (re == null) return;

            int bs = 16, bw = w / bs, bh = h / bs;
            if (bw < 4 || bh < 4) return;
            double[] means = new double[bw * bh];
            for (int by = 0; by < bh; by++) {
                for (int bx = 0; bx < bw; bx++) {
                    long total = 0;
                    for (int y = by * bs; y < by * bs + bs; y++) {
                        for (int x = bx * bs; x < bx * bs + bs; x++) {
                            int a = rgb.getRGB(x, y), b = re.getRGB(x, y);
                            total += Math.abs(((a >> 16) & 0xFF) - ((b >> 16) & 0xFF))
                                    + Math.abs(((a >> 8) & 0xFF) - ((b >> 8) & 0xFF))
                                    + Math.abs((a & 0xFF) - (b & 0xFF));
                        }
                    }
                    means[by * bw + bx] = total / (3.0 * bs * bs);
                }
            }
            double[] sorted = means.clone();
            Arrays.sort(sorted);
            double median = sorted[sorted.length / 2];
            double[] dev = new double[sorted.length];
            for (int i = 0; i < dev.length; i++) dev[i] = Math.abs(sorted[i] - median);
            Arrays.sort(dev);
            double mad = dev[dev.length / 2];
            double limit = median + 6 * Math.max(mad, 0.15) + 1.5;
            int outliers = 0;
            for (double m : means) if (m > limit) outliers++;
            double share = (double) outliers / means.length;
            if (outliers >= 4 && share >= 0.004 && share <= 0.35)
                f.flag("IMG_ELA_INCONSISTENT", outliers + " blocks of " + means.length + " differ from the rest");
        } catch (Exception ignored) {
            // ELA is only a hint. If it cannot run, the scan continues without it.
        }
    }

    // ---------- payment screenshot text checks ----------

    private static final String MONTHS = "jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec";
    private static final Pattern DATE1 = Pattern.compile(
            "\\b(\\d{1,2})(?:st|nd|rd|th)?[\\s\\-]+(" + MONTHS + ")[a-z]*[\\s,\\-]+(\\d{4})\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern DATE2 = Pattern.compile(
            "\\b(" + MONTHS + ")[a-z]*\\s+(\\d{1,2})(?:st|nd|rd|th)?,?\\s+(\\d{4})\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern DATE3 = Pattern.compile("\\b(\\d{1,2})[/\\-.](\\d{1,2})[/\\-.](\\d{4})\\b");

    /** Looks at the words read from a payment screenshot. Returns rule codes with a short detail. */
    public static Map<String, String> paymentIndicators(String text, LocalDate today) {
        Map<String, String> out = new LinkedHashMap<>();
        String t = text == null ? "" : text;
        boolean has12 = Pattern.compile("(?<!\\d)\\d{12}(?!\\d)").matcher(t).find();
        boolean hasT = Pattern.compile("\\bT\\d{12,25}\\b", Pattern.CASE_INSENSITIVE).matcher(t).find();
        boolean hasLong = Pattern.compile("(?<!\\d)\\d{8,20}(?!\\d)").matcher(t).find();
        if (!has12 && !hasT) out.put(hasLong ? "PAY_TXN_ID_FORMAT" : "PAY_NO_TXN_ID", "");
        LocalDate latest = null;
        for (LocalDate d : extractDates(t)) if (latest == null || d.isAfter(latest)) latest = d;
        if (latest != null && latest.isAfter(today.plusDays(1))) out.put("PAY_FUTURE_DATE", "date shown: " + latest);
        return out;
    }

    private static List<LocalDate> extractDates(String t) {
        List<LocalDate> list = new ArrayList<>();
        Matcher m = DATE1.matcher(t);
        while (m.find()) addDate(list, m.group(3), month(m.group(2)), m.group(1));
        m = DATE2.matcher(t);
        while (m.find()) addDate(list, m.group(3), month(m.group(1)), m.group(2));
        m = DATE3.matcher(t);
        while (m.find()) addDate(list, m.group(3), Integer.parseInt(m.group(2)), m.group(1));
        return list;
    }

    private static int month(String s) {
        return "janfebmaraprmayjunjulaugsepoctnovdec".indexOf(s.substring(0, 3).toLowerCase(Locale.ROOT)) / 3 + 1;
    }

    private static void addDate(List<LocalDate> list, String year, int month, String day) {
        try {
            int y = Integer.parseInt(year);
            if (y < 2000 || y > 2100) return;
            list.add(LocalDate.of(y, month, Integer.parseInt(day)));
        } catch (Exception ignored) { }
    }

    // ---------- small helpers ----------

    private static void collectXmpTools(String xmp, Facts f) {
        Matcher a = Pattern.compile("(?is)<xmp:CreatorTool>(.*?)</xmp:CreatorTool>").matcher(xmp);
        while (a.find()) f.tools.append(a.group(1)).append('\n');
        Matcher b = Pattern.compile("(?is)softwareAgent(?:=\"|>)([^\"<]{1,100})").matcher(xmp);
        while (b.find()) f.tools.append(b.group(1)).append('\n');
        Matcher c = Pattern.compile("(?is)xmp:CreatorTool=\"([^\"]{1,100})\"").matcher(xmp);
        while (c.find()) f.tools.append(c.group(1)).append('\n');
    }

    private static String printable(String s) {
        StringBuilder sb = new StringBuilder();
        int run = 0;
        for (char c : s.toCharArray()) {
            if (c >= 32 && c < 127) { sb.append(c); run++; }
            else { if (run >= 4) sb.append(' '); run = 0; }
        }
        return sb.toString();
    }

    private static String str(Object o) { return o instanceof String s ? s.trim() : ""; }

    private static boolean startsWith(byte[] d, int at, String s) {
        if (at < 0 || at + s.length() > d.length) return false;
        for (int i = 0; i < s.length(); i++) if (d[at + i] != (byte) s.charAt(i)) return false;
        return true;
    }

    private static int indexOf(byte[] d, int from, int to, String s) {
        for (int i = Math.max(0, from); i + s.length() <= Math.min(to, d.length); i++)
            if (startsWith(d, i, s)) return i;
        return -1;
    }

    private static int indexOfByte(byte[] d, int from, int to, byte b) {
        for (int i = from; i < to && i < d.length; i++) if (d[i] == b) return i;
        return -1;
    }

    private static int u16(byte[] d, int p, boolean le) {
        if (p < 0 || p + 2 > d.length) return 0;
        return le ? (d[p] & 0xFF) | ((d[p + 1] & 0xFF) << 8) : ((d[p] & 0xFF) << 8) | (d[p + 1] & 0xFF);
    }

    private static long u32(byte[] d, int p, boolean le) {
        if (p < 0 || p + 4 > d.length) return 0;
        long a = d[p] & 0xFFL, b = d[p + 1] & 0xFFL, c = d[p + 2] & 0xFFL, e = d[p + 3] & 0xFFL;
        return le ? a | (b << 8) | (c << 16) | (e << 24) : (a << 24) | (b << 16) | (c << 8) | e;
    }

    private static String sha256(byte[] d) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(d);
            StringBuilder sb = new StringBuilder();
            for (byte b : h) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}