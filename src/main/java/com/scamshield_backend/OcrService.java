package com.scamshield_backend;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Reads the words inside an image by running the free Tesseract OCR program.
 * Returns Optional.empty() when Tesseract is not installed or fails, so the scan still works.
 * The image is written to a temporary file that is always deleted afterwards.
 */
@Service
public class OcrService {

    @Value("${scamshield.tesseract.path:tesseract}")
    private String tesseractPath;

    public Optional<String> extractText(byte[] image, String extension) {
        Path in = null;
        Path outBase = null;
        Path outTxt = null;
        try {
            in = Files.createTempFile("scamshield-in-", "." + extension);
            outBase = Files.createTempFile("scamshield-out-", "");
            outTxt = Path.of(outBase.toString() + ".txt");
            Files.write(in, image);

            ProcessBuilder pb = new ProcessBuilder(
                    tesseractPath, in.toString(), outBase.toString(), "-l", "eng");
            pb.redirectErrorStream(true);
            pb.redirectOutput(ProcessBuilder.Redirect.DISCARD);
            Process p = pb.start();
            if (!p.waitFor(30, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return Optional.empty();
            }
            if (p.exitValue() != 0 || !Files.exists(outTxt)) return Optional.empty();
            String text = Files.readString(outTxt, StandardCharsets.UTF_8);
            return Optional.of(text.length() > 50_000 ? text.substring(0, 50_000) : text);
        } catch (IOException e) {
            return Optional.empty();            // Tesseract not installed or not found
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        } finally {
            deleteQuietly(in);
            deleteQuietly(outBase);
            deleteQuietly(outTxt);
        }
    }

    private static void deleteQuietly(Path p) {
        if (p == null) return;
        try { Files.deleteIfExists(p); } catch (IOException ignored) { }
    }
}