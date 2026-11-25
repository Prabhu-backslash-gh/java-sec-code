package org.joychou.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;

/**
 * Path traversal test cases. Each handler holds one case, named in the comment
 * above it. Cases marked EXPLOITABLE can read files outside the base
 * directory; cases marked SAFE open files the same way but cannot leave it.
 */
@RestController
public class FileAccessCases {

    private static final String BASE_DIR = "/var/app/docs";
    private static final Set<String> ALLOWED_DOCS = Set.of("readme.txt", "terms.txt", "faq.txt");

    // EXPLOITABLE 1: name is appended to the base directory with no check
    @GetMapping("/files/read")
    public String read(@RequestParam String name) throws IOException {
        File f = new File(BASE_DIR, name);
        return new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
    }

    // EXPLOITABLE 2: the request value is used as the whole path
    @GetMapping("/files/stream")
    public String stream(@RequestParam String path) throws IOException {
        try (FileInputStream in = new FileInputStream(path)) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    // EXPLOITABLE 3: request value inside the path of a FileReader, only a suffix is added
    @GetMapping("/files/report")
    public String report(@RequestParam String report) throws IOException {
        try (BufferedReader in = new BufferedReader(new FileReader(BASE_DIR + "/reports/" + report + ".txt"))) {
            return in.readLine();
        }
    }

    // EXPLOITABLE 4: a "../" filter that is bypassed by "....//"
    @GetMapping("/files/weak")
    public String weak(@RequestParam String name) throws IOException {
        String cleaned = name.replace("../", "");
        File f = new File(BASE_DIR + "/" + cleaned);
        return new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
    }

    // SAFE 1: the resolved path is normalised and must stay under the base directory
    @GetMapping("/files/read-safe")
    public String readSafe(@RequestParam String name) throws IOException {
        Path base = Paths.get(BASE_DIR).toAbsolutePath().normalize();
        Path target = base.resolve(name).normalize();
        if (!target.startsWith(base)) {
            throw new IllegalArgumentException("outside base directory");
        }
        File f = new File(target.toString());
        return new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
    }

    // SAFE 2: only names from a fixed allowlist are opened
    @GetMapping("/files/doc")
    public String doc(@RequestParam String name) throws IOException {
        if (!ALLOWED_DOCS.contains(name)) {
            throw new IllegalArgumentException("unknown document");
        }
        File f = new File(BASE_DIR, name);
        return new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
    }

    // SAFE 3: the value must be a plain file name made of letters, digits and dots, with no separator or ".."
    @GetMapping("/files/plain")
    public String plain(@RequestParam String name) throws IOException {
        if (!name.matches("[A-Za-z0-9_]+\\.txt")) {
            throw new IllegalArgumentException("invalid name");
        }
        File f = new File(BASE_DIR, name);
        return new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
    }

    // SAFE 4: the request value only picks a number, the file name is built from it
    @GetMapping("/files/page")
    public String page(@RequestParam String number) throws IOException {
        int n = Integer.parseInt(number);
        File f = new File(BASE_DIR, "page" + n + ".txt");
        return new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
    }
}
