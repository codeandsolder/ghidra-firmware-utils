// Source-bound AMD firmware provenance from Zen3inator JSON inventories.
// @category Firmware
// @menupath Tools.Firmware.Apply AMD Firmware Provenance

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;

/**
 * Apply original ROM provenance to source-verified UEFI executable imports, or
 * place AMD FET/PSP/BIOS directory bookmarks on a raw imported firmware image.
 *
 * The manifest must be generated from the original source by Zen3inator
 * (executable-extract-batch index.json, or inspect --json layout.json).
 * Binary and original ROM SHA-256 values are verified before mutation;
 * the script does not guess PSP addresses, key ownership or CPU support.
 */
public class AMDFirmwareProvenance extends GhidraScript {
    private static final String GROUP = "AMD Firmware Source";
    private static final String BOOKMARK_TYPE = "Note";

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1 || currentProgram == null) {
            throw new IOException("Expected one verified Zen3inator index.json or layout.json");
        }
        Path manifest = Path.of(args[0]).toAbsolutePath().normalize();
        JsonElement root;
        try (var reader = Files.newBufferedReader(manifest)) {
            root = JsonParser.parseReader(reader);
        }
        if (root.isJsonArray()) {
            applyExecutable(manifest, root.getAsJsonArray());
        } else if (root.isJsonObject()) {
            applyRom(manifest, root.getAsJsonObject());
        } else {
            throw new IOException("Manifest root must be the executable array or ROM layout object");
        }
    }

    private static String get(JsonObject object, String field) throws IOException {
        JsonElement value = object.get(field);
        if (value == null || value.isJsonNull() || !value.isJsonPrimitive()) {
            throw new IOException("Missing original firmware field: " + field);
        }
        return value.getAsString();
    }

    private static long number(JsonObject object, String field) throws IOException {
        JsonElement value = object.get(field);
        if (value == null || value.isJsonNull() || !value.isJsonPrimitive()) {
            throw new IOException("Missing original firmware number: " + field);
        }
        return value.getAsLong();
    }

    private static String sha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = Files.newInputStream(path)) {
            byte[] buffer = new byte[1 << 15];
            int count;
            while ((count = input.read(buffer)) >= 0) {
                if (count > 0) {
                    digest.update(buffer, 0, count);
                }
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static boolean digest(String candidate) {
        return candidate.matches("[0-9a-f]{64}");
    }

    private static String cleanName(String name) {
        String sanitized = name.replaceAll("[^A-Za-z0-9_.-]", "_");
        return sanitized.substring(0, Math.min(sanitized.length(), 64));
    }

    private void requireOriginal(Path path, String expected) throws Exception {
        if (!digest(expected) || !Files.isRegularFile(path)
                || !sha256(path).equals(expected)) {
            throw new IOException("Original firmware binary SHA-256 mismatch: " + path);
        }
    }

    private void verifyImportedPath(Path actual) throws Exception {
        String source = currentProgram.getExecutablePath();
        if (source == null || source.isBlank()) {
            throw new IOException("Loaded Ghidra program has no original executable path");
        }
        Path imported = Path.of(source).toRealPath();
        if (!imported.equals(actual.toRealPath())) {
            throw new IOException("Program source path does not match original manifest: " + source);
        }
    }

    private void applyExecutable(Path manifest, JsonArray records) throws Exception {
        String importedName = currentProgram.getName();
        JsonObject selected = null;
        for (JsonElement element : records) {
            JsonObject entry = element.getAsJsonObject();
            if (importedName.equals(get(entry, "binary"))) {
                if (selected != null) {
                    throw new IOException("Duplicate executable export basename: " + importedName);
                }
                selected = entry;
            }
        }
        if (selected == null) {
            throw new IOException("Imported module is absent from source index: " + importedName);
        }

        JsonObject source = selected.getAsJsonObject("source");
        JsonObject original = selected.getAsJsonObject("original");
        if (source == null || original == null) {
            throw new IOException("Missing qualified executable source/record metadata");
        }
        String[] identical = {
            "file_guid", "file_sha256", "rom_root_section", "origin_layer",
            "virtual_file_offset", "decoded_layer_sha256",
            "virtual_section_offset", "executable_sha256"
        };
        for (String field : identical) {
            if (!get(source, field).equals(get(original, field))) {
                throw new IOException("Executable lineage disagrees: " + field);
            }
        }
        String originalSha = get(source, "executable_sha256");
        Path binary = manifest.getParent().resolve(importedName).normalize();
        requireOriginal(binary, originalSha);
        verifyImportedPath(binary);
        Options info = currentProgram.getOptions(Program.PROGRAM_INFO);
        info.setString(GROUP + " / ROM SHA-256", get(source, "rom_sha256"));
        info.setString(GROUP + " / FFS GUID", get(source, "file_guid"));
        info.setString(GROUP + " / FFS SHA-256", get(source, "file_sha256"));
        info.setString(GROUP + " / Decoder SHA-256", get(source, "decoded_layer_sha256"));
        info.setString(GROUP + " / Executable SHA-256", originalSha);
        info.setString(GROUP + " / Physical root offset", get(source, "rom_root_section"));
        info.setString(GROUP + " / Origin layer", get(source, "origin_layer"));
        info.setString(GROUP + " / Virtual FFS offset", get(source, "virtual_file_offset"));
        info.setString(GROUP + " / Virtual section offset", get(source, "virtual_section_offset"));
        info.setString(GROUP + " / FFS type", get(original, "file_type"));
        info.setString(GROUP + " / Executable section type", get(original, "section_type"));

        JsonElement name = original.get("file_name");
        String moduleName = name == null || name.isJsonNull() || name.getAsString().isBlank()
                ? "unnamed" : name.getAsString();
        info.setString(GROUP + " / Original module name", moduleName);
        String named = cleanName(moduleName) + "__"
                + get(source, "file_guid").substring(0, 8) + "__"
                + importedName.substring(0, importedName.lastIndexOf('.'));
        currentProgram.setName(named);
        println("Verified UEFI executable " + named + " from "
                + get(source, "rom_sha256").substring(0, 16));
    }

    private Address mapped(long romOffset, long imageOffset, long length) throws Exception {
        long offset = Math.addExact(romOffset, imageOffset);
        if (imageOffset < 0 || length < 0 || offset < 0) {
            throw new IOException("Invalid negative firmware ROM offset or extent");
        }
        Address base = currentProgram.getMinAddress();
        if (base == null) {
            throw new IOException("No mapped raw ROM memory");
        }
        Address address = base.add(offset);
        if (!currentProgram.getMemory().contains(address)) {
            throw new IOException("Referenced AMD firmware address not mapped: " + address);
        }
        return address;
    }

    private void bookmark(Address address, String category, String description) {
        currentProgram.getBookmarkManager().setBookmark(
                address, BOOKMARK_TYPE, category, description);
    }

    private void applyRom(Path manifest, JsonObject layout) throws Exception {
        String originalSha = get(layout, "input_sha256");
        String romSha = get(layout, "rom_sha256");
        if (!digest(romSha)) {
            throw new IOException("Invalid source ROM SHA-256");
        }
        Path original = Path.of(currentProgram.getExecutablePath()).toAbsolutePath().normalize();
        requireOriginal(original, originalSha);
        verifyImportedPath(original);
        long romOffset = number(layout, "rom_offset");
        long romSize = number(layout, "rom_size");
        if (romSize <= 0 || romOffset < 0 || romOffset + romSize > Files.size(original)) {
            throw new IOException("ROM region is not within original input");
        }
        Options info = currentProgram.getOptions(Program.PROGRAM_INFO);
        info.setString(GROUP + " / ROM SHA-256", romSha);
        info.setString(GROUP + " / Source SHA-256", originalSha);
        info.setString(GROUP + " / ROM offset", Long.toString(romOffset));
        info.setString(GROUP + " / ROM bytes", Long.toString(romSize));
        bookmark(mapped(romOffset, number(layout.getAsJsonObject("fet"), "rom_offset"), romSize),
                "AMD Firmware FET", "Original signed-root entry table");

        int roots = 0;
        int references = 0;
        JsonArray directories = layout.getAsJsonArray("directories");
        for (JsonElement element : directories) {
            JsonObject directory = element.getAsJsonObject();
            String kind = get(directory, "kind");
            long at = number(directory, "rom_offset");
            bookmark(mapped(romOffset, at, romSize), "AMD " + kind + " directory",
                    "Original " + kind + " directory; entries=" + get(directory, "entries")
                    + "; checksum_valid=" + get(directory, "checksum_valid"));
            roots++;
            JsonArray entries = directory.getAsJsonArray("references");
            for (JsonElement child : entries) {
                JsonObject ref = child.getAsJsonObject();
                JsonElement target = ref.get("rom_offset");
                if (target == null || target.isJsonNull()
                        || !ref.get("within_rom").getAsBoolean()) {
                    continue;
                }
                long phys = target.getAsLong();
                long size = number(ref, "declared_size");
                // Zero-size directory references are absent payloads, not
                // flash objects at the beginning of the image.
                if (size == 0) {
                    continue;
                }
                if (size < 0 || phys < 0 || phys >= romSize
                        || size > romSize - phys) {
                    throw new IOException("Resolved AMD reference escapes original ROM");
                }
                Address address = mapped(romOffset, phys, romSize);
                bookmark(address, "AMD " + kind + " root 0x"
                        + Long.toHexString(at) + " entry " + get(ref, "index"),
                        "Type 0x" + Integer.toHexString(ref.get("entry_type").getAsInt())
                        + " index=" + get(ref, "index") + " size=" + size
                        + " directory_root=0x" + Long.toHexString(at)
                        + " physical=0x" + Long.toHexString(phys)
                        + " raw_addr=" + get(ref, "raw_address"));
                references++;
            }
        }
        println("Verified original ROM " + romSha.substring(0, 16)
                + "; AMD directory bookmarks=" + roots
                + " resolved entry bookmarks=" + references);
    }
}
