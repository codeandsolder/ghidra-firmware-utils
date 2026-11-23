package firmware.uefi_fv;

import java.io.IOException;
import java.util.Arrays;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.util.task.TaskMonitor;

import org.junit.jupiter.api.Test;

/**
 * Small synthetic-corpus regression harness; no installed firmware or GUI is required.
 * Run with Gradle verifyFfsParsing (also part of buildExtension).
 */
final class FFSSectionParsingTest {
	@Test
	void checkNormalSection() throws IOException {
		byte[] bytes = { 8, 0, 0, UEFIFFSConstants.SectionType.RAW, 1, 2, 3, 4 };
		BinaryReader reader = new BinaryReader(new ByteArrayProvider(bytes), true);
		FFSSection section = FFSSectionFactory.parseSection(reader);
		require(section.getTotalLength() == 8, "standard total size");
		require(section.getHeaderLength() == 4, "standard header size");
		require(section.length() == 4, "standard body size");
		require(reader.getPointerIndex() == 8, "standard reader position");
		require(Arrays.equals(section.getByteProvider().readBytes(0, 4),
				new byte[] { 1, 2, 3, 4 }), "standard body bytes");
	}

	@Test
	void checkExtendedSection() throws IOException {
		byte[] bytes = { (byte) 0xff, (byte) 0xff, (byte) 0xff,
				UEFIFFSConstants.SectionType.RAW, 12, 0, 0, 0, 5, 6, 7, 8 };
		BinaryReader reader = new BinaryReader(new ByteArrayProvider(bytes), true);
		FFSSection section = FFSSectionFactory.parseSection(reader);
		require(section.getTotalLength() == 12, "extended total size");
		require(section.getHeaderLength() == 8, "extended header size");
		require(section.length() == 4, "extended body size");
		require(reader.getPointerIndex() == 12, "extended reader position");
		require(Arrays.equals(section.getByteProvider().readBytes(0, 4),
				new byte[] { 5, 6, 7, 8 }), "extended body bytes");
	}

	@Test
	void checkInvalidLengths() throws IOException {
		expectInvalid(new byte[] { 3, 0, 0, 0 }, 4);
		expectInvalid(new byte[] { 12, 0, 0, 0 }, 8);
		expectInvalid(new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, 0 }, 4);
		expectInvalid(new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, 0,
				7, 0, 0, 0 }, 8);
		expectInvalid(new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, 0,
				0, 0, 0, (byte) 0x80 }, 8);
		// The child must not cross its enclosing section, even if the backing blob is larger.
		expectInvalid(new byte[] { 8, 0, 0, 0, 1, 2, 3, 4 }, 7);
	}

	@Test
	void checkVolumeSignatureScanning() throws Exception {
		byte[] exactlyOneHeader = new byte[64];
		writeSignature(exactlyOneHeader, 40);
		require(UEFIFirmwareVolumeHeader.findNext(new ByteArrayProvider(exactlyOneHeader),
				0, TaskMonitor.DUMMY) == 0, "signature in final possible position");
		byte[] unaligned = new byte[64 * 1024 + 70];
		writeSignature(unaligned, 64 * 1024 - 1);
		require(UEFIFirmwareVolumeHeader.findNext(new ByteArrayProvider(unaligned),
				0, TaskMonitor.DUMMY) == 64 * 1024 - 41, "unaligned chunk-boundary signature");
		require(UEFIFirmwareVolumeHeader.findNext(new ByteArrayProvider(unaligned),
				64 * 1024, TaskMonitor.DUMMY) == -1, "scan after final signature");
	}

	private static void writeSignature(byte[] bytes, int at) {
		bytes[at] = '_';
		bytes[at + 1] = 'F';
		bytes[at + 2] = 'V';
		bytes[at + 3] = 'H';
	}

	private static void expectInvalid(byte[] bytes, long regionLength) throws IOException {
		BinaryReader reader = new BinaryReader(new ByteArrayProvider(bytes), true);
		try {
			FFSSection.readValidatedTotalLength(reader, 0, regionLength);
			throw new AssertionError("Accepted invalid section length");
		}
		catch (IOException expected) {
			// Expected rejection, including unsigned overflow-sized extended headers.
		}
	}

	private static void require(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
