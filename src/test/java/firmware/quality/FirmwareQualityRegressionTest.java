package firmware.quality;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Objects;

import firmware.cbfs.CBFSConstants;
import firmware.cbfs.CBFSFile;
import firmware.fmap.FlashMapConstants;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.formats.gfilesystem.fileinfo.FileAttribute;

import org.junit.jupiter.api.Test;

/** Self-contained regressions for small firmware metadata and flag encoders. */
final class FirmwareQualityRegressionTest {
	@Test
	void checkFlashMapFlagCombinations() {
		short flags = (short) (FlashMapConstants.FlashAreaFlags.STATIC |
				FlashMapConstants.FlashAreaFlags.COMPRESSED |
				FlashMapConstants.FlashAreaFlags.READ_ONLY |
				FlashMapConstants.FlashAreaFlags.PRESERVE);
		require(Objects.equals("Static Compressed Read-only Preserved",
				FlashMapConstants.FlashAreaFlags.toString(flags)), "all flash-area flags");
		require(Objects.equals("None", FlashMapConstants.FlashAreaFlags.toString((short) 0)),
				"empty flash-area flags");
	}

	@Test
	void checkCbfsCompressionMetadata() throws Exception {
		byte[] bytes = new byte[48];
		System.arraycopy(CBFSConstants.CBFS_FILE_SIGNATURE, 0, bytes, 0, 8);
		ByteBuffer header = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);
		header.putInt(8, 4); // Compressed data length.
		header.putInt(12, CBFSConstants.FileType.RAW);
		header.putInt(16, 28); // Compression attribute starts after file name.
		header.putInt(20, 44); // Data follows the attribute.
		bytes[24] = 't';
		bytes[25] = 0;
		header.putInt(28, CBFSConstants.AttributeTag.COMPRESSION);
		header.putInt(32, 16);
		header.putInt(36, CBFSConstants.CompressionAlgorithm.LZMA);
		header.putInt(40, 4);
		boolean lzma = false;
		boolean lz4 = false;
		try (ByteArrayProvider provider = new ByteArrayProvider(bytes)) {
			CBFSFile file = new CBFSFile(new BinaryReader(provider, false));
			for (FileAttribute<?> attribute : file.getFileAttributes().getAttributes()) {
				if ("Compression Type".equals(attribute.getAttributeDisplayName())) {
					lzma |= "LZMA".equals(attribute.getAttributeValue());
					lz4 |= "LZ4".equals(attribute.getAttributeValue());
				}
			}
		}
		require(lzma, "CBFS LZMA compression label");
		require(!lz4, "CBFS LZMA must not fall through to LZ4");
	}

	private static void require(boolean success, String reason) {
		if (!success) {
			throw new AssertionError(reason);
		}
	}
}
