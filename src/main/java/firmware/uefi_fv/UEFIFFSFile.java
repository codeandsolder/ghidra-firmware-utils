/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package firmware.uefi_fv;

import java.io.IOException;
import java.util.UUID;

import firmware.common.UUIDUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.formats.gfilesystem.FileSystemIndexHelper;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.fileinfo.FileAttributeType;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;

/**
 * Parser for UEFI Firmware File System (FFS) files, which have the following header:
 *
 *   UEFI FFS File Header
 *   +------------+------+----------------------------------------+
 *   | Type       | Size | Description                            |
 *   +------------+------+----------------------------------------+
 *   | efi_guid_t |   16 | File GUID                              |
 *   | u8         |    1 | Header Checksum                        |
 *   | u8         |    1 | File Checksum                          |
 *   | u8         |    1 | Type                                   |
 *   | u8         |    1 | Attributes                             |
 *   | u24        |    3 | Size (0xFFFFFF for FFSv3 large files)  |
 *   | u8         |    1 | State                                  |
 *   | u64        |    8 | Extended Size (FFSv3 large files only) |
 *   +------------+------+----------------------------------------+
 *
 * FFSv3 files can be identified by checking if FFS_ATTRIB_LARGE_FILE (0x01) is set in the
 * Attributes field.
 *
 * Following the header, FFS files may contain multiple sections (this does not apply for raw FFS
 * files). See FFSSection for information regarding the common FFS section header, as well as
 * UEFIFFSConstants.FileType for possible FFS file Type values.
 */
public class UEFIFFSFile implements UEFIFile {
	private static final String HEX_FORMAT = "%#x";
	// Original header fields
	private final UUID nameGuid;
	private final byte headerChecksum;
	private final byte fileChecksum;
	private final byte type;
	private final byte attributes;
	private long size;
	private final byte state;

	private final long baseIndex;
	private String uiName;

	/**
	 * Constructs a UEFIFFSFile from a specified BinaryReader and adds it to a
	 * specified FileSystemIndexHelper.
	 *
	 * @param reader the specified BinaryReader
	 * @param fsih   the specified {@link FileSystemIndexHelper} that handles files
	 * @param parent the parent directory in the specified FileSystemIndexHelper
	 */
	public UEFIFFSFile(BinaryReader reader, FileSystemIndexHelper<UEFIFile> fsih,
			GFile parent, long volumeEnd) throws IOException {
		baseIndex = reader.getPointerIndex();
		if (volumeEnd < baseIndex || volumeEnd - baseIndex < UEFIFFSConstants.FFS_HEADER_SIZE) {
			throw new IOException("Truncated FFS file header");
		}
		nameGuid = UUIDUtils.fromBinaryReader(reader);
		headerChecksum = reader.readNextByte();
		fileChecksum = reader.readNextByte();
		type = reader.readNextByte();
		attributes = reader.readNextByte();

		byte[] sizeBytes = reader.readNextByteArray(3);
		size = (sizeBytes[0] & 0xffL) | ((sizeBytes[1] & 0xffL) << 8) |
				((sizeBytes[2] & 0xffL) << 16);
		state = reader.readNextByte();

		int headerLength = UEFIFFSConstants.FFS_HEADER_SIZE;
		if ((attributes & UEFIFFSConstants.Attributes.LARGE_FILE) != 0) {
			if (size != 0xffffff || volumeEnd - reader.getPointerIndex() < Long.BYTES) {
				throw new IOException("Invalid FFS large-file header");
			}
			size = reader.readNextLong();
			headerLength += Long.BYTES;
		}
		else if (size == 0xffffff) {
			throw new IOException("Extended FFS file size without LARGE_FILE attribute");
		}
		if (size < headerLength || size > volumeEnd - baseIndex) {
			throw new IOException("FFS file extends outside firmware volume");
		}
		long fileEnd = baseIndex + size;

		// Padding files still use the normal (or large) file-size encoding.
		if (type == UEFIFFSConstants.FileType.PAD) {
			reader.setPointerIndex(fileEnd);
			return;
		}
		if (nameGuid.equals(UUID.fromString("ffffffff-ffff-ffff-ffff-ffffffffffff")) ||
				nameGuid.equals(UUID.fromString("00000000-0000-0000-0000-000000000000"))) {
			throw new IOException("Not a valid FFS file");
		}

		if (type != UEFIFFSConstants.FileType.RAW) {
			long payloadStart = reader.getPointerIndex();
			scanSections(reader, fileEnd, fsih, null, true);
			reader.setPointerIndex(payloadStart);
		}

		GFile fileImpl = fsih.storeFileWithParent(
				UEFIFirmwareVolumeFileSystem.getFSFormattedName(this, parent, fsih),
				parent, -1, true, -1, this);

		if (type == UEFIFFSConstants.FileType.RAW) {
			parseRawPayload(reader, fileEnd, fsih, fileImpl);
		}
		else {
			scanSections(reader, fileEnd, fsih, fileImpl, false);
		}
		reader.setPointerIndex(fileEnd);
	}

	/**
	 * Walk FFS sections using their declared sizes rather than trusting arbitrary parser cursor
	 * movement. Both the UI-name discovery pass and the indexing pass use identical boundaries.
	 */
	private void scanSections(BinaryReader reader, long fileEnd,
			FileSystemIndexHelper<UEFIFile> fsih, GFile parent, boolean nameOnly)
			throws IOException {
		while (fileEnd - reader.getPointerIndex() >= UEFIFFSConstants.FFS_SECTION_HEADER_SIZE) {
			long sectionStart = reader.getPointerIndex();
			long declared = FFSSection.readValidatedTotalLength(reader, sectionStart,
					fileEnd - sectionStart);
			FFSSection section = nameOnly
					? FFSSectionFactory.parseSection(reader)
					: FFSSectionFactory.parseSection(reader, fsih, parent);
			if (reader.getPointerIndex() > sectionStart + declared) {
				throw new IOException("FFS section parser exceeded its declared size");
			}
			if (nameOnly && section instanceof FFSUISection ui) {
				uiName = ui.getText();
				return;
			}
			long next = (sectionStart + declared + 3) & ~3L;
			reader.setPointerIndex(Math.min(next, fileEnd));
		}
	}

	/**
	 * Preserve raw bytes around embedded firmware volumes, not just the suffix after the last
	 * recognized volume. Failed candidates advance by one byte without losing preceding data.
	 */
	private static void parseRawPayload(BinaryReader reader, long fileEnd,
			FileSystemIndexHelper<UEFIFile> fsih, GFile parent) throws IOException {
		long rawStart = reader.getPointerIndex();
		long scan = rawStart;
		while (fileEnd - scan >= UEFIFirmwareVolumeConstants.UEFI_FV_HEADER_MIN_SIZE) {
			reader.setPointerIndex(scan);
			try {
				// A nested volume parser must not be allowed to cross this file boundary.
				UEFIFirmwareVolumeHeader header =
						new UEFIFirmwareVolumeHeader(reader, fsih, parent, true, fileEnd);
				if (scan > rawStart) {
					reader.setPointerIndex(rawStart);
					new FFSRawFile(reader, scan - rawStart, fsih, parent);
				}
				scan += header.length();
				rawStart = scan;
			}
			catch (IOException e) {
				scan++;
			}
		}
		if (rawStart < fileEnd) {
			reader.setPointerIndex(rawStart);
			new FFSRawFile(reader, fileEnd - rawStart, fsih, parent);
		}
	}


	/**
	 * Returns the GUID for the current FFS file.
	 *
	 * @return the GUID for the current FFS file
	 */
	public UUID getGUID() {
		return nameGuid;
	}

	/**
	 * Returns the name of the current FFS file.
	 *
	 * @return the name of the current FFS file
	 */
	@Override
	public String getName() {
		// Use the UI section text (if present).
		if (uiName != null) {
			return uiName;
		}

		// Fall back to the GUID database if the UI section isn't present.
		return UUIDUtils.getName(nameGuid);
	}

	/**
	 * Returns the length of the current FFS file.
	 *
	 * @return the length of the current FFS file
	 */
	@Override
	public long length() {
		return size;
	}

	/**
	 * Returns FileAttributes for the current FFS file.
	 *
	 * @return FileAttributes for the current FFS file
	 */
	@Override
	public FileAttributes getFileAttributes() {
		FileAttributes attributes = new FileAttributes();
		attributes.add(FileAttributeType.NAME_ATTR, getName());
		attributes.add(FileAttributeType.SIZE_ATTR, Long.valueOf(size));
		attributes.add("GUID", nameGuid.toString());
		attributes.add("Header Checksum", String.format(HEX_FORMAT, headerChecksum));
		attributes.add("File Checksum", String.format(HEX_FORMAT, fileChecksum));
		attributes.add("File Type", UEFIFFSConstants.FileType.toString(type));
		attributes.add("Attributes", String.format(HEX_FORMAT, this.attributes));
		attributes.add("State", String.format(HEX_FORMAT, state));
		return attributes;
	}
}
