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
import java.util.Formatter;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.fileinfo.FileAttributeType;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;

/**
 * Parser for the common FFS section header, which has the following fields:
 *
 * <pre>
 *   Common UEFI FFS Section Header
 *   +------+------+----------------------------------------+
 *   | Type | Size | Description                            |
 *   +------+------+----------------------------------------+
 *   | u24  |    3 | Size (0xFFFFFF for FFSv3 large files)  |
 *   | u8   |    1 | Type                                   |
 *   | u32  |    4 | Extended Size (FFSv3 large files only) |
 *   +------+------+----------------------------------------+
 * </pre>
 *
 * Subclasses will parse additional fields for specific FFS section types.
 */
public abstract class FFSSection implements UEFIFile {
	// Original header fields
	private final long size;
	private final byte type;

	private final long baseIndex;
	private final boolean hasExtendedSize;
	private final ByteProvider provider;

	/**
	 * Constructs a UEFIFFSFile from a specified BinaryReader.
	 *
	 * @param reader the specified BinaryReader
	 */
	public FFSSection(BinaryReader reader) throws IOException {
		baseIndex = reader.getPointerIndex();
		long totalLength = readValidatedTotalLength(reader, baseIndex,
				reader.getByteProvider().length() - baseIndex);
		byte[] sizeBytes = reader.readNextByteArray(3);
		type = reader.readNextByte();
		hasExtendedSize = ((sizeBytes[0] & 0xff) == 0xff &&
				(sizeBytes[1] & 0xff) == 0xff && (sizeBytes[2] & 0xff) == 0xff);
		if (hasExtendedSize) {
			reader.readNextUnsignedInt();
		}
		size = totalLength - getCommonHeaderLength();
		// Never dispatch to an incompletely initialized subclass from this constructor.
		provider = new ByteProviderWrapper(reader.getByteProvider(), reader.getPointerIndex(), size);
	}

	/**
	 * Validate both normal and extended section sizes against an enclosing region.
	 * Shared by the common constructor and all section traversals.
	 */
	static long readValidatedTotalLength(BinaryReader reader, long index, long remaining)
			throws IOException {
		if (remaining < UEFIFFSConstants.FFS_SECTION_HEADER_SIZE) {
			throw new IOException("Truncated FFS section header");
		}
		byte[] bytes = reader.getByteProvider().readBytes(index,
				UEFIFFSConstants.FFS_SECTION_SIZE_LENGTH);
		long total = (bytes[0] & 0xffL) | ((bytes[1] & 0xffL) << 8) |
				((bytes[2] & 0xffL) << 16);
		long header = UEFIFFSConstants.FFS_SECTION_HEADER_SIZE;
		if (total == UEFIFFSConstants.FFS_SECTION2_IS_USED) {
			header += Integer.BYTES;
			if (remaining < header) {
				throw new IOException("Truncated extended FFS section header");
			}
			total = Integer.toUnsignedLong(
					reader.readInt(index + UEFIFFSConstants.FFS_SECTION_HEADER_SIZE));
		}
		if (total < header || total > remaining) {
			throw new IOException(String.format(
					"Invalid FFS section size %d, expected %d..%d", total, header, remaining));
		}
		return total;
	}

	static int checkedByteArrayLength(long length) throws IOException {
		if (length < 0 || length > Integer.MAX_VALUE) {
			throw new IOException("FFS data exceeds the maximum Java array size");
		}
		return (int) length;
	}

	private int getCommonHeaderLength() {
		return UEFIFFSConstants.FFS_SECTION_HEADER_SIZE +
				(hasExtendedSize ? Integer.BYTES : 0);
	}

	/**
	 * Returns a ByteProvider for the contents of the current FFS section. Subclasses of FFSSection may override this
	 * as needed.
	 *
	 * @return a ByteProvider for the contents of the current FFS section
	 */
	public ByteProvider getByteProvider() {
		return provider;
	}

	/**
	 * Returns the length of the header for the current FFS section.
	 *
	 * @return the length of the header for the current FFS section
	 */
	public int getHeaderLength() {
		return getCommonHeaderLength();
	}

	/**
	 * Returns the total length of the current FFS section.
	 *
	 * @return the total length of the current FFS section
	 */
	public long getTotalLength() {
		return getHeaderLength() + length();
	}

	/**
	 * Returns the name of the current FFS section.
	 *
	 * @return the name of the current FFS section
	 */
	@Override
	public String getName() {
		return UEFIFFSConstants.SectionType.toString(type);
	}

	/**
	 * Returns the type for the current FFS section.
	 *
	 * @return the type for the current FFS section
	 */
	public byte getType() {
		return type;
	}

	/**
	 * Returns the length of the body in the current FFS section.
	 *
	 * @return the length of the body in the current FFS section
	 */
	@Override
	public long length() {
		return size;
	}

	/**
	 * Returns FileAttributes for the current FFS section.
	 *
	 * @return FileAttributes for the current FFS section
	 */
	@Override
	public FileAttributes getFileAttributes() {
		FileAttributes attributes = new FileAttributes();
		attributes.add(FileAttributeType.NAME_ATTR, getName());
		attributes.add(FileAttributeType.SIZE_ATTR, Long.valueOf(length()));
		attributes.add("Base", String.format("%#x", baseIndex));
		attributes.add("Section Type", UEFIFFSConstants.SectionType.toString(type));
		attributes.add("Header Size", getHeaderLength());
		return attributes;
	}
}
