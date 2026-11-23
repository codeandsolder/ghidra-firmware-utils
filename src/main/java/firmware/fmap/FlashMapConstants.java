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

package firmware.fmap;

import java.util.StringJoiner;

/**
 * Various Flash Map (FMAP) constants.
 */
public final class FlashMapConstants {
	// Flash Map signature
	public static final String FMAP_SIGNATURE = "__FMAP__";

	// Flash Map name length (including null terminator)
	public static final int FMAP_NAME_LEN = 32;

	// Flash area flags
	public static final class FlashAreaFlags {
		public static final byte STATIC = 1 << 0;
		public static final byte COMPRESSED = 1 << 1;
		public static final byte READ_ONLY = 1 << 2;
		public static final byte PRESERVE = 1 << 3;

		public static String toString(short flags) {
			StringJoiner names = new StringJoiner(" ");
			if ((flags & STATIC) != 0) {
				names.add("Static");
			}
			if ((flags & COMPRESSED) != 0) {
				names.add("Compressed");
			}
			if ((flags & READ_ONLY) != 0) {
				names.add("Read-only");
			}
			if ((flags & PRESERVE) != 0) {
				names.add("Preserved");
			}
			return names.length() == 0 ? "None" : names.toString();
		}
	}
}
