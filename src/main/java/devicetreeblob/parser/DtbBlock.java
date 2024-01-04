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
package devicetreeblob.parser;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import devicetreeblob.parser.Dtb.FdtBeginNode;
import devicetreeblob.parser.Dtb.FdtProp;

public class DtbBlock {
	private String mName;
	Map<String, byte[]> mProperties;

	public DtbBlock(FdtBeginNode node) {
		mName = node.name();
		mProperties = new HashMap<>();
	}

	public void addProperty(FdtProp n) {
		mProperties.put(n.name(), n.property());
	}

	public String getName() {
		if (mName.contains("@"))
			return mName.split("@")[0];
		return mName;
	}

	public boolean hasRegions() {
		return mProperties.containsKey("reg");
	}

	private int indexOf(byte[] arr, int val) {
		for (int i = 0; i < arr.length; i++)
			if (arr[i] == val)
				return i;
		return -1;
	}

	private void getRegionNames(ArrayList<DtbRegion> regs) {
		byte[] regNames = mProperties.get("reg-names");
		if (regNames == null)
			return;
		for (DtbRegion r : regs) {
			int pos = indexOf(regNames, 0);
			r.name = new String(Arrays.copyOfRange(regNames, 0, pos), StandardCharsets.UTF_8);
			regNames = Arrays.copyOfRange(regNames, pos+1, regNames.length);
		}
	}

	public List<DtbRegion> getRegions() {
		byte[] regs = mProperties.get("reg");
		if (regs == null)
			return null;
		ArrayList<DtbRegion> ret = new ArrayList<DtbRegion>();
		while (regs.length >= 8) {
			DtbRegion r = new DtbRegion();
			r.addr = new BigInteger(Arrays.copyOfRange(regs, 0, 4)).intValue() & 0xffffffffL;
			r.size = new BigInteger(Arrays.copyOfRange(regs, 4, 8)).intValue() & 0xffffffffL;
			regs = Arrays.copyOfRange(regs, 8, regs.length);
			ret.add(r);
		}
		getRegionNames(ret);
		return ret;
	}
}
