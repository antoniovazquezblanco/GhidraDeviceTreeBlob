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
package devicetreeblob;

import java.util.ArrayList;
import java.util.List;

import devicetreeblob.parser.DtbBlock;
import devicetreeblob.parser.DtbRegion;

public class BlockInfo {
	public Block block;
	public String name;
	public boolean isReadable;
	public boolean isWritable;
	public boolean isExecutable;
	public boolean isVolatile;
	public List<DtbBlock> blocks;
	public List<DtbRegion> regions;

	public BlockInfo() {
		blocks = new ArrayList<DtbBlock>();
		regions = new ArrayList<DtbRegion>();
	}
}
