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

import java.io.File;
import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import devicetreeblob.parser.Dtb.FdtBeginNode;
import devicetreeblob.parser.Dtb.FdtBlock;
import devicetreeblob.parser.Dtb.FdtNode;
import devicetreeblob.parser.Dtb.FdtProp;

public class DtbParser {

	private ArrayList<DtbBlock> mBlocks;

	public DtbParser(File file) throws IOException, ParseException {
		mBlocks = new ArrayList<DtbBlock>();
		parseBlocks(Dtb.fromFile(file.getAbsolutePath()));
	}

	private void parseBlocks(Dtb dtb) throws ParseException {
		FdtBlock fdtBlock = dtb.structureBlock();
		ArrayList<DtbBlock> stack = new ArrayList<DtbBlock>();
		for (FdtNode node : fdtBlock.nodes()) {
			switch (node.type()) {
			case BEGIN_NODE:
				DtbBlock b = new DtbBlock((FdtBeginNode) node.body());
				mBlocks.add(b);
				stack.add(b);
				break;
			case END_NODE:
				stack.remove(stack.size() - 1);
				break;
			case PROP:
				stack.get(stack.size() - 1).addProperty((FdtProp) node.body());
				break;
			case NOP:
			case END:
				break;
			}
		}
		if (stack.size() != 0)
			throw new ParseException("Wrong number of END_NODE nodes in DTB file!", 0);
	}
	
	public List<DtbBlock> getBlocks() {
		return mBlocks;
	}
}
