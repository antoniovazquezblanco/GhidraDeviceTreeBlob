package devicetreeblob;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import devicetreeblob.Dtb.FdtBeginNode;
import devicetreeblob.Dtb.FdtBlock;
import devicetreeblob.Dtb.FdtNode;
import devicetreeblob.Dtb.FdtProp;

public class DtbParser {

	ArrayList<Block> mBlocks;

	public DtbParser(File file) throws IOException, ParseException {
		mBlocks = new ArrayList<Block>();
		parseBlocks(Dtb.fromFile(file.getAbsolutePath()));
	}

	private void parseBlocks(Dtb dtb) throws ParseException {
		FdtBlock fdtBlock = dtb.structureBlock();
		ArrayList<Block> stack = new ArrayList<Block>();
		for (FdtNode node : fdtBlock.nodes()) {
			switch (node.type()) {
			case BEGIN_NODE:
				Block b = new Block((FdtBeginNode) node.body());
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

	class Block {
		private String mName;
		Map<String, byte[]> mProperties;

		public Block(FdtBeginNode node) {
			mName = node.name();
			mProperties = new HashMap<>();
		}

		public void addProperty(FdtProp n) {
			mProperties.put(n.name(), n.property());
		}

		public String name() {
			if (mName.contains("@"))
				return mName.split("@")[0];
			return mName;
		}

		public boolean hasRegs() {
			return mProperties.containsKey("reg");
		}

		private int indexOf(byte[] arr, int val) {
			for (int i = 0; i < arr.length; i++)
				if (arr[i] == val)
					return i;
			return -1;
		}

		private void getRegNames(ArrayList<Reg> regs) {
			byte[] regNames = mProperties.get("reg-names");
			if (regNames == null)
				return;
			for (Reg r : regs) {
				int pos = indexOf(regNames, 0);
				r.name = new String(Arrays.copyOfRange(regNames, 0, pos), StandardCharsets.UTF_8);
				regNames = Arrays.copyOfRange(regNames, pos+1, regNames.length);
			}
		}

		public List<Reg> getRegs() {
			byte[] regs = mProperties.get("reg");
			if (regs == null)
				return null;
			ArrayList<Reg> ret = new ArrayList<Reg>();
			while (regs.length >= 8) {
				Reg r = new Reg();
				r.addr = new BigInteger(Arrays.copyOfRange(regs, 0, 4)).intValue() & 0xffffffffL;
				r.size = new BigInteger(Arrays.copyOfRange(regs, 4, 8)).intValue() & 0xffffffffL;
				regs = Arrays.copyOfRange(regs, 8, regs.length);
				ret.add(r);
			}
			getRegNames(ret);
			return ret;
		}

		class Reg {
			String name;
			Long addr;
			Long size;
		}
	}
}
