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

import java.text.ParseException;

import javax.swing.SwingConstants;

import devicetreeblob.parser.Dtb;
import devicetreeblob.parser.DtbParser;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskBuilder;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import io.kaitai.struct.ByteBufferKaitaiStream;
import io.kaitai.struct.KaitaiStream.ValidationGreaterThanError;

public class DeviceTreeBlobAnalyzer extends AbstractAnalyzer {
	private static byte[] DTB_SIGNATURE = new byte[] { -48, 13, -2, -19 };

	public DeviceTreeBlobAnalyzer() {
		super("Device Tree Blob Analyzer", "Find Device Tree signatures and import memory map information from them.",
				AnalyzerType.BYTE_ANALYZER);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return true;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		monitor.setMessage("Looking for DTB signatures...");
		Address search_from = set.getMinAddress();
		while (search_from != null) {
			monitor.checkCancelled();
			Address found_addr = program.getMemory().findBytes(search_from, DTB_SIGNATURE, null, true, monitor);
			if (found_addr != null) {
				monitor.setMessage(String.format("Checking DTB signatures in %s...", found_addr.toString()));
				try {
					parseDtb(program, found_addr);
				} catch (MemoryAccessException | ParseException e) {
					Msg.error(getClass(), "Could not parse DTB file!", e);
				}
				search_from = found_addr.next();
			} else {
				search_from = null;
			}
		}
		return true;
	}

	private void parseDtb(Program program, Address addr) throws MemoryAccessException, ParseException {
		int len = parseDtbLength(program, addr);

		byte[] bytes = new byte[len];
		int read = program.getMemory().getBytes(addr, bytes);
		if (read < len)
			throw new ParseException("Not enough bytes to parse DTB.", read);

		DtbParser parser = new DtbParser(bytes);

		DtbMemoryMapLoadTask loadTask = new DtbMemoryMapLoadTask(program, parser);
		TaskBuilder.withTask(loadTask).setStatusTextAlignment(SwingConstants.LEADING).setLaunchDelay(0);

		new TaskLauncher(loadTask);

		// TODO Create a DTB byte array in memory
	}

	private int parseDtbLength(Program program, Address addr) throws MemoryAccessException, ParseException {
		byte[] header = new byte[40];
		int read = program.getMemory().getBytes(addr, header);
		if (read < 40)
			throw new ParseException("Not enough bytes to parse DTB header.", read);
		Dtb dtb = null;
		try {
			dtb = new Dtb(new ByteBufferKaitaiStream(header));
		} catch (ValidationGreaterThanError e) {
			throw new ParseException("Wrong DTB format.", 0);
		}
		long len = dtb.totalSize();
		if (len < 40)
			// Full DTB cannot be shorter than its header...
			throw new ParseException("Wrong DTB length signature.", 0);
		if (dtb.ofsStructureBlock() < 40)
			throw new ParseException("Offset of structure block cannot be lower than header size.", 0);
		if ((dtb.ofsStructureBlock() & 0x3) != 0)
			throw new ParseException("Offset of structure must be aligned to a 4 byte boundary.", 0);
		if (dtb.lenStructureBlock() <= 0)
			throw new ParseException("Len of structure block cannot be zero or negative.", 0);
		if (dtb.ofsStringsBlock() < 40)
			throw new ParseException("Offset of strings block cannot be lower than header size.", 0);
		if (dtb.lenStringsBlock() <= 0)
			throw new ParseException("Len of strings block cannot be zero or negative.", 0);
		if (dtb.version() > 30)
			throw new ParseException("Invalid FDT version.", 0);
		return (int) len;
	}
}
