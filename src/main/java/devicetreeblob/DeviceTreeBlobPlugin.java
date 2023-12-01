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

import java.io.File;
import java.io.IOException;
import java.text.ParseException;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.JComponent;

import devicetreeblob.DtbParser.Block;
import devicetreeblob.DtbParser.Block.Reg;
import docking.action.builder.ActionBuilder;
import docking.tool.ToolConstants;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.Msg;
import ghidra.util.filechooser.ExtensionFileFilter;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Import External Device Tree Blob Files",
	description = "This plugin manages the import of DTB files to add memory map information to a program."
)
//@formatter:on
public class DeviceTreeBlobPlugin extends ProgramPlugin {
	public static final String NAME = "Device Tree Blob";
	private static final String LAST_DTBFILE_PREFERENCE_KEY = "Dtb.LastFile";

	public DeviceTreeBlobPlugin(PluginTool tool) {
		super(tool);
		createActions();
	}

	private void createActions() {
		new ActionBuilder("Load DTB File", this.getName()).withContext(ProgramActionContext.class)
				.validContextWhen(pac -> pac.getProgram() != null).menuPath(ToolConstants.MENU_FILE, "Load DTB File...")
				.menuGroup("Import PDB", "5").onAction(pac -> loadDtb(pac)).buildAndInstall(tool);
	}

	private void loadDtb(ProgramActionContext pac) {
		Program program = pac.getProgram();
		AutoAnalysisManager currentAutoAnalysisManager = AutoAnalysisManager.getAnalysisManager(program);
		if (currentAutoAnalysisManager.isAnalyzing()) {
			Msg.showWarn(getClass(), null, "Load PDB", "Unable to load PDB file while analysis is running.");
			return;
		}

		File file = getDtbFileFromDialog(pac.getComponentProvider().getComponent());
		if (file == null)
			return;

		Msg.info(getClass(), "Loading " + file.getPath());
		DtbParser dtb;
		try {
			dtb = new DtbParser(file);
		} catch (IOException | ParseException e) {
			Msg.error(getClass(), "Could not parse DTB file!", e);
			return;
		}

		Msg.info(getClass(), "Filtering unwanted DTB blocks...");
		List<Block> memBlocks = dtb.mBlocks.stream().filter(x -> (!x.name().equalsIgnoreCase("cpu") && x.hasRegs()))
				.collect(Collectors.toList());

		Msg.info(getClass(), "Creating regions in memory...");
		Memory memory = program.getMemory();
		AddressSpace addrSpace = program.getAddressFactory().getDefaultAddressSpace();
		for (Block block : memBlocks)
			for (Reg region : block.getRegs()) {
				String reg_name = block.name() + ((region.name != null) ? ("_" + region.name) : "");
				Address addr = addrSpace.getAddress(region.addr);

				int transactionId = program.startTransaction("Device Tree Blob memory block creation");
				boolean ok = createMemoryRegion(memory, reg_name, addr, region.size);
				program.endTransaction(transactionId, ok);
			}
	}

	private boolean createMemoryRegion(Memory memory, String name, Address addr, Long size) {
		try {
			MemoryBlock memBlock = memory.createUninitializedBlock(name, addr, size, false);
			boolean isRam = name.equals("memory");
			memBlock.setRead(true);
			memBlock.setWrite(true);
			memBlock.setExecute(isRam);
			memBlock.setVolatile(!isRam);
			memBlock.setComment("Generated by Device Tree Blob");
			return true;
		} catch (MemoryConflictException e) {
			Msg.error(getClass(),
					"Could not create a region for " + name + "@" + String.format("0x%08x", addr.getOffset()) + "+"
							+ String.format("0x%08x", size) + ". It conflicts with an existing region!",
					e);
		} catch (LockException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalArgumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (AddressOverflowException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}

	private File getDtbFileFromDialog(JComponent parent) {
		GhidraFileChooser chooser = new GhidraFileChooser(parent);
		chooser.addFileFilter(ExtensionFileFilter.forExtensions("Device Tree Blobs", "dtb"));
		chooser.setMultiSelectionEnabled(false);
		chooser.setApproveButtonText("Choose");
		chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		chooser.setTitle("Select DTB");

		String lastFile = Preferences.getProperty(LAST_DTBFILE_PREFERENCE_KEY);
		if (lastFile != null) {
			chooser.setSelectedFile(new File(lastFile));
		}

		File file = chooser.getSelectedFile();
		chooser.dispose();

		if (file == null || !file.isFile())
			return null;

		Preferences.setProperty(LAST_DTBFILE_PREFERENCE_KEY, file.getPath());
		return file;
	}

}