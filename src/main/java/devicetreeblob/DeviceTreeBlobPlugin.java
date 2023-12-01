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

import javax.swing.JComponent;

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
import ghidra.program.model.listing.Program;
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
		Dtb dtb;
		try {
			dtb = Dtb.fromFile(file.getAbsolutePath());
		} catch (IOException e) {
			Msg.error(getClass(), "Could not parse DTB file!", e);
			return;
		}
		
		


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
