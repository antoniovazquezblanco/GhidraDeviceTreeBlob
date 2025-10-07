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

import javax.swing.SwingConstants;

import devicetreeblob.parser.DtbParser;
import docking.action.builder.ActionBuilder;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskBuilder;
import ghidra.util.task.TaskLauncher;

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

		tool.setStatusInfo("Loading DTB.");

		File file = DtbFileDialog.getDtbFileFromDialog(pac.getComponentProvider().getComponent());
		if (file == null) {
			tool.setStatusInfo("DTB loading was cancelled.");
			return;
		}

		DtbParser parser;
		try {
			parser = new DtbParser(file);
		} catch (IOException | ParseException e) {
			Msg.showError(getClass(), null, "Load PDB", "Unable to load PDB file while analysis is running.", e);
			return;
		}
		DtbMemoryMapLoadTask loadTask = new DtbMemoryMapLoadTask(program, parser);
		TaskBuilder.withTask(loadTask).setStatusTextAlignment(SwingConstants.LEADING).setLaunchDelay(0);
		new TaskLauncher(loadTask);

		tool.setStatusInfo("DTB loader finished.");
	}
}
