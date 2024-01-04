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

import javax.swing.JComponent;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.framework.preferences.Preferences;
import ghidra.util.filechooser.ExtensionFileFilter;

public class DtbFileDialog {
	private static final String LAST_DTBFILE_PREFERENCE_KEY = "Dtb.LastFile";

	public static File getDtbFileFromDialog(JComponent parent) {
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
