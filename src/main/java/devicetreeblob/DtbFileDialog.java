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
