# Ghidra Device Tree Blob

[![Build](https://github.com/antoniovazquezblanco/GhidraDeviceTreeBlob/actions/workflows/main.yml/badge.svg)](https://github.com/antoniovazquezblanco/GhidraDeviceTreeBlob/actions/workflows/main.yml)

Import Device Tree Information onto your Ghidra memory map. This is usefull when reversing firmware from propietary devices that do not publish SVD files.

If you have SVD files for your device, I recommend you try  [GhidraSVD](https://github.com/antoniovazquezblanco/GhidraSVD).


## Installing

This extension is available for installation via the [Ghidra Extension Manager](https://github.com/antoniovazquezblanco/GhidraExtensionManager).

You may also install this extension by going to the [releases page](https://github.com/antoniovazquezblanco/GhidraDeviceTreeBlob/releases) and downloading the latest version for your Ghidra distribution. In order to install from the release, in Ghidra main window go to `File` > `Install extensions...`. In the new window press the `+` icon to import the downloaded zip.


## Usage

In a CodeBrowser window press `File` > `Import DTB...`.

A file dialog will allow you to select your device tree file and import it. Memory map will automatically be updated.


## Development

### Development environment

1. First, install [Eclipse for Java Developers](https://www.eclipse.org/downloads/packages/).
2. Once installed, open Eclipse and click on `Help` > `Install New Software...`. A window will pop up.
3. Click on `Add...` > `Archive...`. It will open a file selection dialog. In this dialog, please select `GhidraDev.zip` file from `<Your Ghidra install dir>/Extensions/Eclipse/GhidraDev/`.
4. Check Ghidra category (or GhidraDev entry).
5. Repeatedly click `Next`.
6. Accept the terms of the license agreement.
7. Check the `Unsigned` table entry and click `Trust Selected`.
8. Restart Eclipse...

### Importing the project

After all of that, if you still want to develop and/or contribute to the project, first clone this repository:
```bash
git clone git@github.com:antoniovazquezblanco/GhidraDeviceTreeBlob.git
```

In Eclipse:
1. Click on `File` > `Import...`.
2. In the dialog click on `Ghidra` > `Ghidra Module Source`.
3. Select the `GhidraDeviceTreeBlob` folder you have just cloned.
4. Select a valid Ghidra installation to develop against.
5. Click on `Finish`.

You are now ready to develop!
