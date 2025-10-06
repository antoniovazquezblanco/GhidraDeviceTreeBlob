# Ghidra Device Tree Blob

[![Build](https://github.com/antoniovazquezblanco/GhidraDeviceTreeBlob/actions/workflows/main.yml/badge.svg)](https://github.com/antoniovazquezblanco/GhidraDeviceTreeBlob/actions/workflows/main.yml)
[![CodeQL](https://github.com/antoniovazquezblanco/GhidraDeviceTreeBlob/actions/workflows/codeql.yml/badge.svg)](https://github.com/antoniovazquezblanco/GhidraDeviceTreeBlob/actions/workflows/codeql.yml)

<p align="center">
  <img width="400" src="doc/logo.png" alt="A fierce dragon looking with intent at a Linux penguin holding a binary tree.">
</p>

Import Device Tree Information onto your Ghidra memory map. This is usefull when reversing firmware from propietary devices that do not publish SVD files.

If you have SVD files for your device, I recommend you try [GhidraSVD](https://github.com/antoniovazquezblanco/GhidraSVD).

## Installing

This extension is available for installation via the [Ghidra Extension Manager](https://github.com/antoniovazquezblanco/GhidraExtensionManager).

You may also install this extension by going to the [releases page](https://github.com/antoniovazquezblanco/GhidraDeviceTreeBlob/releases) and downloading the latest version for your Ghidra distribution. In order to install from the release, in Ghidra main window go to `File` > `Install extensions...`. In the new window press the `+` icon to import the downloaded zip.

## Usage

In a CodeBrowser window press `File` > `Import DTB...`.

A file dialog will allow you to select your device tree file and import it. Memory map will automatically be updated.

## Development

For development instructions checkout [doc/Develop.md](doc/Develop.md).
