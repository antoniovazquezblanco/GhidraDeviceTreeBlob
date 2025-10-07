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

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class DtbDataTypeLoadTask extends Task {
	private Program mProgram;
	private Address mDtbAddress;
	private int mDtbLength;

	public DtbDataTypeLoadTask(Program program, Address dtbAddress, int dtbLength) {
		super("Load DTB Data Types", true, false, true, true);
		mProgram = program;
		mDtbAddress = dtbAddress;
		mDtbLength = dtbLength;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		// Create a label for the DTB structure
		monitor.setMessage("Creating DTB label...");
		SymbolTable symbolTable = mProgram.getSymbolTable();
		int transactionId = mProgram.startTransaction("DTB label creation");
		boolean ok = false;
		try {
			symbolTable.createLabel(mDtbAddress, "DTB", SourceType.ANALYSIS);
			ok = true;
		} catch (InvalidInputException e) {
			Msg.error(getClass(), "Could not create DTB label", e);
		}
		mProgram.endTransaction(transactionId, ok);

		// Create data types in the listing view...
		monitor.setMessage("Creating DTB data type...");

		// Create a structure data type for the DTB
		StructureDataType dtbStruct = new StructureDataType("dtb_t", mDtbLength);

		// Apply the data type to the DTB location in the program
		transactionId = mProgram.startTransaction("DTB data type assignment");
		ok = false;
		try {
			// Clear existing data and create new data type, allowing conflicts to be overwritten
			DataUtilities.createData(mProgram, mDtbAddress, dtbStruct, mDtbLength, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
			ok = true;
		} catch (Exception e) {
			Msg.error(getClass(), "Could not assign DTB data type", e);
		}
		mProgram.endTransaction(transactionId, ok);
	}
}