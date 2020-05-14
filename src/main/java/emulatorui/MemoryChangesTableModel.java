package emulatorui;

import java.util.ArrayList;
import javax.swing.table.AbstractTableModel;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

public class MemoryChangesTableModel extends AbstractTableModel {
	private EmulatorHelper emu;
	private ArrayList<AddressRange> rows = new ArrayList<AddressRange>();
	private String[] columnNames = new String[] {
			"Range", "Commit"
	};
	
	public MemoryChangesTableModel(EmulatorHelper emu) {
		this.emu = emu;
	}
	
	private void writeMemoryRange(AddressRange mask) {
		byte[] mem = emu.readMemory(mask.getMinAddress(), (int) mask.getLength());
		int transactionID = emu.getProgram().startTransaction("Move emulator memory to listing.");
		try {
			Memory parent = emu.getProgram().getMemory();
			parent.setBytes(mask.getMinAddress(), mem);
			emu.getProgram().endTransaction(transactionID, true);
		} catch (MemoryAccessException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			emu.getProgram().endTransaction(transactionID, false);
		}
	}
		
	public void recompute() {
		rows.clear();
		AddressSetView allchanges = emu.getTrackedMemoryWriteSet();
		for (AddressRange range : allchanges.intersect(emu.getProgram().getMemory())) {
			rows.add(range);
		}
		this.fireTableDataChanged();
	}
	
	@Override
	public String getColumnName(int col) {
		return columnNames[col];
	}
	
	public int getRowCount() {
		return rows.size();
	}
	
	public int getColumnCount() {
		return 2;
	}
	
	public boolean isCellEditable(int row, int col) {
		return col == 1;
	}
	
	public void setValueAt(Object value, int row, int col) {
		if (col == 1) {
			if ("COMMIT".equals(value)) {
				writeMemoryRange(rows.get(row));
			}
		}
	}
	
	public Object getValueAt(int row, int col) {
		if (col == 0) {
			AddressRange range = rows.get(row);
			return range.getMinAddress().toString() + "---" + range.getMaxAddress().toString();
		} else if (col == 1) {
			return "Enter 'COMMIT' into this box to move memory changes to listing'";
		}
		return "";
	}
}
