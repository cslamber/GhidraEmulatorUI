package emulatorui;

import java.util.ArrayList;
import java.util.HashMap;

import javax.swing.table.AbstractTableModel;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;

public class BreakPointTableModel extends AbstractTableModel {
	private EmulatorHelper emu;
	private ArrayList<Address> rows = new ArrayList<Address>();
	private HashMap<Address, Integer> hit = new HashMap<Address, Integer>();
	private String[] columnNames = new String[] {
			"Location", "Times Hit"
	};
	
	public BreakPointTableModel(EmulatorHelper emu) {
		this.emu = emu;
	}
	
	public void changeEmu(EmulatorHelper emu) {
		this.emu = emu;
		for (Address a : rows) {
			emu.setBreakpoint(a);
			hit.put(a, 0);
		}
		this.fireTableDataChanged();
	}
	
	// Columns we care about
	// 1 - Register
	// 2 - Raw value
	// 3 - Type
	// 4 - Interpreted value
	
	@Override
	public String getColumnName(int col) {
		return columnNames[col];
	}
	
	public int getRowCount() {
		return rows.size() + 1;
	}
	
	public int getColumnCount() {
		return 2;
	}
	
	public boolean isCellEditable(int row, int col) {
		return col == 0 || (row < rows.size() && col == 1);
	}
	
	public void hit(Address a) {
		if (hit.containsKey(a)) hit.put(a, hit.get(a)+1);
		this.fireTableDataChanged();
	}
	
	public void setValueAt(Object value, int row, int col) {
		if (col == 0) {
			String val = ((String)value).strip();
			if (val.isBlank()) {
				emu.clearBreakpoint(rows.get(row));
				rows.remove(row);
				return;
			}
			Address[] a = emu.getProgram().parseAddress(val);
			if (a.length == 0) return;
			if (row == rows.size()) {
				rows.add(a[0]);
				if (!hit.containsKey(a[0])) hit.put(a[0], 0);
			} else {
				emu.clearBreakpoint(rows.get(row));
				rows.set(row, a[0]);
				hit.put(a[0], 0);
			}
			emu.setBreakpoint(a[0]);
		} else if (col == 1) {
			String val = ((String)value).strip();
			Integer times = Integer.valueOf(val);
			if (times != null) {
				hit.put(rows.get(row), times);
			}
		}
		this.fireTableDataChanged();
	}
	
	public Object getValueAt(int row, int col) {
		if (row == rows.size()) {
			return "";
		} else if (col == 0) {
			return rows.get(row).toString();
		} else if (col == 1) {
			return hit.get(rows.get(row));
		}
		return "";
	}
}
