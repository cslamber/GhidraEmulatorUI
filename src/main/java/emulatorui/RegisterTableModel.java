package emulatorui;

import java.math.BigInteger;
import java.util.ArrayList;
import javax.swing.table.AbstractTableModel;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;

public class RegisterTableModel extends AbstractTableModel {
	private EmulatorHelper emu;
	private ArrayList<String> rows = new ArrayList<String>();
	private String[] columnNames = new String[] {
			"Register", "Raw Value", "Type", "Interpreted"
	};
	private ArrayList<String> types = new ArrayList<String>();
	
	public RegisterTableModel(EmulatorHelper emu) {
		this.emu = emu;
	}
	
	public void changeEmu(EmulatorHelper emu) {
		this.emu = emu;
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
		return 4;
	}
	
	public boolean isCellEditable(int row, int col) {
		return col == 0 || ((col == 1 || col == 2) && row < rows.size());
	}
	
	public void setValueAt(Object value, int row, int col) {
		if (col == 0) {
			String reg = ((String)value).strip();
			if (reg.isBlank()) return;
			if (row == rows.size()) {
				rows.add(reg);
				types.add("Integer");
			} else {
				rows.set(row, reg);
			}
		} else if (col == 1) {
			String val = ((String)value).strip();
			Register r = emu.getLanguage().getRegister(rows.get(row));
			if (r != null) {
				BigInteger v;
				try {
					v = new BigInteger(val, 16);
				} catch (Exception e) {
					return;
				}
				emu.writeRegister(r, v);
			}
		} else if (col == 2) {
			String val = ((String)value).strip();
			types.set(row, val);
		}
		this.fireTableDataChanged();
	}
	
	public Object getValueAt(int row, int col) {
		if (row == rows.size()) {
			return "";
		} else if (col == 0) {
			return rows.get(row);
		} else if (col == 1) {
			Register r = emu.getLanguage().getRegister(rows.get(row));
			if (r == null) return "INVALID";
			return emu.readRegister(r).toString(16);
		} else if (col == 2) {
			return types.get(row);
		} else if (col == 3) {
			String typ = types.get(row);
			Register r = emu.getLanguage().getRegister(rows.get(row));
			if (r == null) return "INVALID";
			BigInteger val = emu.readRegister(r);
			if (typ.equals("Integer")) {
				return val.toString(16);
			} else if (typ.equals("String")) {
				Address base = emu.getProgram().getAddressFactory().getDefaultAddressSpace().getAddress(val.longValue());
				String ret = "";
				for (int i = 0; i < 1000; i++) {
					byte c = emu.readMemoryByte(base.add(i));
					if (c == 0) break;
					ret = ret.concat(Character.toString((char) (c & 0xFF)));
				}
				return ret;
			}
		}
		return "";
	}
}
