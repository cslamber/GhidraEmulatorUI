package emulatorui;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import javax.swing.table.AbstractTableModel;

import org.python.bouncycastle.util.encoders.Hex;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;

public class LocalsTableModel extends AbstractTableModel {
	private EmulatorHelper emu;
	private ArrayList<String> rows = new ArrayList<String>();
	private HashMap<String, byte[]> vals = new HashMap<String, byte[]>();
	private HashMap<String, VariableStorage> storage = new HashMap<String, VariableStorage>();
	private String[] columnNames = new String[] {
			"Name", "Storage", "Raw Value", "Type", "Interpreted"
	};
	private ArrayList<String> types = new ArrayList<String>();
	
	public LocalsTableModel(EmulatorHelper emu) {
		this.emu = emu;
	}
	
	/* Retrieve the bytes given a VariableStorage.  I will need to expand
	 * on this as I go deeper into Ghidra's addressing system/being able to
	 * handle more complex tasks, but for right now register, memory, and the
	 * stack will handle 99.9% of all locals
	 */
	public byte[] retrieveVarStorage(VariableStorage s) {
		if (s.isRegisterStorage()) {
			return emu.readRegister(s.getRegister()).toByteArray();
		} else if (s.isMemoryStorage()) {
			return emu.readMemory(s.getMinAddress(), s.size());
		} else if (s.isStackStorage()) {
			try {
				return emu.readStackValue(s.getStackOffset(), s.size(), false).toByteArray();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return null;
			}
		} else {
			// TODO
		}
		return null;
	}
	
	/* Just as above, write some value to a VariableStorage */
	public void writeVarStorage(VariableStorage s, BigInteger val) {
		if (s.isRegisterStorage()) {
			emu.writeRegister(s.getRegister(), val);
		} else if (s.isMemoryStorage()) {
			emu.writeMemory(s.getMinAddress(), val.toByteArray());
		} else if (s.isStackStorage()) {
			try {
				emu.writeStackValue(s.getStackOffset(), s.size(), val);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} else {
			// TODO
		}
	}
	
	/* Recompute all locals */
	public void recompute() {
		rows.clear();
		vals.clear();
		storage.clear();
		Address addr = emu.getExecutionAddress();
		Function currentlyIn = emu.getProgram().getFunctionManager().getFunctionContaining(addr);
		if (currentlyIn == null) return;
		Variable[] vars = currentlyIn.getAllVariables();
		for (Variable v : vars) {
			rows.add(v.getName());
			storage.put(v.getName(), v.getVariableStorage());
			vals.put(v.getName(), retrieveVarStorage(v.getVariableStorage()));
			types.add("Integer");
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
		return 5;
	}
	
	public boolean isCellEditable(int row, int col) {
		return col == 2 || col == 3;
	}
	
	public void setValueAt(Object value, int row, int col) {
		if (col == 2) {
			BigInteger v;
			try {
				v = new BigInteger((String)value, 16);
			} catch (Exception e) {
				return;
			}
			writeVarStorage(storage.get(rows.get(row)), v);
		} else if (col == 3) {
			types.set(row, (String)value);
		}
		this.recompute();
	}
	
	public Object getValueAt(int row, int col) {
		String local = rows.get(row);
		switch (col) {
		case 0: return local; 
		case 1: return storage.get(local).toString();
		case 2:
			byte[] stored = vals.get(local);
			if (stored != null) return new String(Hex.encode(stored));
			return "";
		case 3: return types.get(row);
		case 4: return "";
		}
		return "";
	}
}
