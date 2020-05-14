package emulatorui;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;

import org.python.core.PyInteger;
import org.python.core.PyLong;
import org.python.core.PyObject;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.python.GhidraPythonInterpreter;
import ghidra.util.Msg;

public class HookManager {
	private EmulatorHelper emu;
	private GhidraPythonInterpreter interp = GhidraPythonInterpreter.get();
	private HashMap<String, PyObject> hookfns = new HashMap<String, PyObject>();
	private HashMap<Address, String> fnlocs = new HashMap<Address, String>();
	private HashMap<String, Function> fns = new HashMap<String, Function>();
	
	/* A liasion to allow for the hook script to add hooks (specifically
	 * adding members/breakpoints to the hashmaps defined above
	 */
	private class HookLiasion extends PyObject {
		@Override
		public PyObject __call__(PyObject name, PyObject obj) {
			hookfns.put(name.asString(), obj);
			return null;
		}
	}
	
	/* A liasion to provide the mem psuedo-array to the hook script */
	private class MemoryArrayLiasion extends PyObject {
		@Override
		public PyObject __getitem__(PyObject key) {
			long ind = key.asLong();
			Address readaddr = emu.getProgram().getAddressFactory().getDefaultAddressSpace().getAddress(ind);
			byte val = emu.readMemoryByte(readaddr);
			return new PyInteger(val & 0xff);
		}
		
		@Override
		public void __setitem__(PyObject key, PyObject val) {
			long ind = key.asLong();
			long byt = val.asLong();
			Address writeaddr = emu.getProgram().getAddressFactory().getDefaultAddressSpace().getAddress(ind);
			emu.writeMemoryValue(writeaddr, 1, byt);
		}
	}
	
	/* A liasion to provide the reg psuedo-dictionary to the hook script */
	private class RegisterDictLiasion extends PyObject {
		@Override
		public PyObject __getitem__(PyObject key) {
			Register r = emu.getLanguage().getRegister(key.asString());
			BigInteger val = emu.readRegister(r);
			return new PyLong(val);
		}
		
		@Override
		public void __setitem__(PyObject key, PyObject pyval) {
			BigInteger val;
			if (pyval instanceof PyLong) {
				val = ((PyLong)pyval).getValue();
			} else {
				val = BigInteger.valueOf(pyval.asLong());
			}
			Register r = emu.getLanguage().getRegister(key.asString());
			emu.writeRegister(r, val);
		}
	}
		
	/* Allow the hook liasion to be used as a decorator */
	private final String prelude =
			"def Hook(name):\n"
			+ "\tdef inner(fn):\n"
			+ "\t\t__hookliasion(name, fn)\n"
			+ "\treturn inner\n"
			+ "\n"
			+ "\n";
	
	public HookManager(EmulatorHelper emu, String script) {
		this.emu = emu;
		interp.set("__hookliasion", new HookLiasion());
		interp.set("emu", emu);
		interp.set("mem", new MemoryArrayLiasion());
		interp.set("reg", new RegisterDictLiasion());
		interp.exec(prelude);
		interp.exec(script);
		
		for (String name : hookfns.keySet()) {
			/* Stardard naive symbol grabbing.  Since they probably want to hook external functions,
			 * prefer external symbols above others
			 */
			Symbol externalSymbol = emu.getProgram().getSymbolTable().getExternalSymbol(name);
			if (externalSymbol == null) externalSymbol = emu.getProgram().getSymbolTable().getSymbols(name).next();
			if (externalSymbol == null || externalSymbol.getSymbolType() != SymbolType.FUNCTION) {
				Msg.showError(getClass(), null, "Hook function not installed", "Failed to find external function " + name + " in program");
				continue;
			}
			Function f = (Function) externalSymbol.getObject();
			fns.put(name, f);
			Address[] thunkAddrs = f.getFunctionThunkAddresses();
			if (thunkAddrs != null && thunkAddrs.length >= 1) {
				fnlocs.put(thunkAddrs[0], name);
				emu.setBreakpoint(thunkAddrs[0]);
			} else {
				Address a = f.getEntryPoint();
				fnlocs.put(a, name);
				emu.setBreakpoint(a);
			}
		}
	}
	
	/* Get the parameters to a function from the current emulator state immediately after a call */
	public Object[] extractArgs(Function f) {
		Parameter[] params = f.getParameters();
		ArrayList<Object> ret = new ArrayList<Object>();
		for (Parameter p : params) {
			BigInteger val;
			if (p.isRegisterVariable()) {
				val = emu.readRegister(p.getRegister());
			} else if (p.isStackVariable()) {
				try {
					val = emu.readStackValue(p.getStackOffset(), p.getDataType().getLength(), false);
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
					return new Object[] { };
				}
			} else {
				return new Object[] { };
			}
//			if (p.getDataType() instanceof Pointer) {
//				ret.add(f.getProgram().parseAddress(val.toString(16))); // TODO - use API better
//			} else {
			ret.add(val.longValue());
//			}
		}
		return ret.toArray();
	}
	
	/* Whenever we break, we want to check if we breaked because of a hook or not and run it if so,
	 * this function runs an applicable hook, and returns if it did or not  */
	public boolean runHookIfPresent() {
		Address cur = emu.getExecutionAddress();
		String name = fnlocs.get(cur);
		if (name == null) return false;
		PyObject hookfn = hookfns.get(name);
		Object[] args = extractArgs(fns.get(name));
		try {
			hookfn._jcall(args);
			Register spr = emu.getStackPointerRegister();
			int offset = fns.get(name).getStackPurgeSize();
			BigInteger aftersp = emu.readRegister(spr).add(BigInteger.valueOf(offset));
			emu.writeRegister(spr, aftersp);
		} catch (Exception e) {
			ghidra.util.Msg.showError(getClass(), null, "Python hook function " + name + " failed", e.toString());
		}
		return true;
	}
	
	public void dispose() {
		interp.cleanup();
	}
}
