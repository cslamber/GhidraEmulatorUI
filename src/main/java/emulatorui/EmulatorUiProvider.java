package emulatorui;

import java.awt.BorderLayout;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import javax.swing.DefaultCellEditor;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.event.TableModelEvent;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.table.GTable;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.DummyCancellableTaskMonitor;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import resources.Icons;

class EmulatorUiProvider extends ComponentProviderAdapter {

	private JTabbedPane panel;
	private JTextArea textArea;
	private JTextArea hookarea;
	
	private RegisterTableModel regtablemodel;
	private GTable regtable;
	private LocalsTableModel localtablemodel;
	private GTable localtable;
	private MemoryChangesTableModel changetablemodel;
	private GTable changetable;
	private BreakPointTableModel bptablemodel;
	private GTable bptable;
	
	private HookManager hookmgr;
	
	private EmulatorHelper emu = null;
	private ProgramPlugin master;

	public EmulatorUiProvider(ProgramPlugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		master = plugin;
		buildPanel();
		createActions();
	}
	
	/* Start an emulator run task in another, cancellable thread */
	private void runEmu() {
		Task task = new Task("Running Emulator") {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				while (true) {
					boolean success = emu.run(monitor);
					if (success) {
						textArea.append("Successfully ran\n");
						if (!hookmgr.runHookIfPresent()) {
							bptablemodel.hit(emu.getExecutionAddress());
							break;
						}
					} else {
						textArea.append("Failed to run\n");
						break;
					}
				}
				updateSub();
			}
		};
		TaskLauncher.launch(task);
	}
	
	private void stepEmu() {
		Task task = new Task("Stepping Emulator") {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				while (true) {
					boolean success = hookmgr.runHookIfPresent();
					if (!success) success = emu.step(monitor);
					if (success) {
						textArea.append("Successfully stepped\n");
						if (!hookmgr.runHookIfPresent()) {
							bptablemodel.hit(emu.getExecutionAddress());
							break;
						}
					} else {
						textArea.append("Failed to step\n");
						break;
					}
				}
				updateSub();
			}
		};
		TaskLauncher.launch(task);
	}
	
	/* Update the AbstractTableModels that use information from the emulator */
	private void updateSub() {
		regtablemodel.fireTableDataChanged();
		localtablemodel.recompute();
		changetablemodel.recompute();
	}
	
	public boolean hasEmulator() {
		return emu != null;
	}
	
	/* Reset stackpointer to a sane default (half the max address minus 7fff) */
	private void resetStackPointer() {
		Register sp = emu.getStackPointerRegister();
		BigInteger top = emu.getLanguage().getDefaultSpace().getMaxAddress().getOffsetAsBigInteger();
		BigInteger spl = top.shiftRight(1).subtract(new BigInteger("7fff", 16));
		emu.writeRegister(sp, spl);
	}
	
	/* Completely reset (or start up) the plugin */
	public void fullReset(Program p) {
		/* Register table initialization */
		regtablemodel = new RegisterTableModel(emu);
		regtable.setModel(regtablemodel);
		/* Register dropdown */
		JComboBox<String> regcb = new JComboBox<String>();
		regcb.setEditable(true);
		for (Register reg : emu.getLanguage().getRegisters()) {
			regcb.addItem(reg.getName());
		}
		regtable.getColumnModel().getColumn(0).setCellEditor(new DefaultCellEditor(regcb));
		
		/* Type dropdown */
		JComboBox<String> typecb = new JComboBox<String>();
		typecb.addItem("Integer");
		typecb.addItem("String");
		regtable.getColumnModel().getColumn(2).setCellEditor(new DefaultCellEditor(typecb));
		
		/* Locals table initialization */
		localtablemodel = new LocalsTableModel(emu);
		localtable.setModel(localtablemodel);
		localtablemodel.recompute();
		/* Types dropdown */
		localtable.getColumnModel().getColumn(3).setCellEditor(new DefaultCellEditor(typecb));
				
		/* Reset breakpointtable */
		bptablemodel = new BreakPointTableModel(emu);
		bptable.setModel(bptablemodel);
	}
	
	/* Handle a reset of the emulator plugin (either from button or initialization */
	public void reset(Program p, boolean complete) {
		/* If we didn't have an emulator, we need to initialize everything
		 * with a fullReset()
		 */
		if (emu != null) {
			emu.dispose();
			hookmgr.dispose();
		} else complete = true;
		
		emu = new EmulatorHelper(p);
		emu.enableMemoryWriteTracking(true);
		
		if (complete) fullReset(p);

		hookmgr = new HookManager(emu, hookarea.getText());
		
		changetablemodel = new MemoryChangesTableModel(emu);
		changetable.setModel(changetablemodel);
		
		regtablemodel.changeEmu(emu);
		bptablemodel.changeEmu(emu);

		resetStackPointer();
	}

	// Customize GUI
	private void buildPanel() {
		panel = new JTabbedPane();
		textArea = new JTextArea(5, 25);
		textArea.setEditable(false);
		panel.addTab("Dev Log", new JScrollPane(textArea));
		
		regtable = new GTable();
		panel.addTab("Register Table", new JScrollPane(regtable));
		
		localtable = new GTable();
		panel.addTab("Locals Table", new JScrollPane(localtable));
		
		changetable = new GTable();
		panel.addTab("Memory Changes Table", new JScrollPane(changetable));
		
		bptable = new GTable();
		panel.addTab("Breakpoint Table", new JScrollPane(bptable));
		
		hookarea = new JTextArea(5, 25);
		hookarea.setEditable(true);
		panel.addTab("Hook Script", new JScrollPane(hookarea));
		
		setVisible(true);
	}

	// TODO: Customize actions
	private void createActions() {
		DockingAction action = new DockingAction("Reset Emulator", getName()) {
			public void actionPerformed(ActionContext context) {
				//Msg.showInfo(getClass(), panel, "Custom Action", "Hello!");
				reset(master.getCurrentProgram(), false);
				textArea.append("Created emulator instance " + emu.getProgram().getName() + "\n");
			}
		};
		action.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		addLocalAction(action);
		
		action = new DockingAction("Goto", getName()) {
			public void actionPerformed(ActionContext context) {
				BigInteger to = master.getProgramLocation().getAddress().getOffsetAsBigInteger();
				emu.writeRegister(emu.getPCRegister(), to);
				regtablemodel.fireTableDataChanged();
				localtablemodel.recompute();
}
		};
		action.setToolBarData(new ToolBarData(Icons.ARROW_UP_LEFT_ICON, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		addLocalAction(action);
		
		action = new DockingAction("Step", getName()) {
			public void actionPerformed(ActionContext context) {
				stepEmu();
			}
		};
		action.setToolBarData(new ToolBarData(Icons.RIGHT_ALTERNATE_ICON, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		addLocalAction(action);
		action = new DockingAction("Run until breakpoint", getName()) {
			public void actionPerformed(ActionContext context) {
				runEmu();
			}
		};
		action.setToolBarData(new ToolBarData(Icons.RIGHT_ICON, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		addLocalAction(action);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}
