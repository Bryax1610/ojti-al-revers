import ghidra.app.script.GhidraScript;

/** Disable the named auto-analyzers before default auto-analysis. */
public final class ReaGhidraAnalysisOptions extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 1 || arguments[0].isBlank()) {
            throw new IllegalArgumentException(
                "ReaGhidraAnalysisOptions requires one comma-separated analyzer-name argument");
        }
        for (String name : arguments[0].split(",")) {
            monitor.checkCancelled();
            setAnalysisOption(currentProgram, name.trim(), "false");
        }
    }
}
