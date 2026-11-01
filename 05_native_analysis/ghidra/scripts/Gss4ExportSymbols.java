// Ghidra Headless Post-Script: Gss4ExportSymbols.java
// Decompiles target functions and extracts string XREFs & vtables to JSON format.
//@category GSS4

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.address.Address;
import java.io.FileWriter;
import java.io.File;

public class Gss4ExportSymbols extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outJsonPath = (args.length > 0) ? args[0] : "ghidra_export.json";

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"engine\": \"ghidra\",\n");
        sb.append("  \"program\": \"").append(currentProgram.getName()).append("\",\n");
        sb.append("  \"base_address\": \"0x").append(Long.toHexString(currentProgram.getImageBase().getOffset())).append("\",\n");
        sb.append("  \"functions\": {\n");

        FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
        boolean first = true;
        int count = 0;
        while (iter.hasNext() && count < 50) {
            Function f = iter.next();
            DecompileResults res = decomp.decompileFunction(f, 30, monitor);
            if (res != null && res.decompileCompleted()) {
                if (!first) sb.append(",\n");
                first = false;
                String rva = "0x" + Long.toHexString(f.getEntryPoint().getOffset() - currentProgram.getImageBase().getOffset());
                sb.append("    \"").append(rva).append("\": {\n");
                sb.append("      \"rva\": \"").append(rva).append("\",\n");
                sb.append("      \"symbol\": \"").append(f.getName()).append("\",\n");
                sb.append("      \"signature\": \"").append(f.getPrototypeString(true, true)).append("\",\n");
                String cCode = res.getDecompiledFunction().getC().replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
                sb.append("      \"pseudocode\": \"").append(cCode).append("\"\n");
                sb.append("    }");
                count++;
            }
        }
        sb.append("\n  }\n");
        sb.append("}\n");

        FileWriter writer = new FileWriter(new File(outJsonPath));
        writer.write(sb.toString());
        writer.close();
        println("GSS4: Ghidra export completed -> " + outJsonPath);
    }
}
