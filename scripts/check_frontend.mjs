// Global: reproducible browser-module syntax and import checks without npm dependencies.
// Local: SourceTextModule parses ECMAScript without Node's implicit TypeScript/file detection.
// Source: https://nodejs.org/api/vm.html#class-vmsourcetextmodule .
import { readdir, readFile } from "node:fs/promises"; // Read only the repository's shipped JavaScript modules.
import vm from "node:vm"; // Use the strict ECMAScript module parser rather than executing DOM code.

async function checkFrontend() {
  // Global: fail CI before a syntax error can strand the dashboard shell. Local: parse and link every static module.
  if (typeof vm.SourceTextModule !== "function") throw new Error("Run with: node --experimental-vm-modules scripts/check_frontend.mjs"); // Make the required runtime flag explicit.
  const directory = new URL("../src/security_monitoring_agent/static/", import.meta.url); // Resolve from this script, independent of the caller's cwd.
  const files = (await readdir(directory)).filter((name) => name.endsWith(".js")).sort(); // Check every current browser entry point and helper.
  if (!files.length) throw new Error("No frontend JavaScript modules were found"); // A missing asset directory must not pass silently.
  const modules = new Map(); // Reuse one module identity while resolving relative imports.
  let failures = 0; // Report every syntax error from this pass instead of stopping at the first file.
  for (const file of files) {
    // Global: strict browser syntax. Local: construct a module without evaluating any of its statements.
    const url = new URL(file, directory); // File URLs work consistently on Windows and Linux.
    try { modules.set(url.href, new vm.SourceTextModule(await readFile(url, "utf8"), { identifier: url.href })); console.log(`Parsed ${file}`); } // Preserve the filename in parser diagnostics.
    catch (error) { failures += 1; console.error(`${file}: ${error.message}`); } // Syntax failures produce a nonzero final result.
  }
  if (failures) throw new Error(`${failures} frontend module(s) failed strict syntax parsing`); // Do not link an incomplete graph.
  for (const module of modules.values()) {
    // Global: detect missing files and mismatched named exports. Local: linking does not access document, fetch, or other browser globals.
    if (module.status !== "unlinked") continue; // Dependencies already linked through another entry point need no repeated work.
    await module.link((specifier, parent) => {
      // Global: assets remain local. Local: resolve only explicit relative imports shipped alongside the dashboard.
      if (!specifier.startsWith("./") && !specifier.startsWith("../")) throw new Error(`Unsupported frontend import ${specifier} in ${parent.identifier}`); // No hidden npm or network dependency.
      const dependency = modules.get(new URL(specifier, parent.identifier).href); // Match the browser's URL-relative module resolution.
      if (!dependency) throw new Error(`Missing frontend import ${specifier} in ${parent.identifier}`); // Prevent a broken import from reaching the browser.
      return dependency; // SourceTextModule checks the imported export names during linking.
    });
  }
  console.log(`Frontend check passed: ${files.length} ECMAScript modules parsed and linked.`); // Report exactly the coverage this check establishes.
}

try { await checkFrontend(); } // One explicit orchestration entry point is usable locally and in CI.
catch (error) { console.error(error.message); process.exitCode = 1; } // Signal failure without dropping buffered diagnostics.
