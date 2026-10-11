/** Run source-owned producer controls and the public CLI/MCP verification lane. */
export function verifyGhidraPrototypeDiagnostics(options: {
  readonly installation: { readonly analyzeHeadlessPath: string };
  readonly entrypoint?: string;
}): Promise<unknown>;
