/** Emitted NodeNext suffixes and the TypeScript source counterparts they name. */
const EMITTED_SUFFIXES: ReadonlyArray<
  readonly [suffix: string, sourceSuffixes: readonly string[]]
> = [
  [".js", [".ts", ".tsx", ".d.ts"]],
  [".mjs", [".mts", ".d.mts"]],
  [".cjs", [".cts", ".d.cts"]],
  [".jsx", [".tsx", ".d.ts"]],
];

/**
 * TypeScript source commonly names the extension emitted for NodeNext, so a
 * missing emitted name resolves to its present source counterpart. Candidates
 * are returned only for TypeScript-family callers and explicit filenames;
 * directory and index resolution never substitutes a counterpart, and any
 * present runtime file wins because callers try it first.
 */
export const typescriptEmittedSourceCandidates = (
  sourcePath: string,
  candidate: string,
): readonly string[] => {
  if (!/\.(?:ts|tsx|mts|cts)$/u.test(sourcePath)) return [];
  const emitted = EMITTED_SUFFIXES.find(([suffix]) =>
    candidate.endsWith(suffix),
  );
  if (emitted === undefined) return [];
  // Strip the matched suffix by length. posix.extname would miss dotfile
  // names such as ".js", whose whole basename is the emitted suffix itself.
  const stem = candidate.slice(0, candidate.length - emitted[0].length);
  return emitted[1].map((suffix) => `${stem}${suffix}`);
};
