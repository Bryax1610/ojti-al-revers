import * as t from "@babel/types";

import {
  semanticMemberWriteTargets,
  semanticStaticPropertyKey,
  unwrapJavaScriptExpression,
} from "./javascriptAstValues.js";
import { collectParsedJavaScriptLexicalStateSteps } from "./javascriptSemanticAnalysis.js";
import {
  resolveSemanticBindingState,
  type JavaScriptSemanticAnalysisState,
} from "./javascriptSemanticState.js";
import { traverseJavaScriptAstSteps } from "./javascriptSemanticTraversal.js";
import type { ParsedJavaScriptSource } from "./javascriptSourceParser.js";

/** exact table slots; a dynamic spread also makes all later indexes unknown. */
export type JavaScriptViteDependencyTable = readonly (string | undefined)[];

/** resolve emitted Vite helpers by lexical identity without executing them. */
export function* classifyParsedJavaScriptViteDependencyTablesSteps(
  file: ParsedJavaScriptSource,
): Generator<void, ReadonlyMap<number, JavaScriptViteDependencyTable | null>> {
  const candidates = new Map<t.VariableDeclarator, t.ArrayExpression>();
  yield* traverseJavaScriptAstSteps(file.program, {
    enter: (node) => {
      if (!t.isVariableDeclarator(node)) return;
      const table = viteDependencyTable(node);
      if (table !== undefined) candidates.set(node, table);
    },
  });
  const calls = new Map<number, JavaScriptViteDependencyTable | null>();
  if (candidates.size === 0) return calls;
  const state = yield* collectParsedJavaScriptLexicalStateSteps(file);
  const tables = viteBindingTables(candidates, state);
  yield* traverseJavaScriptAstSteps(file.program, {
    enter: (node) => invalidateViteCacheWrite(node, tables, state),
  });
  yield* traverseJavaScriptAstSteps(file.program, {
    enter: (node) => {
      if (
        (!t.isCallExpression(node) && !t.isOptionalCallExpression(node)) ||
        !t.isIdentifier(node.callee, { name: "__vite__mapDeps" })
      )
        return;
      const binding = resolveSemanticBindingState(
        state,
        node.callee,
        node.callee.name,
      );
      if (binding !== undefined && tables.has(binding.bindingId))
        calls.set(node.start ?? -1, tables.get(binding.bindingId) ?? null);
    },
  });
  return calls;
}

const viteBindingTables = (
  candidates: ReadonlyMap<t.VariableDeclarator, t.ArrayExpression>,
  state: JavaScriptSemanticAnalysisState,
): Map<string, JavaScriptViteDependencyTable | null> => {
  const tables = new Map<string, JavaScriptViteDependencyTable | null>();
  for (const [declaration, table] of candidates) {
    if (!t.isIdentifier(declaration.id)) continue;
    const binding = resolveSemanticBindingState(
      state,
      declaration.id,
      declaration.id.name,
    );
    if (binding === undefined) continue;
    const [initializer] = binding.initializers;
    const unchanged =
      initializer !== undefined &&
      initializer.node === declaration.init &&
      initializer.projection.length === 0 &&
      binding.initializers.length === 1 &&
      !binding.definitions.some(({ kind }) => kind === "assignment") &&
      !state.conditionalInitializers.has(initializer.node);
    tables.set(binding.bindingId, unchanged ? exactTableSlots(table) : null);
  }
  return tables;
};

const exactTableSlots = (
  table: t.ArrayExpression,
): JavaScriptViteDependencyTable => {
  const spread = table.elements.findIndex((element) =>
    t.isSpreadElement(element),
  );
  const entries = spread < 0 ? table.elements : table.elements.slice(0, spread);
  return entries.map((element) =>
    t.isStringLiteral(element) ? element.value : undefined,
  );
};

const viteDependencyTable = (
  declaration: t.VariableDeclarator,
): t.ArrayExpression | undefined => {
  const helper = declaration.init;
  if (
    !t.isIdentifier(declaration.id, { name: "__vite__mapDeps" }) ||
    !t.isArrowFunctionExpression(helper) ||
    helper.async ||
    helper.params.length !== 3
  )
    return undefined;
  const [indexes, map, dependencies] = helper.params;
  if (
    !t.isIdentifier(indexes) ||
    !t.isAssignmentPattern(map) ||
    !t.isIdentifier(map.left) ||
    !t.isIdentifier(map.right, { name: declaration.id.name }) ||
    !t.isAssignmentPattern(dependencies) ||
    !t.isIdentifier(dependencies.left)
  )
    return undefined;
  const parameterNames = new Set([
    indexes.name,
    map.left.name,
    dependencies.left.name,
  ]);
  if (parameterNames.size !== 3 || parameterNames.has(declaration.id.name))
    return undefined;
  const cache = dependencies.right;
  if (
    !t.isLogicalExpression(cache, { operator: "||" }) ||
    !isNamedMember(cache.left, map.left.name, "f") ||
    !t.isAssignmentExpression(cache.right, { operator: "=" }) ||
    !isNamedMember(cache.right.left, map.left.name, "f") ||
    !t.isArrayExpression(cache.right.right) ||
    !mapsDependencyIndexes(helper.body, indexes.name, dependencies.left.name)
  )
    return undefined;
  return cache.right.right;
};

const isNamedMember = (
  node: t.Node,
  object: string,
  property: string,
): boolean =>
  t.isMemberExpression(node) &&
  t.isIdentifier(node.object, { name: object }) &&
  semanticStaticPropertyKey(node.property, node.computed) === property;

const mapsDependencyIndexes = (
  body: t.Node,
  indexes: string,
  dependencies: string,
): boolean => {
  if (
    !t.isCallExpression(body) ||
    !isNamedMember(body.callee, indexes, "map") ||
    body.arguments.length !== 1
  )
    return false;
  const callback = body.arguments[0];
  if (
    !t.isArrowFunctionExpression(callback) ||
    callback.async ||
    callback.params.length !== 1 ||
    !t.isIdentifier(callback.params[0]) ||
    callback.params[0].name === dependencies
  )
    return false;
  return (
    t.isMemberExpression(callback.body) &&
    callback.body.computed &&
    t.isIdentifier(callback.body.object, { name: dependencies }) &&
    t.isIdentifier(callback.body.property, { name: callback.params[0].name })
  );
};

const invalidateViteCacheWrite = (
  node: t.Node,
  tables: Map<string, JavaScriptViteDependencyTable | null>,
  state: JavaScriptSemanticAnalysisState,
): void => {
  const target = t.isAssignmentExpression(node)
    ? node.left
    : t.isUpdateExpression(node)
      ? node.argument
      : t.isUnaryExpression(node, { operator: "delete" })
        ? node.argument
        : t.isForOfStatement(node) || t.isForInStatement(node)
          ? node.left
          : undefined;
  if (target === undefined) return;
  for (const member of semanticMemberWriteTargets(target)) {
    let root: t.Node = member;
    let property: string | null = null;
    while (t.isMemberExpression(root) || t.isOptionalMemberExpression(root)) {
      property = semanticStaticPropertyKey(root.property, root.computed);
      root = unwrapJavaScriptExpression(root.object).node;
    }
    if (property !== null && property !== "f") continue;
    if (!t.isIdentifier(root)) continue;
    const binding = resolveSemanticBindingState(state, root, root.name);
    if (binding !== undefined && tables.has(binding.bindingId))
      tables.set(binding.bindingId, null);
  }
};
