import * as t from "@babel/types";

/** Only definite synchronous exits; unsupported control flow stays unknown. */
export const symbolicDefiniteExit = (
  node: t.Node | null | undefined,
  depth = 0,
): boolean => {
  if (!node || depth >= 128) return false;
  if (t.isReturnStatement(node) || t.isThrowStatement(node)) return true;
  if (t.isBlockStatement(node))
    return node.body.some((child) => symbolicDefiniteExit(child, depth + 1));
  return (
    t.isIfStatement(node) &&
    symbolicDefiniteExit(node.consequent, depth + 1) &&
    symbolicDefiniteExit(node.alternate, depth + 1)
  );
};
