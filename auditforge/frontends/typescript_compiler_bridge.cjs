"use strict";

// AuditForge optional TypeScript Compiler API bridge.
//
// The process receives one JSON document on stdin and emits one JSON document
// on stdout. It parses source text only: no tsconfig, project plugin, transformer,
// or target-project module is loaded. The only required module is `typescript`.

const fs = require("fs");
const path = require("path");

const MAX_TEXT = 1600;
const MAX_EVENTS = 30000;

function emit(value) {
  process.stdout.write(JSON.stringify(value));
}

function fail(status, reason) {
  emit({ status, reason: String(reason || status).slice(0, 1200) });
  process.exit(0);
}

function readInput() {
  const raw = fs.readFileSync(0, "utf8");
  const input = JSON.parse(raw);
  if (!input || typeof input !== "object" || typeof input.source !== "string") {
    throw new Error("bridge input must contain source text");
  }
  return input;
}

function resolveTypeScript(input) {
  const explicit = typeof input.typescriptPath === "string" ? input.typescriptPath.trim() : "";
  if (explicit) {
    const candidate = path.resolve(explicit);
    const stat = fs.existsSync(candidate) ? fs.statSync(candidate) : null;
    if (!stat) throw new Error("configured TypeScript path does not exist");
    if (stat.isDirectory()) {
      const packageEntry = require.resolve("typescript", { paths: [candidate] });
      return packageEntry;
    }
    return candidate;
  }
  const searchPaths = Array.isArray(input.searchPaths)
    ? input.searchPaths.filter((item) => typeof item === "string" && item.length > 0)
    : [];
  return require.resolve("typescript", { paths: searchPaths });
}

let input;
let ts;
let modulePath;
try {
  input = readInput();
  modulePath = resolveTypeScript(input);
  ts = require(modulePath);
} catch (error) {
  const message = error && error.message ? error.message : String(error);
  if (/typescript|cannot find module|does not exist/i.test(message)) {
    fail("typescript_not_found", message);
  }
  fail("bridge_error", message);
}

if (!ts || typeof ts.createSourceFile !== "function" || !ts.ScriptKind) {
  fail(
    "compiler_api_unavailable",
    "Resolved TypeScript package does not expose the stable Compiler API; install a TypeScript 5.x release."
  );
}

const fileName = typeof input.fileName === "string" ? input.fileName : "input.ts";
const extension = path.extname(fileName).toLowerCase();
const scriptKind = extension === ".tsx"
  ? ts.ScriptKind.TSX
  : extension === ".jsx"
    ? ts.ScriptKind.JSX
    : extension === ".js" || extension === ".mjs" || extension === ".cjs"
      ? ts.ScriptKind.JS
      : ts.ScriptKind.TS;
const sourceFile = ts.createSourceFile(fileName, input.source, ts.ScriptTarget.Latest, true, scriptKind);
const parseDiagnostics = Array.isArray(sourceFile.parseDiagnostics) ? sourceFile.parseDiagnostics : [];
if (parseDiagnostics.length) {
  const messages = parseDiagnostics.slice(0, 5).map((item) => {
    const message = ts.flattenDiagnosticMessageText(item.messageText, " ");
    const position = typeof item.start === "number" ? sourceFile.getLineAndCharacterOfPosition(item.start) : null;
    return position ? `${position.line + 1}:${position.character + 1} ${message}` : message;
  });
  fail("parse_error", messages.join("; "));
}

const facts = {
  classes: [],
  functions: [],
  calls: [],
  assignments: [],
  returns: [],
  controls: [],
  accesses: [],
  decorators: [],
};
let eventCount = 0;

function push(bucket, value) {
  if (eventCount >= MAX_EVENTS) throw new Error(`compiler event limit exceeded (${MAX_EVENTS})`);
  facts[bucket].push(value);
  eventCount += 1;
}

function lineOf(node) {
  return sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile, false)).line + 1;
}

function endLineOf(node) {
  return sourceFile.getLineAndCharacterOfPosition(Math.max(node.getStart(sourceFile, false), node.end - 1)).line + 1;
}

function textOf(node) {
  if (!node) return "";
  return node.getText(sourceFile).slice(0, MAX_TEXT);
}

function keyOf(prefix, node) {
  return `${prefix}:${node.pos}:${node.end}`;
}

function bindingNames(node, output = []) {
  if (!node) return output;
  if (ts.isIdentifier(node)) {
    output.push(node.text);
  } else if (ts.isObjectBindingPattern(node) || ts.isArrayBindingPattern(node)) {
    for (const element of node.elements) {
      if (ts.isBindingElement(element)) bindingNames(element.name, output);
    }
  } else if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
    const value = accessPath(node);
    if (value) output.push(value);
  }
  return [...new Set(output)];
}

function accessPath(node) {
  if (!node) return null;
  if (ts.isIdentifier(node)) return node.text;
  if (node.kind === ts.SyntaxKind.ThisKeyword) return "this";
  if (ts.isPropertyAccessExpression(node)) {
    const base = accessPath(node.expression);
    return base ? `${base}.${node.name.text}` : null;
  }
  if (ts.isElementAccessExpression(node)) {
    const base = accessPath(node.expression);
    if (!base || !node.argumentExpression) return null;
    if (ts.isStringLiteralLike(node.argumentExpression) || ts.isNumericLiteral(node.argumentExpression)) {
      return `${base}.${node.argumentExpression.text}`;
    }
    if (ts.isIdentifier(node.argumentExpression)) return `${base}.${node.argumentExpression.text}`;
  }
  return null;
}

function isPropertyNameIdentifier(node) {
  const parent = node.parent;
  return Boolean(
    parent &&
      ((ts.isPropertyAccessExpression(parent) && parent.name === node) ||
        (ts.isPropertyAssignment(parent) && parent.name === node) ||
        (ts.isMethodDeclaration(parent) && parent.name === node) ||
        (ts.isPropertyDeclaration(parent) && parent.name === node))
  );
}

function referenceNames(node) {
  const result = [];
  function add(value) {
    if (value && !result.includes(value)) result.push(value);
  }
  function visit(current) {
    if (ts.isPropertyAccessExpression(current) || ts.isElementAccessExpression(current)) {
      const value = accessPath(current);
      if (value) {
        add(value);
        return;
      }
    }
    if (ts.isIdentifier(current) && !isPropertyNameIdentifier(current)) add(current.text);
    ts.forEachChild(current, visit);
  }
  visit(node);
  return result;
}

function literalValue(node) {
  if (ts.isStringLiteralLike(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  return null;
}

function functionLike(node) {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isGetAccessorDeclaration(node) ||
    ts.isSetAccessorDeclaration(node)
  );
}

function functionName(node) {
  if (node.name && (ts.isIdentifier(node.name) || ts.isStringLiteralLike(node.name))) return node.name.text;
  const parent = node.parent;
  if (parent && ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) return parent.name.text;
  if (parent && ts.isPropertyAssignment(parent)) return textOf(parent.name);
  if (parent && ts.isCallExpression(parent)) return `callback@${lineOf(node)}`;
  return `anonymous@${lineOf(node)}`;
}

function closest(node, predicate) {
  let current = node.parent;
  while (current) {
    if (predicate(current)) return current;
    current = current.parent;
  }
  return null;
}

const classKeys = new Map();
const functionKeys = new Map();

function discover(node) {
  if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) {
    const name = node.name && ts.isIdentifier(node.name) ? node.name.text : `anonymous@${lineOf(node)}`;
    const key = keyOf("class", node);
    classKeys.set(node, key);
    push("classes", { key, name, line: lineOf(node), endLine: endLineOf(node), qualifiedName: name });
  }
  if (functionLike(node)) {
    const key = keyOf("function", node);
    functionKeys.set(node, key);
    const owner = closest(node, (candidate) => ts.isClassDeclaration(candidate) || ts.isClassExpression(candidate));
    const parentFunction = closest(node, functionLike);
    const name = functionName(node);
    const classKey = owner ? classKeys.get(owner) || keyOf("class", owner) : null;
    const ownerName = owner && owner.name && ts.isIdentifier(owner.name) ? owner.name.text : null;
    push("functions", {
      key,
      name,
      qualifiedName: ownerName ? `${ownerName}.${name}` : name,
      line: lineOf(node),
      endLine: endLineOf(node),
      params: node.parameters.flatMap((parameter) => bindingNames(parameter.name)),
      classKey,
      parentKey: parentFunction ? functionKeys.get(parentFunction) || keyOf("function", parentFunction) : null,
    });
  }
  ts.forEachChild(node, discover);
}
discover(sourceFile);

function scopeKey(node) {
  const owner = closest(node, functionLike);
  return owner ? functionKeys.get(owner) || keyOf("function", owner) : null;
}

function assignmentTargetsFor(node) {
  let current = node;
  while (current && current !== sourceFile) {
    const parent = current.parent;
    if (!parent) break;
    if (ts.isVariableDeclaration(parent) && parent.initializer && current.pos >= parent.initializer.pos) {
      return bindingNames(parent.name);
    }
    if (
      ts.isBinaryExpression(parent) &&
      parent.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      current.pos >= parent.right.pos
    ) {
      return bindingNames(parent.left);
    }
    if (ts.isStatement(parent)) break;
    current = parent;
  }
  return [];
}

function decoratorsOf(node) {
  if (typeof ts.canHaveDecorators === "function" && ts.canHaveDecorators(node)) {
    return ts.getDecorators(node) || [];
  }
  return node.decorators ? Array.from(node.decorators) : [];
}

function recordDecorators(node) {
  for (const decorator of decoratorsOf(node)) {
    const expression = decorator.expression;
    const call = ts.isCallExpression(expression) ? expression : null;
    const nameNode = call ? call.expression : expression;
    const name = accessPath(nameNode) || textOf(nameNode);
    const firstArgument = call && call.arguments.length ? call.arguments[0] : null;
    const classOwner = ts.isClassDeclaration(node) || ts.isClassExpression(node)
      ? node
      : closest(node, (candidate) => ts.isClassDeclaration(candidate) || ts.isClassExpression(candidate));
    push("decorators", {
      name,
      value: firstArgument ? literalValue(firstArgument) : null,
      line: lineOf(decorator),
      classKey: classOwner ? classKeys.get(classOwner) || keyOf("class", classOwner) : null,
      scopeKey: functionLike(node) ? functionKeys.get(node) : scopeKey(node),
      parameterNames: ts.isParameter(node) ? bindingNames(node.name) : [],
      expression: textOf(decorator),
    });
  }
}

function recordSyntax(node) {
  if (
    ts.isClassDeclaration(node) ||
    ts.isClassExpression(node) ||
    functionLike(node) ||
    ts.isParameter(node)
  ) {
    recordDecorators(node);
  }

  if (ts.isVariableDeclaration(node) && node.initializer && !functionLike(node.initializer)) {
    for (const target of bindingNames(node.name)) {
      push("assignments", {
        target,
        sources: referenceNames(node.initializer),
        expression: textOf(node.initializer),
        line: lineOf(node),
        scopeKey: scopeKey(node),
      });
    }
  } else if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
    for (const target of bindingNames(node.left)) {
      push("assignments", {
        target,
        sources: referenceNames(node.right),
        expression: textOf(node.right),
        line: lineOf(node),
        scopeKey: scopeKey(node),
      });
    }
  }

  if (ts.isReturnStatement(node) && node.expression) {
    push("returns", {
      expression: textOf(node.expression),
      sources: referenceNames(node.expression),
      line: lineOf(node),
      scopeKey: scopeKey(node),
    });
  }

  if (ts.isCallExpression(node)) {
    push("calls", {
      callee: accessPath(node.expression) || textOf(node.expression),
      expression: textOf(node),
      line: lineOf(node),
      scopeKey: scopeKey(node),
      argumentTexts: node.arguments.map(textOf),
      argumentSources: node.arguments.map(referenceNames),
      argumentLiterals: node.arguments.map(literalValue),
      argumentFunctionKeys: node.arguments.map((argument) => functionLike(argument) ? functionKeys.get(argument) || null : null),
    });
  }

  let controlKind = null;
  let condition = null;
  if (ts.isIfStatement(node)) {
    controlKind = node.parent && ts.isIfStatement(node.parent) && node.parent.elseStatement === node ? "elif" : "if";
    condition = node.expression;
  } else if (ts.isForStatement(node) || ts.isForInStatement(node) || ts.isForOfStatement(node)) {
    controlKind = "for";
    condition = node.condition || node.expression || node.initializer;
  } else if (ts.isWhileStatement(node) || ts.isDoStatement(node)) {
    controlKind = "while";
    condition = node.expression;
  } else if (ts.isSwitchStatement(node)) {
    controlKind = "switch";
    condition = node.expression;
  } else if (ts.isCaseClause(node)) {
    controlKind = "case";
    condition = node.expression;
  } else if (ts.isCatchClause(node)) {
    controlKind = "catch";
    condition = node.variableDeclaration || node;
  }
  if (controlKind && condition) {
    push("controls", {
      kind: controlKind,
      condition: textOf(condition),
      variables: referenceNames(condition),
      line: lineOf(node),
      scopeKey: scopeKey(node),
    });
  }

  if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
    const parent = node.parent;
    const nestedBase = parent &&
      ((ts.isPropertyAccessExpression(parent) || ts.isElementAccessExpression(parent)) && parent.expression === node);
    if (!nestedBase) {
      const value = accessPath(node);
      if (value) {
        push("accesses", {
          path: value,
          expression: textOf(node),
          line: lineOf(node),
          scopeKey: scopeKey(node),
          targetVariables: assignmentTargetsFor(node),
        });
      }
    }
  }

  ts.forEachChild(node, recordSyntax);
}

try {
  recordSyntax(sourceFile);
  emit({
    status: "ok",
    compiler: { version: String(ts.version || "unknown"), modulePath },
    facts,
  });
} catch (error) {
  fail("bridge_error", error && error.message ? error.message : String(error));
}
