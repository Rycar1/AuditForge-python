package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"os"
	"regexp"
	"strings"
)

var identifier = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)
var packageDeclaration = regexp.MustCompile(`(?m)^\s*package\s+[A-Za-z_][A-Za-z0-9_]*`)

type collector struct {
	fset       *token.FileSet
	facts      map[string][]map[string]any
	lineOffset int
}

func newCollector(fset *token.FileSet, lineOffset int) *collector {
	return &collector{fset: fset, facts: map[string][]map[string]any{
		"classes": {}, "functions": {}, "calls": {}, "assignments": {}, "returns": {}, "controls": {},
	}, lineOffset: lineOffset}
}

func (c *collector) adjustedLine(line int) int {
	line -= c.lineOffset
	if line < 1 {
		return 1
	}
	return line
}
func (c *collector) line(node ast.Node) int { return c.adjustedLine(c.fset.Position(node.Pos()).Line) }
func (c *collector) endLine(node ast.Node) int {
	return c.adjustedLine(c.fset.Position(node.End()).Line)
}
func (c *collector) key(prefix string, node ast.Node) string {
	return fmt.Sprintf("%s:%d:%d", prefix, node.Pos(), node.End())
}
func text(fset *token.FileSet, node any) string {
	if node == nil {
		return ""
	}
	var output bytes.Buffer
	if err := format.Node(&output, fset, node); err != nil {
		return ""
	}
	value := output.String()
	if len(value) > 1600 {
		return value[:1600]
	}
	return value
}
func names(value string) []string {
	ignored := map[string]bool{"true": true, "false": true, "nil": true, "return": true, "func": true, "package": true}
	seen := map[string]bool{}
	result := []string{}
	for _, item := range identifier.FindAllString(value, -1) {
		if !ignored[item] && !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}
func (c *collector) add(bucket string, value map[string]any) {
	c.facts[bucket] = append(c.facts[bucket], value)
}

func receiverName(decl *ast.FuncDecl, fset *token.FileSet) string {
	if decl.Recv == nil || len(decl.Recv.List) == 0 {
		return ""
	}
	value := text(fset, decl.Recv.List[0].Type)
	return strings.Trim(value, "*() ")
}
func parameters(fields *ast.FieldList) []string {
	if fields == nil {
		return []string{}
	}
	result := []string{}
	for _, field := range fields.List {
		for _, name := range field.Names {
			if name.Name != "_" {
				result = append(result, name.Name)
			}
		}
	}
	return result
}

func (c *collector) collectFunction(decl *ast.FuncDecl) {
	key := c.key("function", decl)
	receiver := receiverName(decl, c.fset)
	qualified := decl.Name.Name
	if receiver != "" {
		qualified = receiver + "." + qualified
	}
	c.add("functions", map[string]any{
		"key": key, "name": decl.Name.Name, "qualifiedName": qualified, "line": c.line(decl), "endLine": c.endLine(decl),
		"params": parameters(decl.Type.Params), "classKey": nil, "parentKey": nil,
	})
	if decl.Body != nil {
		c.collectNode(decl.Body, key)
	}
}

func (c *collector) collectNode(root ast.Node, scope string) {
	ast.Inspect(root, func(node ast.Node) bool {
		if node == nil {
			return true
		}
		switch value := node.(type) {
		case *ast.AssignStmt:
			for index, target := range value.Lhs {
				right := ast.Expr(nil)
				if len(value.Rhs) == 1 {
					right = value.Rhs[0]
				} else if index < len(value.Rhs) {
					right = value.Rhs[index]
				}
				if right != nil {
					expression := text(c.fset, right)
					c.add("assignments", map[string]any{"target": text(c.fset, target), "sources": names(expression), "expression": expression, "line": c.line(value), "scopeKey": scope})
				}
			}
		case *ast.DeclStmt:
			if declaration, ok := value.Decl.(*ast.GenDecl); ok {
				for _, spec := range declaration.Specs {
					if variable, ok := spec.(*ast.ValueSpec); ok {
						for index, name := range variable.Names {
							if index < len(variable.Values) {
								expression := text(c.fset, variable.Values[index])
								c.add("assignments", map[string]any{"target": name.Name, "sources": names(expression), "expression": expression, "line": c.line(variable), "scopeKey": scope})
							}
						}
					}
				}
			}
		case *ast.ReturnStmt:
			for _, expressionNode := range value.Results {
				expression := text(c.fset, expressionNode)
				c.add("returns", map[string]any{"expression": expression, "sources": names(expression), "line": c.line(value), "scopeKey": scope})
			}
		case *ast.CallExpr:
			arguments := []string{}
			argumentSources := [][]string{}
			for _, argument := range value.Args {
				expression := text(c.fset, argument)
				arguments = append(arguments, expression)
				argumentSources = append(argumentSources, names(expression))
			}
			c.add("calls", map[string]any{"callee": text(c.fset, value.Fun), "expression": text(c.fset, value), "line": c.line(value), "scopeKey": scope, "argumentTexts": arguments, "argumentSources": argumentSources})
		case *ast.IfStmt:
			c.control("if", value.Cond, value, scope)
		case *ast.ForStmt:
			c.control("for", value.Cond, value, scope)
		case *ast.RangeStmt:
			c.control("for", value.X, value, scope)
		case *ast.SwitchStmt:
			c.control("switch", value.Tag, value, scope)
		case *ast.TypeSwitchStmt:
			c.control("switch", value.Assign, value, scope)
		}
		return true
	})
}
func (c *collector) control(kind string, condition ast.Node, anchor ast.Node, scope string) {
	if condition == nil {
		return
	}
	expression := text(c.fset, condition)
	c.add("controls", map[string]any{"kind": kind, "condition": expression, "variables": names(expression), "line": c.line(anchor), "scopeKey": scope})
}

func main() {
	source, err := io.ReadAll(os.Stdin)
	if err != nil {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "bridge_error", "reason": err.Error()})
		return
	}
	lineOffset := 0
	if !packageDeclaration.Match(source) {
		source = append([]byte("package auditforge\n"), source...)
		lineOffset = 1
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "AuditForgeInput.go", source, parser.SkipObjectResolution)
	if err != nil {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "parse_error", "reason": err.Error()})
		return
	}
	collector := newCollector(fset, lineOffset)
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok {
			collector.collectFunction(function)
		}
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "ok", "facts": collector.facts})
}
