import com.sun.source.tree.AnnotationTree;
import com.sun.source.tree.ArrayTypeTree;
import com.sun.source.tree.AssignmentTree;
import com.sun.source.tree.BinaryTree;
import com.sun.source.tree.BreakTree;
import com.sun.source.tree.CaseTree;
import com.sun.source.tree.CatchTree;
import com.sun.source.tree.ClassTree;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.CompoundAssignmentTree;
import com.sun.source.tree.DoWhileLoopTree;
import com.sun.source.tree.EnhancedForLoopTree;
import com.sun.source.tree.ExpressionTree;
import com.sun.source.tree.ForLoopTree;
import com.sun.source.tree.IdentifierTree;
import com.sun.source.tree.IfTree;
import com.sun.source.tree.ImportTree;
import com.sun.source.tree.InstanceOfTree;
import com.sun.source.tree.LiteralTree;
import com.sun.source.tree.MemberSelectTree;
import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.tree.NewArrayTree;
import com.sun.source.tree.NewClassTree;
import com.sun.source.tree.PackageTree;
import com.sun.source.tree.ReturnTree;
import com.sun.source.tree.StatementTree;
import com.sun.source.tree.SwitchTree;
import com.sun.source.tree.ThrowTree;
import com.sun.source.tree.Tree;
import com.sun.source.tree.TypeCastTree;
import com.sun.source.tree.VariableTree;
import com.sun.source.tree.WhileLoopTree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.SourcePositions;
import com.sun.source.util.TreePathScanner;
import com.sun.source.util.TreeScanner;
import com.sun.source.util.Trees;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.ToolProvider;

/** Emits a bounded JSON syntax-event stream using the JDK compiler tree API. */
class AuditForgeJavaAstBridge {
    private static final Pattern IDENTIFIER = Pattern.compile("[A-Za-z_$][A-Za-z0-9_$]*");

    private static final class MemorySource extends SimpleJavaFileObject {
        private final String id;
        private final String content;

        MemorySource(String id, String content) {
            super(URI.create("string:///AuditForgeInput_" + id + ".java"), JavaFileObject.Kind.SOURCE);
            this.id = id;
            this.content = content;
        }

        String id() { return id; }

        @Override
        public CharSequence getCharContent(boolean ignoreEncodingErrors) {
            return content;
        }
    }

    private static final class Collector extends TreePathScanner<Void, Void> {
        private final CompilationUnitTree unit;
        private final SourcePositions positions;
        private String packageName = "";
        private final List<String> imports = new ArrayList<>();
        private final List<String> classes = new ArrayList<>();
        private final List<String> functions = new ArrayList<>();
        private final List<String> variables = new ArrayList<>();
        private final List<String> calls = new ArrayList<>();
        private final List<String> newClasses = new ArrayList<>();
        private final List<String> assignments = new ArrayList<>();
        private final List<String> returns = new ArrayList<>();
        private final List<String> controls = new ArrayList<>();
        private final Deque<String> classKeys = new ArrayDeque<>();
        private final Deque<String> classNames = new ArrayDeque<>();
        private final Deque<String> functionKeys = new ArrayDeque<>();

        Collector(CompilationUnitTree unit, Trees trees) {
            this.unit = unit;
            this.positions = trees.getSourcePositions();
        }

        private long start(Tree tree) {
            long value = positions.getStartPosition(unit, tree);
            return value < 0 ? 0 : value;
        }

        private long end(Tree tree) {
            long value = positions.getEndPosition(unit, tree);
            return value < 0 ? start(tree) : value;
        }

        private int line(Tree tree) {
            return (int) unit.getLineMap().getLineNumber(start(tree));
        }

        private int endLine(Tree tree) {
            return (int) unit.getLineMap().getLineNumber(Math.max(start(tree), end(tree) - 1));
        }

        private int col(Tree tree) {
            return Math.max(0, (int) unit.getLineMap().getColumnNumber(start(tree)) - 1);
        }

        private List<String> annotationTexts(List<? extends AnnotationTree> annotations) {
            List<String> values = new ArrayList<>();
            for (AnnotationTree ann : annotations) {
                values.add(text(ann));
            }
            return values;
        }

        @Override
        public Void visitPackage(PackageTree node, Void unused) {
            if (node.getPackageName() != null) {
                packageName = node.getPackageName().toString();
            }
            return super.visitPackage(node, unused);
        }

        @Override
        public Void visitImport(ImportTree node, Void unused) {
            if (node.getQualifiedIdentifier() != null) {
                imports.add("{\"module\":" + quote(node.getQualifiedIdentifier().toString())
                        + ",\"isStatic\":" + (node.isStatic() ? "true" : "false")
                        + ",\"line\":" + line(node) + "}");
            }
            return super.visitImport(node, unused);
        }

        private String key(String prefix, Tree tree) {
            return prefix + ":" + start(tree) + ":" + end(tree);
        }

        private String scope() {
            return functionKeys.isEmpty() ? "null" : quote(functionKeys.peek());
        }

        private List<String> names(Tree tree) {
            LinkedHashSet<String> values = new LinkedHashSet<>();
            if (tree == null) {
                return new ArrayList<>(values);
            }
            new TreeScanner<Void, Boolean>() {
                @Override
                public Void visitLiteral(LiteralTree node, Boolean inMethodSelect) {
                    return null;
                }

                @Override
                public Void visitArrayType(ArrayTypeTree node, Boolean inMethodSelect) {
                    return null;
                }

                @Override
                public Void visitTypeCast(TypeCastTree node, Boolean inMethodSelect) {
                    return scan(node.getExpression(), Boolean.FALSE);
                }

                @Override
                public Void visitInstanceOf(InstanceOfTree node, Boolean inMethodSelect) {
                    return scan(node.getExpression(), Boolean.FALSE);
                }

                @Override
                public Void visitNewArray(NewArrayTree node, Boolean inMethodSelect) {
                    scan(node.getDimensions(), Boolean.FALSE);
                    scan(node.getInitializers(), Boolean.FALSE);
                    return null;
                }

                @Override
                public Void visitNewClass(NewClassTree node, Boolean inMethodSelect) {
                    scan(node.getEnclosingExpression(), Boolean.FALSE);
                    scan(node.getArguments(), Boolean.FALSE);
                    return null;
                }

                @Override
                public Void visitMethodInvocation(MethodInvocationTree node, Boolean inMethodSelect) {
                    scan(node.getMethodSelect(), Boolean.TRUE);
                    scan(node.getArguments(), Boolean.FALSE);
                    return null;
                }

                @Override
                public Void visitMemberSelect(MemberSelectTree node, Boolean inMethodSelect) {
                    scan(node.getExpression(), Boolean.FALSE);
                    if (!Boolean.TRUE.equals(inMethodSelect)) {
                        String id = node.getIdentifier().toString();
                        if (!id.isEmpty() && !Arrays.asList("class", "length").contains(id)) {
                            values.add(id);
                        }
                    }
                    return null;
                }

                @Override
                public Void visitIdentifier(IdentifierTree node, Boolean inMethodSelect) {
                    if (!Boolean.TRUE.equals(inMethodSelect)) {
                        String value = node.getName().toString();
                        if (!Arrays.asList("true", "false", "null", "new", "return", "this", "super", "void", "class").contains(value)) {
                            values.add(value);
                        }
                    }
                    return null;
                }
            }.scan(tree, Boolean.FALSE);
            return new ArrayList<>(values);
        }

        private String text(Tree tree) {
            String value = tree == null ? "" : tree.toString();
            return value.length() > 1600 ? value.substring(0, 1600) : value;
        }

        @Override
        public Void visitClass(ClassTree node, Void unused) {
            String rawName = node.getSimpleName().toString();
            String name = rawName.isEmpty() ? ("Anonymous$" + line(node)) : rawName;
            String key = key("class", node);
            List<String> anns = node.getModifiers() != null
                    ? annotationTexts(node.getModifiers().getAnnotations())
                    : new ArrayList<>();
            String extendsType = node.getExtendsClause() != null ? text(node.getExtendsClause()) : "";
            List<String> implementsTypes = new ArrayList<>();
            for (Tree iface : node.getImplementsClause()) {
                implementsTypes.add(text(iface));
            }
            String qualified = packageName.isEmpty() ? name : (packageName + "." + name);
            classes.add("{\"key\":" + quote(key) + ",\"name\":" + quote(name)
                    + ",\"qualifiedName\":" + quote(qualified) + ",\"line\":" + line(node)
                    + ",\"endLine\":" + endLine(node)
                    + ",\"annotations\":" + strings(anns)
                    + ",\"extendsType\":" + quote(extendsType)
                    + ",\"implementsTypes\":" + strings(implementsTypes) + "}");
            classKeys.push(key);
            classNames.push(name);
            super.visitClass(node, unused);
            classNames.pop();
            classKeys.pop();
            return null;
        }

        @Override
        public Void visitMethod(MethodTree node, Void unused) {
            String name = node.getName().toString();
            String key = key("function", node);
            List<String> params = new ArrayList<>();
            List<String> paramTypes = new ArrayList<>();
            for (VariableTree parameter : node.getParameters()) {
                params.add(parameter.getName().toString());
                paramTypes.add(parameter.getType() != null ? text(parameter.getType()) : "");
            }
            List<String> anns = node.getModifiers() != null
                    ? annotationTexts(node.getModifiers().getAnnotations())
                    : new ArrayList<>();
            String returnType = node.getReturnType() != null ? text(node.getReturnType()) : "";
            int methodLine = (!anns.isEmpty() && node.getReturnType() != null)
                    ? Math.max(line(node), line(node.getReturnType()))
                    : line(node);
            String qualified = classNames.isEmpty() ? name : classNames.peek() + "." + name;
            functions.add("{\"key\":" + quote(key) + ",\"name\":" + quote(name)
                    + ",\"qualifiedName\":" + quote(qualified) + ",\"line\":" + methodLine
                    + ",\"endLine\":" + endLine(node) + ",\"params\":" + strings(params)
                    + ",\"paramTypes\":" + strings(paramTypes)
                    + ",\"returnType\":" + quote(returnType)
                    + ",\"annotations\":" + strings(anns)
                    + ",\"classKey\":" + (classKeys.isEmpty() ? "null" : quote(classKeys.peek()))
                    + ",\"parentKey\":" + scope() + "}");
            functionKeys.push(key);
            super.visitMethod(node, unused);
            functionKeys.pop();
            return null;
        }

        @Override
        public Void visitVariable(VariableTree node, Void unused) {
            Tree parent = getCurrentPath().getParentPath() != null ? getCurrentPath().getParentPath().getLeaf() : null;
            String varKind = parent instanceof MethodTree ? "param"
                    : (functionKeys.isEmpty() && !classKeys.isEmpty() ? "field" : "local");
            String varType = node.getType() != null ? text(node.getType()) : "";
            String initText = node.getInitializer() != null ? text(node.getInitializer()) : "";
            List<String> initSources = node.getInitializer() != null ? names(node.getInitializer()) : new ArrayList<>();
            variables.add("{\"name\":" + quote(node.getName().toString())
                    + ",\"type\":" + quote(varType)
                    + ",\"kind\":" + quote(varKind)
                    + ",\"line\":" + line(node)
                    + ",\"endLine\":" + endLine(node)
                    + ",\"initializer\":" + quote(initText)
                    + ",\"sources\":" + strings(initSources)
                    + ",\"scopeKey\":" + scope()
                    + ",\"classKey\":" + (classKeys.isEmpty() ? "null" : quote(classKeys.peek())) + "}");
            if (node.getInitializer() != null) {
                assignment(node.getName().toString(), node.getInitializer(), node);
            }
            return super.visitVariable(node, unused);
        }

        @Override
        public Void visitAssignment(AssignmentTree node, Void unused) {
            assignment(text(node.getVariable()), node.getExpression(), node);
            return super.visitAssignment(node, unused);
        }

        @Override
        public Void visitCompoundAssignment(CompoundAssignmentTree node, Void unused) {
            String target = text(node.getVariable());
            LinkedHashSet<String> sources = new LinkedHashSet<>();
            sources.add(target);
            sources.addAll(names(node.getExpression()));
            assignments.add("{\"target\":" + quote(target) + ",\"sources\":" + strings(new ArrayList<>(sources))
                    + ",\"expression\":" + quote(text(node)) + ",\"line\":" + line(node)
                    + ",\"endLine\":" + endLine(node)
                    + ",\"operator\":" + quote(node.getKind().toString())
                    + ",\"scopeKey\":" + scope() + "}");
            return super.visitCompoundAssignment(node, unused);
        }

        private void assignment(String target, Tree expression, Tree anchor) {
            assignments.add("{\"target\":" + quote(target) + ",\"sources\":" + strings(names(expression))
                    + ",\"expression\":" + quote(text(expression)) + ",\"line\":" + line(anchor)
                    + ",\"endLine\":" + endLine(anchor)
                    + ",\"scopeKey\":" + scope() + "}");
        }

        @Override
        public Void visitReturn(ReturnTree node, Void unused) {
            if (node.getExpression() != null) {
                returns.add("{\"expression\":" + quote(text(node.getExpression())) + ",\"sources\":"
                        + strings(names(node.getExpression())) + ",\"line\":" + line(node)
                        + ",\"scopeKey\":" + scope() + "}");
            }
            return super.visitReturn(node, unused);
        }

        @Override
        public Void visitMethodInvocation(MethodInvocationTree node, Void unused) {
            List<String> argumentTexts = new ArrayList<>();
            List<String> argumentSources = new ArrayList<>();
            for (ExpressionTree argument : node.getArguments()) {
                argumentTexts.add(text(argument));
                argumentSources.add(strings(names(argument)));
            }
            String receiver = "";
            String methodName = text(node.getMethodSelect());
            if (node.getMethodSelect() instanceof MemberSelectTree) {
                MemberSelectTree ms = (MemberSelectTree) node.getMethodSelect();
                receiver = text(ms.getExpression());
                methodName = ms.getIdentifier().toString();
            }
            calls.add("{\"callee\":" + quote(text(node.getMethodSelect())) + ",\"expression\":"
                    + quote(text(node)) + ",\"line\":" + line(node) + ",\"endLine\":" + endLine(node)
                    + ",\"col\":" + col(node) + ",\"receiver\":" + quote(receiver)
                    + ",\"methodName\":" + quote(methodName) + ",\"scopeKey\":" + scope()
                    + ",\"argumentTexts\":" + strings(argumentTexts) + ",\"argumentSources\":"
                    + "[" + String.join(",", argumentSources) + "]}");
            return super.visitMethodInvocation(node, unused);
        }

        @Override
        public Void visitNewClass(NewClassTree node, Void unused) {
            List<String> argumentTexts = new ArrayList<>();
            List<String> argumentSources = new ArrayList<>();
            for (ExpressionTree argument : node.getArguments()) {
                argumentTexts.add(text(argument));
                argumentSources.add(strings(names(argument)));
            }
            String ctorType = node.getIdentifier() != null ? text(node.getIdentifier()) : "";
            newClasses.add("{\"type\":" + quote(ctorType)
                    + ",\"expression\":" + quote(text(node))
                    + ",\"line\":" + line(node) + ",\"endLine\":" + endLine(node) + ",\"col\":" + col(node)
                    + ",\"scopeKey\":" + scope()
                    + ",\"argumentTexts\":" + strings(argumentTexts) + ",\"argumentSources\":"
                    + "[" + String.join(",", argumentSources) + "]}");
            return super.visitNewClass(node, unused);
        }

        @Override
        public Void visitIf(IfTree node, Void unused) {
            if (node.getCondition() != null) {
                Tree thenStmt = node.getThenStatement();
                Tree elseStmt = node.getElseStatement();
                controls.add("{\"kind\":\"if\",\"condition\":" + quote(text(node.getCondition()))
                        + ",\"variables\":" + strings(names(node.getCondition()))
                        + ",\"line\":" + line(node) + ",\"endLine\":" + endLine(node)
                        + ",\"thenStartLine\":" + (thenStmt != null ? line(thenStmt) : 0)
                        + ",\"thenEndLine\":" + (thenStmt != null ? endLine(thenStmt) : 0)
                        + ",\"elseStartLine\":" + (elseStmt != null ? line(elseStmt) : 0)
                        + ",\"elseEndLine\":" + (elseStmt != null ? endLine(elseStmt) : 0)
                        + ",\"scopeKey\":" + scope() + "}");
            }
            return super.visitIf(node, unused);
        }

        @Override public Void visitForLoop(ForLoopTree node, Void unused) { control("for", node.getCondition(), node); return super.visitForLoop(node, unused); }

        @Override
        public Void visitEnhancedForLoop(EnhancedForLoopTree node, Void unused) {
            control("for", node.getExpression(), node);
            if (node.getVariable() != null && node.getExpression() != null) {
                assignment(node.getVariable().getName().toString(), node.getExpression(), node.getVariable());
            }
            return super.visitEnhancedForLoop(node, unused);
        }

        @Override public Void visitWhileLoop(WhileLoopTree node, Void unused) { control("while", node.getCondition(), node); return super.visitWhileLoop(node, unused); }
        @Override public Void visitDoWhileLoop(DoWhileLoopTree node, Void unused) { control("while", node.getCondition(), node); return super.visitDoWhileLoop(node, unused); }

        @Override
        public Void visitSwitch(SwitchTree node, Void unused) {
            if (node.getExpression() != null) {
                List<String> caseItems = new ArrayList<>();
                for (CaseTree ct : node.getCases()) {
                    List<String> labels = new ArrayList<>();
                    for (ExpressionTree expr : ct.getExpressions()) {
                        labels.add(text(expr));
                    }
                    boolean isDefault = labels.isEmpty();
                    int cStart = line(ct);
                    int cEnd = endLine(ct);
                    boolean hasBreak = false;
                    List<? extends StatementTree> stmts = ct.getStatements();
                    if (stmts != null && !stmts.isEmpty()) {
                        cStart = line(stmts.get(0));
                        cEnd = endLine(stmts.get(stmts.size() - 1));
                        StatementTree lastStmt = stmts.get(stmts.size() - 1);
                        hasBreak = lastStmt instanceof BreakTree || lastStmt instanceof ReturnTree || lastStmt instanceof ThrowTree;
                    } else if (stmts == null && ct.getBody() != null) {
                        cStart = line(ct.getBody());
                        cEnd = endLine(ct.getBody());
                        hasBreak = true;
                    }
                    caseItems.add("{\"labels\":" + strings(labels)
                            + ",\"isDefault\":" + (isDefault ? "true" : "false")
                            + ",\"startLine\":" + cStart + ",\"endLine\":" + cEnd
                            + ",\"hasBreak\":" + (hasBreak ? "true" : "false") + "}");
                }
                controls.add("{\"kind\":\"switch\",\"condition\":" + quote(text(node.getExpression()))
                        + ",\"variables\":" + strings(names(node.getExpression()))
                        + ",\"line\":" + line(node) + ",\"endLine\":" + endLine(node)
                        + ",\"cases\":" + array(caseItems)
                        + ",\"scopeKey\":" + scope() + "}");
            }
            return super.visitSwitch(node, unused);
        }

        @Override public Void visitCatch(CatchTree node, Void unused) { control("catch", node.getParameter(), node); return super.visitCatch(node, unused); }

        private void control(String kind, Tree condition, Tree anchor) {
            if (condition == null) return;
            controls.add("{\"kind\":" + quote(kind) + ",\"condition\":" + quote(text(condition))
                    + ",\"variables\":" + strings(names(condition)) + ",\"line\":" + line(anchor)
                    + ",\"endLine\":" + endLine(anchor)
                    + ",\"scopeKey\":" + scope() + "}");
        }

        String json() {
            return "{\"status\":\"ok\",\"facts\":{\"packageName\":" + quote(packageName)
                    + ",\"imports\":" + array(imports)
                    + ",\"classes\":" + array(classes)
                    + ",\"functions\":" + array(functions)
                    + ",\"variables\":" + array(variables)
                    + ",\"calls\":" + array(calls)
                    + ",\"newClasses\":" + array(newClasses)
                    + ",\"assignments\":" + array(assignments)
                    + ",\"returns\":" + array(returns)
                    + ",\"controls\":" + array(controls) + "}}";
        }
    }

    private static String array(List<String> values) { return "[" + String.join(",", values) + "]"; }
    private static String strings(List<String> values) {
        List<String> quoted = new ArrayList<>();
        for (String value : values) quoted.add(quote(value));
        return array(quoted);
    }
    private static String quote(String value) {
        StringBuilder output = new StringBuilder("\"");
        for (char character : value.toCharArray()) {
            switch (character) {
                case '\\': output.append("\\\\"); break;
                case '"': output.append("\\\""); break;
                case '\n': output.append("\\n"); break;
                case '\r': output.append("\\r"); break;
                case '\t': output.append("\\t"); break;
                default:
                    if (character < 0x20) output.append(String.format("\\u%04x", (int) character));
                    else output.append(character);
            }
        }
        return output.append('"').toString();
    }

    private static CompilationUnitTree parseOne(JavaCompiler compiler, String id, String source) throws IOException {
        JavacTask task = (JavacTask) compiler.getTask(null, null, null, Arrays.asList("-proc:none"), null,
                Arrays.asList(new MemorySource(id, source)));
        return task.parse().iterator().next();
    }

    private static String collectOne(JavaCompiler compiler, String id, String source) throws IOException {
        JavacTask task = (JavacTask) compiler.getTask(null, null, null, Arrays.asList("-proc:none"), null,
                Arrays.asList(new MemorySource(id, source)));
        CompilationUnitTree unit = task.parse().iterator().next();
        Collector collector = new Collector(unit, Trees.instance(task));
        collector.scan(unit, null);
        return collector.json();
    }

    private static String batch(JavaCompiler compiler, BufferedReader reader) throws IOException {
        List<MemorySource> sources = new ArrayList<>();
        String line;
        while ((line = reader.readLine()) != null) {
            int separator = line.indexOf('\t');
            if (separator <= 0) continue;
            String id = line.substring(0, separator);
            String encoded = line.substring(separator + 1);
            try {
                String content = new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
                sources.add(new MemorySource(id, content));
            } catch (IllegalArgumentException ignored) {
                // The Python caller falls back to its single-file bridge when
                // a batch result is incomplete; do not parse malformed input.
            }
        }
        if (sources.isEmpty()) {
            return "{\"status\":\"ok\",\"files\":[]}";
        }
        JavacTask task = (JavacTask) compiler.getTask(null, null, null, Arrays.asList("-proc:none"), null, sources);
        Map<String, String> ids = new LinkedHashMap<>();
        for (MemorySource source : sources) ids.put(source.toUri().toString(), source.id());
        List<String> entries = new ArrayList<>();
        for (CompilationUnitTree unit : task.parse()) {
            String id = ids.get(unit.getSourceFile().toUri().toString());
            if (id == null) continue;
            Collector collector = new Collector(unit, Trees.instance(task));
            collector.scan(unit, null);
            entries.add("{\"id\":" + quote(id) + ",\"payload\":" + collector.json() + "}");
        }
        return "{\"status\":\"ok\",\"files\":" + array(entries) + "}";
    }

    private static String batch(JavaCompiler compiler) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
            return batch(compiler, reader);
        }
    }

    private static void serve(JavaCompiler compiler) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
            String request;
            while ((request = reader.readLine()) != null) {
                if ("__AUDITFORGE_QUIT__".equals(request)) return;
                String response;
                try {
                    String payload = new String(Base64.getDecoder().decode(request), StandardCharsets.UTF_8);
                    response = batch(compiler, new BufferedReader(new StringReader(payload)));
                } catch (Throwable error) {
                    response = "{\"status\":\"bridge_error\",\"reason\":" + quote(error.toString()) + "}";
                }
                System.out.println(response);
                System.out.flush();
            }
        }
    }

    public static void main(String[] args) {
        try {
            JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
            if (compiler == null) {
                System.out.print("{\"status\":\"compiler_unavailable\",\"reason\":\"JDK compiler API is unavailable\"}");
                return;
            }
            if (args.length == 1 && "--batch".equals(args[0])) {
                System.out.print(batch(compiler));
                return;
            }
            if (args.length == 1 && "--server".equals(args[0])) {
                serve(compiler);
                return;
            }
            String source = new String(System.in.readAllBytes(), StandardCharsets.UTF_8);
            System.out.print(collectOne(compiler, "single", source));
        } catch (Throwable error) {
            System.out.print("{\"status\":\"bridge_error\",\"reason\":" + quote(error.toString()) + "}");
        }
    }
}
