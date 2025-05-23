import {SyntaxNode, Tree} from 'tree-sitter';
import {Rules, Vulnerability} from './types';

export class TaintTracker {
    private taintedVars: Set<string> = new Set();
    private vulnerabilities: Vulnerability[] = [];
    private sanitizedVars: { [varName: string]: Set<string> } = {};

    constructor(
        private sourceCode: Buffer,
        private vulnTypes: string[],
        private rules: Rules
    ) {
    }

    analyze(tree: Tree, filePath: string): Vulnerability[] {
        this.taintedVars.clear();
        this.vulnerabilities = [];
        this.sanitizedVars = {};

        // Débogage : inspecter les nœuds enfants de rootNode
        console.log('Root node children:', tree.rootNode.children.map(n => ({
            type: n.type,
            text: this.getNodeText(n),
            function: n.type === 'function_call_expression' ? this.getFunctionName(n) : null
        })));

        // Chercher function_call_expression dans expression_statement
        const loginNodes = tree.rootNode.namedChildren
            .filter(n => n.type === 'expression_statement')
            .flatMap(n => n.namedChildren)
            .filter(n => {
                if (n.type !== 'function_call_expression') return false;
                const funcName = this.getFunctionName(n);
                if (!funcName) {
                    console.log('No function name for node:', this.getNodeText(n), 'children:', n.namedChildren.map(c => ({
                        type: c.type,
                        text: this.getNodeText(c)
                    })));
                    return false;
                }
                const isAuthFunction = this.rules.auth_functions.includes(funcName);
                console.log(`Checking function: ${funcName}, isAuthFunction: ${isAuthFunction}`);
                return isAuthFunction;
            });

        console.log('loginNodes:', loginNodes.map(n => this.getNodeText(n)));

        for (const node of loginNodes) {
            if (this.isSessionFixation(node)) {
                this.vulnerabilities.push({
                    type: 'session_fixation',
                    sink: 'session_start',
                    line: node.startPosition.row + 1,
                    file: filePath,
                    trace: 'Absence de session_regenerate_id après connexion',
                    severity: 'error'
                });
            }
        }

        this.trackTaint(tree.rootNode, filePath);
        return this.vulnerabilities;
    }

    private getNodeText(node: SyntaxNode | null): string {
        if (!node) return '';
        return this.sourceCode.slice(node.startIndex, node.endIndex).toString('utf-8');
    }

    private getFunctionName(node: SyntaxNode): string {
        const funcNode = node.namedChildren.find(c => c.type === 'name');
        return funcNode ? this.getNodeText(funcNode) : '';
    }

    private isSource(node: SyntaxNode): boolean {
        const text = this.getNodeText(node);
        console.log(`Checking if source: ${text}`);
        if (node.type === 'subscript_expression' && text.startsWith('$_GET')) {
            return true;
        }
        return this.rules.sources.includes(text);
    }

    private isFilterCall(node: SyntaxNode): [boolean, string] {
        const funcName = this.getFunctionName(node);
        if (funcName) {
            // Gérer les appels de méthodes statiques (ex. Sanitizer::sanitizeText)
            const funcNode = node.namedChildren.find(c => c.type === 'member_access_expression');
            if (funcNode) {
                const methodName = funcNode.children.find(c => c.type === 'name')?.text;
                if (methodName && methodName === 'sanitizeText') {
                    return [true, 'xss'];
                }
            }
            for (const [vulnType, filters] of Object.entries(this.rules.filters)) {
                if (filters.includes(funcName)) {
                    // Vérifier si le filtre est non préféré (ex. htmlentities pour XSS)
                    if (vulnType === 'xss' && funcName === 'htmlentities') {
                        this.vulnerabilities.push({
                            type: 'non_preferred_filter',
                            sink: funcName,
                            line: node.startPosition.row + 1,
                            file: '',
                            trace: `Utilisation de ${funcName}. Préférez sanitize_text_field pour XSS.`,
                            severity: 'warning'
                        });
                    }
                    return [true, vulnType];
                }
            }
        }
        return [false, ''];
    }

    private getSinkType(funcName: string): string {
        for (const [vulnType, sinks] of Object.entries(this.rules.sinks)) {
            if (sinks.includes(funcName)) {
                return vulnType;
            }
        }
        return '';
    }

    private isAuthCheck(node: SyntaxNode): boolean {
        if (node.type === 'binary_expression') {
            const operatorNode = node.childForFieldName('operator');
            const leftNode = node.childForFieldName('left');
            const rightNode = node.childForFieldName('right');
            if (operatorNode && leftNode && rightNode) {
                const operator = this.getNodeText(operatorNode);
                if (operator === '==') {
                    const leftText = this.getNodeText(leftNode);
                    const rightText = this.getNodeText(rightNode);
                    return this.rules.auth_checks.some(check => leftText.includes(check) || rightText.includes(check));
                }
            }
        }
        return false;
    }

    private isSessionFixation(node: SyntaxNode): boolean {
        if (node.type === 'function_call_expression') {
            const funcName = this.getFunctionName(node);
            if (funcName && this.rules.session_functions.includes(funcName)) {
                return false;
            }
        }
        return true;
    }

    private analyzeSink(node: SyntaxNode, filePath: string): void {
        const funcName = this.getFunctionName(node);
        if (!funcName) {
            console.log('No function name in analyzeSink for node:', this.getNodeText(node), 'children:', node.namedChildren.map(c => ({
                type: c.type,
                text: this.getNodeText(c)
            })));
            return;
        }
        const vulnType = this.getSinkType(funcName);
        if (!vulnType) return;

        console.log(`Detected sink: ${funcName}, vulnType: ${vulnType}`);

        const argsNode = node.childForFieldName('arguments');
        if (argsNode) {
            console.log(`Arguments for ${funcName}:`, argsNode.namedChildren.map(a => ({
                type: a.type,
                text: this.getNodeText(a),
                children: a.namedChildren.map(c => ({
                    type: c.type,
                    text: this.getNodeText(c)
                }))
            })));
            for (const arg of argsNode.namedChildren) {
                // Vérifier les variables directement
                if (arg.type === 'variable_name') {
                    const argName = this.getNodeText(arg);
                    if (this.taintedVars.has(argName) && !this.sanitizedVars[argName]?.has(vulnType)) {
                        console.log(`Adding vulnerability for variable: ${argName}`);
                        this.vulnerabilities.push({
                            type: vulnType,
                            sink: funcName,
                            variable: argName,
                            line: node.startPosition.row + 1,
                            file: filePath,
                            trace: `Source tainted: ${argName} → Sink: ${funcName}`,
                            severity: 'error'
                        });
                    }
                }
                // Vérifier les arguments qui contiennent des encapsed_string
                if (arg.type === 'argument') {
                    const encapsedString = arg.namedChildren.find(c => c.type === 'encapsed_string');
                    if (encapsedString) {
                        for (const child of encapsedString.namedChildren) {
                            if (child.type === 'variable_name') {
                                const argName = this.getNodeText(child);
                                if (this.taintedVars.has(argName) && !this.sanitizedVars[argName]?.has(vulnType)) {
                                    console.log(`Adding vulnerability for interpolated variable: ${argName}`);
                                    this.vulnerabilities.push({
                                        type: vulnType,
                                        sink: funcName,
                                        variable: argName,
                                        line: node.startPosition.row + 1,
                                        file: filePath,
                                        trace: `Source tainted: ${argName} → Sink: ${funcName} (interpolated)`,
                                        severity: 'error'
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private trackTaint(node: SyntaxNode, filePath: string, inAuthContext: boolean = false): void {
        if (node.type === 'assignment_expression') {
            const left = node.childForFieldName('left');
            const right = node.childForFieldName('right');
            if (left?.type === 'variable_name' && right) {
                const varName = this.getNodeText(left);
                console.log(`Assignment: ${varName} = ${this.getNodeText(right)}, isSource: ${this.isSource(right)}`);
                if (this.isSource(right)) {
                    this.taintedVars.add(varName);
                    console.log(`Adding unsanitized_source for: ${varName}`);
                    this.vulnerabilities.push({
                        type: 'unsanitized_source',
                        sink: varName,
                        variable: varName,
                        line: node.startPosition.row + 1,
                        file: filePath,
                        trace: `Source non désinfectée: ${varName}`,
                        severity: 'warning'
                    });
                } else if (right.namedChildren.some(c => c.type === 'variable_name' && this.taintedVars.has(this.getNodeText(c)))) {
                    this.taintedVars.add(varName);
                    console.log(`Adding unsanitized_source (propagation) for: ${varName}`);
                    this.vulnerabilities.push({
                        type: 'unsanitized_source',
                        sink: varName,
                        variable: varName,
                        line: node.startPosition.row + 1,
                        file: filePath,
                        trace: `Propagation de source non désinfectée: ${varName}`,
                        severity: 'warning'
                    });
                }
            }
        } else if (node.type === 'expression_statement') {
            // Chercher function_call_expression dans expression_statement
            const callNodes = node.namedChildren.filter(c => c.type === 'function_call_expression');
            for (const callNode of callNodes) {
                const [isFilter, vulnType] = this.isFilterCall(callNode);
                if (isFilter) {
                    const args = callNode.childForFieldName('arguments');
                    if (args && args.namedChildren[0]?.type === 'variable_name') {
                        const varName = this.getNodeText(args.namedChildren[0]);
                        this.sanitizedVars[varName] = this.sanitizedVars[varName] || new Set();
                        this.sanitizedVars[varName].add(vulnType);
                    }
                } else {
                    this.analyzeSink(callNode, filePath);
                }
            }
        } else if (node.type === 'binary_expression' && this.isAuthCheck(node)) {
            this.vulnerabilities.push({
                type: 'auth_bypass',
                sink: 'weak_comparison',
                line: node.startPosition.row + 1,
                file: filePath,
                trace: 'Comparaison faible (==) détectée dans une vérification d\'authentification',
                severity: 'error'
            });
        } else if (node.type === 'function_call_expression') {
            const funcName = this.getFunctionName(node);
            if (funcName && this.rules.upload_functions.includes(funcName)) {
                const args = node.childForFieldName('arguments');
                if (args && args.namedChildren.some(arg => arg.type === 'variable_name' && this.taintedVars.has(this.getNodeText(arg)))) {
                    this.vulnerabilities.push({
                        type: 'insecure_upload',
                        sink: 'move_uploaded_file',
                        line: node.startPosition.row + 1,
                        file: filePath,
                        trace: 'Upload de fichier sans validation détectée',
                        severity: 'error'
                    });
                }
            }
        }

        inAuthContext = inAuthContext || (
            node.type === 'function_call_expression' &&
            this.rules.auth_functions.includes(this.getFunctionName(node))
        );

        for (const child of node.children) {
            this.trackTaint(child, filePath, inAuthContext);
        }
    }
}