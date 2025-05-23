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

        const loginNodes = tree.rootNode.children.filter(
            n => n.type === 'function_call_expression' && this.rules.auth_functions.includes(this.getNodeText(n.childForFieldName('function')!))
        );

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

    private getNodeText(node: SyntaxNode): string {
        return this.sourceCode.slice(node.startIndex, node.endIndex).toString('utf-8');
    }

    private isSource(node: SyntaxNode): boolean {
        const text = this.getNodeText(node);
        return this.rules.sources.includes(text);
    }

    private isFilterCall(node: SyntaxNode): [boolean, string] {
        const func = node.childForFieldName('function');
        if (func) {
            const funcName = this.getNodeText(func);
            // Gérer les appels de méthodes statiques (ex. Sanitizer::sanitizeText)
            if (func.type === 'member_access_expression') {
                const methodName = func.children.find(c => c.type === 'name')?.text;
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
            const func = node.childForFieldName('function');
            if (func && this.rules.session_functions.includes(this.getNodeText(func))) {
                return false;
            }
        }
        return true;
    }

    private analyzeSink(node: SyntaxNode, filePath: string): void {
        const funcNode = node.childForFieldName('function');
        if (!funcNode) return;
        const funcName = this.getNodeText(funcNode);
        const vulnType = this.getSinkType(funcName);
        if (!vulnType) return;

        const argsNode = node.childForFieldName('arguments');
        if (argsNode) {
            for (const arg of argsNode.namedChildren) {
                if (arg.type === 'variable_name') {
                    const argName = this.getNodeText(arg);
                    if (this.taintedVars.has(argName) && !this.sanitizedVars[argName]?.has(vulnType)) {
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
            }
        }
    }

    private trackTaint(node: SyntaxNode, filePath: string, inAuthContext: boolean = false): void {
        if (node.type === 'assignment_expression') {
            const left = node.childForFieldName('left');
            const right = node.childForFieldName('right');
            if (left?.type === 'variable_name' && right) {
                const varName = this.getNodeText(left);
                if (this.isSource(right)) {
                    this.taintedVars.add(varName);
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
        } else if (node.type === 'function_call_expression') {
            const [isFilter, vulnType] = this.isFilterCall(node);
            if (isFilter) {
                const args = node.childForFieldName('arguments');
                if (args && args.namedChildren[0]?.type === 'variable_name') {
                    const varName = this.getNodeText(args.namedChildren[0]);
                    this.sanitizedVars[varName] = this.sanitizedVars[varName] || new Set();
                    this.sanitizedVars[varName].add(vulnType);
                }
            } else {
                this.analyzeSink(node, filePath);
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
        } else if (node.type === 'function_call_expression' && this.rules.upload_functions.includes(this.getNodeText(node.childForFieldName('function')!))) {
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

        inAuthContext = inAuthContext || (
            node.type === 'function_call_expression' &&
            this.rules.auth_functions.includes(this.getNodeText(node.childForFieldName('function')!))
        );

        for (const child of node.children) {
            this.trackTaint(child, filePath, inAuthContext);
        }
    }
}