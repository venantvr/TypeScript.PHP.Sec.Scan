import * as vscode from 'vscode';
import {TaintTracker} from './taintTracker';
import {parsePhpFile} from './phpParser';
import {getConfig, loadRules} from './config';

export function activate(context: vscode.ExtensionContext) {
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('phpSecurityScanner');
    context.subscriptions.push(diagnosticCollection);

    // Enregistrer un fournisseur de code actions
    const codeActionProvider = vscode.languages.registerCodeActionsProvider('php', {
        provideCodeActions(document, range, context) {
            const diagnostics = context.diagnostics.filter(d => d.source === 'phpSecurityScanner');
            const actions: vscode.CodeAction[] = [];

            for (const diagnostic of diagnostics) {
                if (diagnostic.message.includes('weak_comparison')) {
                    const action = new vscode.CodeAction(
                        'Remplacer == par === pour une comparaison stricte',
                        vscode.CodeActionKind.QuickFix
                    );
                    action.diagnostics = [diagnostic];
                    action.edit = new vscode.WorkspaceEdit();
                    const line = document.lineAt(diagnostic.range.start.line);
                    const newText = line.text.replace('==', '===');
                    action.edit.replace(document.uri, line.range, newText);
                    actions.push(action);
                } else if (diagnostic.message.includes('Source tainted') && diagnostic.message.includes('xss')) {
                    const action = new vscode.CodeAction(
                        'Ajouter htmlspecialchars pour désinfecter',
                        vscode.CodeActionKind.QuickFix
                    );
                    action.diagnostics = [diagnostic];
                    action.edit = new vscode.WorkspaceEdit();
                    const line = document.lineAt(diagnostic.range.start.line);
                    const match = line.text.match(/echo\s+(\$\w+)/);
                    if (match) {
                        const newText = line.text.replace(match[0], `echo htmlspecialchars(${match[1]})`);
                        action.edit.replace(document.uri, line.range, newText);
                    }
                    actions.push(action);
                } else if (diagnostic.message.includes('htmlentities')) {
                    const action = new vscode.CodeAction(
                        'Remplacer htmlentities par sanitize_text_field',
                        vscode.CodeActionKind.QuickFix
                    );
                    action.diagnostics = [diagnostic];
                    action.edit = new vscode.WorkspaceEdit();
                    const line = document.lineAt(diagnostic.range.start.line);
                    const match = line.text.match(/htmlentities\((\$\w+)\)/);
                    if (match) {
                        const newText = line.text.replace(/htmlentities\((\$\w+)\)/, `sanitize_text_field($1)`);
                        action.edit.replace(document.uri, line.range, newText);
                    }
                    actions.push(action);
                }
            }
            return actions;
        }
    });
    context.subscriptions.push(codeActionProvider);

    const scanCommand = vscode.commands.registerCommand('phpSecurityScanner.scan', async () => {
        diagnosticCollection.clear();
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders) {
            vscode.window.showErrorMessage('Aucun dossier de workspace ouvert.');
            return;
        }

        const config = getConfig();
        const rules = loadRules(context);
        const includePatterns = config.includePatterns;
        const excludePatterns = config.excludePatterns;
        const vulnTypes = config.vulnTypes;

        for (const folder of workspaceFolders) {
            const files = await vscode.workspace.findFiles(
                new vscode.RelativePattern(folder, `{${includePatterns.join(',')}}`),
                new vscode.RelativePattern(folder, `{${excludePatterns.join(',')}}`)
            );

            for (const file of files) {
                try {
                    const document = await vscode.workspace.openTextDocument(file);
                    const code = document.getText();

                    // Vérifier la syntaxe PHP avec les diagnostics natifs de VS Code
                    const nativeDiagnostics = vscode.languages.getDiagnostics(file).filter(d => d.source !== 'phpSecurityScanner');
                    if (nativeDiagnostics.some(d => d.severity === vscode.DiagnosticSeverity.Error)) {
                        diagnosticCollection.set(file, [
                            new vscode.Diagnostic(
                                new vscode.Range(0, 0, 0, Number.MAX_SAFE_INTEGER),
                                'Erreurs de syntaxe PHP détectées. Veuillez corriger avant l\'analyse de sécurité.',
                                vscode.DiagnosticSeverity.Warning
                            )
                        ]);
                        continue;
                    }

                    const {tree, source} = parsePhpFile(code);
                    if (!tree || !source) {
                        continue;
                    }

                    const tracker = new TaintTracker(source, vulnTypes, rules);
                    const vulnerabilities = tracker.analyze(tree, file.fsPath);
                    const diagnostics = vulnerabilities.map(vuln => {
                        const range = new vscode.Range(vuln.line - 1, 0, vuln.line - 1, Number.MAX_SAFE_INTEGER);
                        const diagnostic = new vscode.Diagnostic(
                            range,
                            `${vuln.type}: ${vuln.trace} (Sink: ${vuln.sink})`,
                            vuln.severity === 'error' ? vscode.DiagnosticSeverity.Error : vscode.DiagnosticSeverity.Warning
                        );
                        diagnostic.source = 'phpSecurityScanner';
                        return diagnostic;
                    });

                    diagnosticCollection.set(file, diagnostics);
                } catch (error) {
                    diagnosticCollection.set(file, [
                        new vscode.Diagnostic(
                            new vscode.Range(0, 0, 0, Number.MAX_SAFE_INTEGER),
                            `Erreur d'analyse: ${error}`,
                            vscode.DiagnosticSeverity.Error
                        )
                    ]);
                }
            }
        }

        vscode.window.showInformationMessage('Analyse de sécurité PHP terminée.');
    });

    context.subscriptions.push(scanCommand);

    // Analyse automatique à la sauvegarde
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(async document => {
            if (document.languageId === 'php') {
                const config = getConfig();
                const rules = loadRules(context);

                // Vérifier la syntaxe PHP avec les diagnostics natifs
                const nativeDiagnostics = vscode.languages.getDiagnostics(document.uri).filter(d => d.source !== 'phpSecurityScanner');
                if (nativeDiagnostics.some(d => d.severity === vscode.DiagnosticSeverity.Error)) {
                    diagnosticCollection.set(document.uri, [
                        new vscode.Diagnostic(
                            new vscode.Range(0, 0, 0, Number.MAX_SAFE_INTEGER),
                            'Erreurs de syntaxe PHP détectées. Veuillez corriger avant l\'analyse de sécurité.',
                            vscode.DiagnosticSeverity.Warning
                        )
                    ]);
                    return;
                }

                const {tree, source} = parsePhpFile(document.getText());
                if (!tree || !source) {
                    return;
                }

                const tracker = new TaintTracker(source, config.vulnTypes, rules);
                const vulnerabilities = tracker.analyze(tree, document.uri.fsPath);
                const diagnostics = vulnerabilities.map(vuln => {
                    const range = new vscode.Range(vuln.line - 1, 0, vuln.line - 1, Number.MAX_SAFE_INTEGER);
                    const diagnostic = new vscode.Diagnostic(
                        range,
                        `${vuln.type}: ${vuln.trace} (Sink: ${vuln.sink})`,
                        vuln.severity === 'error' ? vscode.DiagnosticSeverity.Error : vscode.DiagnosticSeverity.Warning
                    );
                    diagnostic.source = 'phpSecurityScanner';
                    return diagnostic;
                });

                diagnosticCollection.set(document.uri, diagnostics);
            }
        })
    );
}

export function deactivate() {
}