import * as vscode from 'vscode';
import * as yaml from 'js-yaml';
import * as fs from 'fs';
import * as path from 'path';
import {Rules} from './types';

export function getConfig() {
    const config = vscode.workspace.getConfiguration('phpSecurityScanner');
    return {
        vulnTypes: config.get<string[]>('vulnTypes') || [],
        includePatterns: config.get<string[]>('includePatterns') || ['**/*.php'],
        excludePatterns: config.get<string[]>('excludePatterns') || ['**/vendor/**', '**/node_modules/**'],
        rulesFile: config.get<string>('rulesFile') || ''
    };
}

export function loadRules(context: vscode.ExtensionContext): Rules {
    const defaultRulesPath = path.join(context.extensionPath, 'rules.yaml');
    const config = getConfig();
    const rulesPath = config.rulesFile ? path.resolve(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '.', config.rulesFile) : defaultRulesPath;

    try {
        const rulesContent = fs.readFileSync(rulesPath, 'utf-8');
        return yaml.load(rulesContent) as Rules;
    } catch (error) {
        vscode.window.showErrorMessage(`Échec du chargement des règles depuis ${rulesPath}: ${error}`);
        return {
            sources: [],
            filters: {},
            sinks: {},
            auth_checks: [],
            auth_functions: [],
            session_functions: [],
            upload_functions: []
        };
    }
}