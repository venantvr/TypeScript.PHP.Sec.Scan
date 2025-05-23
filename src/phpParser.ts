import {Tree} from 'tree-sitter';
import treeSitterPhp from 'tree-sitter-php';
import Parser = require("tree-sitter");

export function parsePhpFile(code: string): { tree: Tree | null; source: Buffer | null } {
    const parser = new Parser();
    parser.setLanguage(treeSitterPhp.php);
    try {
        const tree = parser.parse(code);
        return {tree, source: Buffer.from(code, 'utf-8')};
    } catch (error) {
        console.error(`Échec de l'analyse du fichier PHP : ${error}`);
        return {tree: null, source: null};
    }
}