declare module 'tree-sitter-php' {
    interface PhpLanguage {
        // Interface générique pour le langage PHP utilisé par tree-sitter
    }

    interface PhpModule {
        php: PhpLanguage;
        php_only: PhpLanguage;
    }

    const TreeSitterPhp: PhpModule;
    export = TreeSitterPhp;
}