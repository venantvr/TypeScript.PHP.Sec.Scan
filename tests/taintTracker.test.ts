import {expect} from 'chai';
import {TaintTracker} from '../src/taintTracker';
import {Rules} from '../src/types';
import Parser = require("tree-sitter");

const treeSitterPhp = require('tree-sitter-php');

// Configuration des règles pour les tests
const rules: Rules = {
    sources: ['$_GET', '$_POST', '$_COOKIE', '$_REQUEST', '$_FILES'],
    filters: {
        sql_injection: ['mysqli_real_escape_string', 'filter_var'],
        xss: ['htmlspecialchars', 'htmlentities', 'sanitize_text_field'],
        rce: ['escapeshellcmd', 'escapeshellarg']
    },
    sinks: {
        sql_injection: ['mysqli_query', 'mysql_query'],
        xss: ['echo', 'print', 'printf'],
        rce: ['system', 'exec', 'shell_exec', 'passthru'],
        file_inclusion: ['include', 'require', 'include_once', 'require_once']
    },
    auth_checks: ['password_verify', 'hash_equals'],
    auth_functions: ['login', 'authenticate'],
    session_functions: ['session_regenerate_id'],
    upload_functions: ['move_uploaded_file']
};

// Initialisation du parseur
const parser = new Parser();
parser.setLanguage(treeSitterPhp.php);

describe('TaintTracker', () => {
    it('devrait détecter une injection SQL', () => {
        const code = `
      <?php
      $id = $_GET['id'];
      mysqli_query($conn, "SELECT * FROM users WHERE id = $id");
      ?>
    `;
        const tree = parser.parse(code);
        const tracker = new TaintTracker(Buffer.from(code, 'utf-8'), ['sql_injection'], rules);
        const vulnerabilities = tracker.analyze(tree, 'test.php');
        expect(vulnerabilities).to.have.lengthOf(2); // 1 vulnérabilité + 1 avertissement
        expect(vulnerabilities.some(v => v.type === 'sql_injection' && v.sink === 'mysqli_query' && v.variable === '$id' && v.severity === 'error')).to.be.true;
        expect(vulnerabilities.some(v => v.type === 'unsanitized_source' && v.variable === '$id' && v.severity === 'warning')).to.be.true;
    });

    it('ne devrait pas détecter de XSS avec désinfection', () => {
        const code = `
      <?php
      $input = $_GET['input'];
      $safe = htmlspecialchars($input);
      echo $safe;
      ?>
    `;
        const tree = parser.parse(code);
        const tracker = new TaintTracker(Buffer.from(code, 'utf-8'), ['xss'], rules);
        const vulnerabilities = tracker.analyze(tree, 'test.php');
        expect(vulnerabilities).to.have.lengthOf(1); // Avertissement pour source non désinfectée
        expect(vulnerabilities.some(v => v.type === 'unsanitized_source' && v.variable === '$input' && v.severity === 'warning')).to.be.true;
    });

    it('devrait détecter une comparaison faible', () => {
        const code = `
      <?php
      if ($password == $_POST['password']) {
        login();
      }
      ?>
    `;
        const tree = parser.parse(code);
        const tracker = new TaintTracker(Buffer.from(code, 'utf-8'), ['auth_bypass'], rules);
        const vulnerabilities = tracker.analyze(tree, 'test.php');
        expect(vulnerabilities).to.have.lengthOf(2); // 1 vulnérabilité + 1 avertissement
        expect(vulnerabilities.some(v => v.type === 'auth_bypass' && v.sink === 'weak_comparison' && v.severity === 'error')).to.be.true;
        expect(vulnerabilities.some(v => v.type === 'unsanitized_source' && v.variable === '$_POST[\'password\']' && v.severity === 'warning')).to.be.true;
    });

    it('devrait détecter une injection SQL via un paramètre de fonction', () => {
        const code = `
      <?php
      function run_query($conn, $value) {
        mysqli_query($conn, "SELECT * FROM users WHERE id = $value");
      }
      $id = $_GET['id'];
      run_query($conn, $id);
      ?>
    `;
        const tree = parser.parse(code);
        const tracker = new TaintTracker(Buffer.from(code, 'utf-8'), ['sql_injection'], rules);
        const vulnerabilities = tracker.analyze(tree, 'test.php');
        expect(vulnerabilities).to.have.lengthOf(2); // 1 vulnérabilité + 1 avertissement
        expect(vulnerabilities.some(v => v.type === 'sql_injection' && v.sink === 'mysqli_query' && v.variable === '$value' && v.severity === 'error')).to.be.true;
        expect(vulnerabilities.some(v => v.type === 'unsanitized_source' && v.variable === '$id' && v.severity === 'warning')).to.be.true;
    });

    it('devrait détecter une XSS via le retour d\'une fonction', () => {
        const code = `
      <?php
      function get_tainted() {
        return $_POST['data'];
      }
      $x = get_tainted();
      echo $x;
      ?>
    `;
        const tree = parser.parse(code);
        const tracker = new TaintTracker(Buffer.from(code, 'utf-8'), ['xss'], rules);
        const vulnerabilities = tracker.analyze(tree, 'test.php');
        expect(vulnerabilities).to.have.lengthOf(2); // 1 vulnérabilité + 1 avertissement
        expect(vulnerabilities.some(v => v.type === 'xss' && v.sink === 'echo' && v.variable === '$x' && v.severity === 'error')).to.be.true;
        expect(vulnerabilities.some(v => v.type === 'unsanitized_source' && v.variable === '$x' && v.severity === 'warning')).to.be.true;
    });

    it('devrait détecter un upload de fichier non sécurisé', () => {
        const code = `
      <?php
      $file = $_FILES['upload'];
      move_uploaded_file($file, 'uploads/');
      ?>
    `;
        const tree = parser.parse(code);
        const tracker = new TaintTracker(Buffer.from(code, 'utf-8'), ['insecure_upload'], rules);
        const vulnerabilities = tracker.analyze(tree, 'test.php');
        expect(vulnerabilities).to.have.lengthOf(2); // 1 vulnérabilité + 1 avertissement
        expect(vulnerabilities.some(v => v.type === 'insecure_upload' && v.sink === 'move_uploaded_file' && v.severity === 'error')).to.be.true;
        expect(vulnerabilities.some(v => v.type === 'unsanitized_source' && v.variable === '$file' && v.severity === 'warning')).to.be.true;
    });

    it('devrait détecter une session fixation', () => {
        const code = `
      <?php
      login();
      session_start();
      ?>
    `;
        const tree = parser.parse(code);
        const tracker = new TaintTracker(Buffer.from(code, 'utf-8'), ['session_fixation'], rules);
        const vulnerabilities = tracker.analyze(tree, 'test.php');
        expect(vulnerabilities).to.have.lengthOf(1);
        expect(vulnerabilities.some(v => v.type === 'session_fixation' && v.sink === 'session_start' && v.severity === 'error')).to.be.true;
    });

    it('devrait détecter l\'usage de htmlentities comme filtre non préféré', () => {
        const code = `
      <?php
      $input = $_POST['data'];
      $safe = htmlentities($input);
      echo $safe;
      ?>
    `;
        const tree = parser.parse(code);
        const tracker = new TaintTracker(Buffer.from(code, 'utf-8'), ['xss'], rules);
        const vulnerabilities = tracker.analyze(tree, 'test.php');
        expect(vulnerabilities).to.have.lengthOf(2); // 1 avertissement pour htmlentities + 1 pour source non désinfectée
        expect(vulnerabilities.some(v => v.type === 'non_preferred_filter' && v.sink === 'htmlentities' && v.severity === 'warning')).to.be.true;
        expect(vulnerabilities.some(v => v.type === 'unsanitized_source' && v.variable === '$input' && v.severity === 'warning')).to.be.true;
    });

    it('devrait ne pas détecter de XSS avec méthode de classe comme filtre', () => {
        const code = `
      <?php
      class Sanitizer {
        static function sanitizeText($input) {
          return sanitize_text_field($input);
        }
      }
      $input = $_POST['data'];
      $safe = Sanitizer::sanitizeText($input);
      echo $safe;
      ?>
    `;
        const tree = parser.parse(code);
        const tracker = new TaintTracker(Buffer.from(code, 'utf-8'), ['xss'], rules);
        const vulnerabilities = tracker.analyze(tree, 'test.php');
        expect(vulnerabilities).to.have.lengthOf(1); // Avertissement pour source non désinfectée
        expect(vulnerabilities.some(v => v.type === 'unsanitized_source' && v.variable === '$input' && v.severity === 'warning')).to.be.true;
    });
});