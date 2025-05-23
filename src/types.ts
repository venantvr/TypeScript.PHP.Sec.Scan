export interface Vulnerability {
    type: string;
    sink: string;
    variable?: string;
    line: number;
    file: string;
    trace: string;
    severity: 'error' | 'warning';
}

export interface Rules {
    sources: string[];
    filters: { [vulnType: string]: string[] };
    sinks: { [vulnType: string]: string[] };
    auth_checks: string[];
    auth_functions: string[];
    session_functions: string[];
    upload_functions: string[];
}
