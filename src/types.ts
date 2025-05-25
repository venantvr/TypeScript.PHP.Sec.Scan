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
}

export interface CodeEvent {
    type: 'assignment' | 'function_call';
    line: number;
    file: string;
    details: AssignmentDetails | FunctionCallDetails;
}

export interface AssignmentDetails {
    variable: string;
    source: string;
}

export interface FunctionCallDetails {
    functionName: string;
    arguments: string[];
}

export interface TaintFlowEntry {
    variable: string;
    source: string;
    line: number;
    action: 'assignment' | 'function_parameter';
    details: string;
    file: string;
}
