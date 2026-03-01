import re
from pathlib import Path
from typing import List, Dict, Any

def strip_js_comments(source_code: str) -> str:
    """
    Remove JavaScript single-line (//) and multi-line (/* */) comments to prevent false positives.
    """
    # Regex to catch comments but avoid stripping URLs in strings (e.g., "http://...")
    # This is a simplified regex-based approach. We replace comments with spaces
    # to maintain line numbers if later mapping is needed.
    
    # First, block comments /* ... */
    # Using re.DOTALL to match across newlines
    source_code = re.sub(r'/\*.*?\*/', lambda m: ' ' * len(m.group(0)), source_code, flags=re.DOTALL)
    
    # Then, single line comments // ... but not inside strings.
    # A robust regex for this is complex, but this heuristically handles most cases
    # by replacing the comment part with empty space.
    lines = source_code.split('\n')
    cleaned_lines = []
    
    for line in lines:
        in_string = False
        string_char = None
        escape = False
        comment_start = -1
        
        for i, char in enumerate(line):
            if escape:
                escape = False
                continue
                
            if char == '\\':
                escape = True
                continue
                
            if char in ('"', "'", '`'):
                if not in_string:
                    in_string = True
                    string_char = char
                elif string_char == char:
                    in_string = False
                continue
                
            if not in_string and char == '/' and i + 1 < len(line) and line[i+1] == '/':
                comment_start = i
                break
                
        if comment_start != -1:
            line = line[:comment_start]
            
        cleaned_lines.append(line)
        
    return '\n'.join(cleaned_lines)

def check_0000_binding_in_js(filepath: Path) -> List[int]:
    """
    Checks if a JS/TS file binds to '0.0.0.0' using a simple AST-like semantic search.
    Returns a list of line numbers where it occurs outside of comments.
    """
    if not filepath.exists():
        return []
        
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            source = f.read()
    except Exception:
        return []
        
    cleaned_source = strip_js_comments(source)
    lines = cleaned_source.split('\n')
    
    suspicious_lines = []
    
    # Looks for '0.0.0.0' or "0.0.0.0" or `0.0.0.0`
    pattern = re.compile(r"['\"`]0\.0\.0\.0['\"`]")
    
    for i, line in enumerate(lines, 1):
        if pattern.search(line):
            # We add context-awareness: it must be an assignment, object property, or function call.
            # Example: host: '0.0.0.0', host="0.0.0.0", listen(8080, '0.0.0.0')
            if re.search(r"(host|bind)\s*[:=]\s*['\"`]0\.0\.0\.0['\"`]", line, re.IGNORECASE) or \
               re.search(r"listen\s*\([^\)]*['\"`]0\.0\.0\.0['\"`]", line):
                suspicious_lines.append(i)
                
    return suspicious_lines

def check_direct_exec_in_js(filepath: Path) -> List[int]:
    """
    Checks for child_process exec/execSync piping curl/wget to bash/sh.
    Returns list of line numbers.
    """
    if not filepath.exists():
        return []

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            source = f.read()
    except Exception:
        return []

    cleaned_source = strip_js_comments(source)
    lines = cleaned_source.split('\n')
    
    suspicious_lines = []
    
    # Looks for child_process calls like exec or execSync
    exec_pattern = re.compile(r"exec(Sync)?\s*\(")
    # Looks for the bash pipe pattern
    pipe_pattern = re.compile(r"(curl|wget)[\s\S]+?\|[\s\S]*(bash|sh|zsh)")
    
    for i, line in enumerate(lines, 1):
        if exec_pattern.search(line) and pipe_pattern.search(line):
            suspicious_lines.append(i)
            
    return suspicious_lines
