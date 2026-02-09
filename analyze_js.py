def analyze_structure(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    start_tag = "<script>"
    end_tag = "</script>"
    start_idx = content.find(start_tag) + len(start_tag)
    end_idx = content.find(end_tag)
    js = content[start_idx:end_idx]
    
    lines = js.split('\n')
    
    # 层级跟踪
    braces = 0
    brackets = 0
    parens = 0
    backticks = 0
    
    for i, line in enumerate(lines, 1):
        for char in line:
            if char == '{': braces += 1
            elif char == '}': braces -= 1
            elif char == '[': brackets += 1
            elif char == ']': brackets -= 1
            elif char == '(': parens += 1
            elif char == ')': parens -= 1
            elif char == '`': backticks += 1
        
        if braces < 0 or brackets < 0 or parens < 0:
            print(f"Negative balance at line {i}: {line.strip()}")
            return
            
    print(f"Final counts - Braces: {braces}, Brackets: {brackets}, Parens: {parens}, Backticks: {backticks}")
    if braces != 0: print("Error: Braces mismatch")
    if brackets != 0: print("Error: Brackets mismatch")
    if parens != 0: print("Error: Parens mismatch")
    if backticks % 2 != 0: print("Error: Backticks mismatch (odd count)")

if __name__ == "__main__":
    analyze_structure("go-version/resources/public/admin.html")
