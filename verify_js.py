import re

def check_js_syntax(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 提取 script 标签内容
    match = re.search(r'<script>(.*?)</script>', content, re.DOTALL)
    if not match:
        print("Error: No script tag found")
        return
    
    js = match.group(1)
    
    # 简单的平衡性检查
    pairs = {
        '(': ')',
        '[': ']',
        '{': '}',
        '`': '`'
    }
    
    stack = []
    in_string = None
    in_template = 0
    
    for i, char in enumerate(js):
        if in_string:
            if char == in_string and js[i-1] != '\\':
                in_string = None
            continue
        
        if char in ["'", '"']:
            in_string = char
            continue
            
        if char == '`':
            # 模板字符串比较特殊，可以嵌套 ${}
            # 但这里我们先做简单计数
            pass

        if char in pairs.keys():
            stack.append((char, i))
        elif char in pairs.values():
            if not stack:
                print(f"Error: Unexpected closed char {char} at index {i}")
                # 打印上下文
                print(js[max(0, i-50):min(len(js), i+50)])
                return
            opening, pos = stack.pop()
            if pairs[opening] != char:
                print(f"Error: Mismatched {opening} at {pos} with {char} at {i}")
                print(js[max(0, pos-20):min(len(js), i+20)])
                return
                
    if stack:
        for char, pos in stack:
            print(f"Error: Unclosed {char} at {pos}")
            print(js[max(0, pos-20):min(len(js), pos+50)])
    else:
        print("Basic balance check passed")

if __name__ == "__main__":
    check_js_syntax("go-version/resources/public/admin.html")
