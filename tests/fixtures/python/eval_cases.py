def execute_math(expr):
    return eval(expr)

def safe_math(data):
    import json
    return json.loads(data)
