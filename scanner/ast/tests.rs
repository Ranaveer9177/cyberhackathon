use crate::ast::parse_file;
use crate::ast::types::*;

#[test]
fn test_ast_simple_function() {
    let code = "def add(a, b):\n    return a + b\n";
    let node = parse_file("calc.py", code).expect("Failed to parse simple function");
    assert_eq!(node.functions.len(), 1);
    let f = &node.functions[0];
    assert_eq!(f.name, "add");
    assert_eq!(f.params, vec!["a", "b"]);
    assert!(!f.body.is_empty());
}

#[test]
fn test_ast_multiline_function() {
    let code = r#"
def process_data(items):
    total = 0
    for x in items:
        if x > 0:
            total += x
    return total
"#;
    let node = parse_file("data.py", code).expect("Failed to parse multiline function");
    assert_eq!(node.functions.len(), 1);
    let f = &node.functions[0];
    assert_eq!(f.name, "process_data");
    assert_eq!(f.params, vec!["items"]);
    assert!(f.body.len() >= 2);
}

#[test]
fn test_ast_nested_expression() {
    let code = "result = a + (b + c)\n";
    let node = parse_file("calc.py", code).expect("Failed to parse nested expression");
    assert!(!node.statements.is_empty());
    if let StmtNode::Assignment(assign) = &node.statements[0] {
        assert_eq!(assign.target.to_source_string(), "result");
        match &assign.value {
            ExprNode::BinaryOp { op, left, .. } => {
                assert_eq!(op, "+");
                assert_eq!(left.to_source_string(), "a");
            }
            _ => panic!(
                "Expected BinaryOp for nested expression, got {:?}",
                assign.value
            ),
        }
    } else {
        panic!("Expected assignment statement");
    }
}

#[test]
fn test_ast_lambda_expression() {
    let code = "square = lambda x: x * x\n";
    let node = parse_file("fn.py", code).expect("Failed to parse lambda expression");
    assert!(!node.statements.is_empty());
    if let StmtNode::Assignment(assign) = &node.statements[0] {
        assert_eq!(assign.target.to_source_string(), "square");
        assert!(assign.value.to_source_string().contains("lambda"));
    } else {
        panic!("Expected assignment of lambda");
    }
}

#[test]
fn test_ast_nested_call() {
    let code = "output = outer(inner(value))\n";
    let node = parse_file("calls.py", code).expect("Failed to parse nested call");
    assert!(!node.statements.is_empty());
    if let StmtNode::Assignment(assign) = &node.statements[0] {
        match &assign.value {
            ExprNode::Call { callee, args, .. } => {
                assert_eq!(callee.to_source_string(), "outer");
                assert_eq!(args.len(), 1);
                match &args[0] {
                    ExprNode::Call {
                        callee: inner_callee,
                        args: inner_args,
                        ..
                    } => {
                        assert_eq!(inner_callee.to_source_string(), "inner");
                        assert_eq!(inner_args.len(), 1);
                        assert_eq!(inner_args[0].to_source_string(), "value");
                    }
                    _ => panic!("Expected inner call, got {:?}", args[0]),
                }
            }
            _ => panic!("Expected Call for nested call, got {:?}", assign.value),
        }
    } else {
        panic!("Expected assignment with call");
    }
}

#[test]
fn test_ast_multiline_call() {
    let code = "db.query(\n    \"SELECT * FROM users\",\n    user_id\n)\n";
    let node = parse_file("query.py", code).expect("Failed to parse multiline call");
    assert!(
        !node.statements.is_empty(),
        "Statements should not be empty for multiline call"
    );
    match &node.statements[0] {
        StmtNode::Call(ExprNode::Call { callee, args, .. }) => {
            assert_eq!(callee.to_source_string(), "db.query");
            assert_eq!(args.len(), 2, "Multiline call should parse 2 arguments");
        }
        _ => panic!(
            "Expected Call statement for multiline call, got {:?}",
            node.statements[0]
        ),
    }
}

#[test]
fn test_ast_complex_assignment() {
    let code = "data = client.get_service().fetch_records(limit=10).data\n";
    let node = parse_file("assign.py", code).expect("Failed to parse complex assignment");
    assert!(!node.statements.is_empty());
    if let StmtNode::Assignment(assign) = &node.statements[0] {
        assert_eq!(assign.target.to_source_string(), "data");
        assert!(assign
            .value
            .to_source_string()
            .contains("client.get_service"));
    } else {
        panic!("Expected assignment");
    }
}

#[test]
fn test_ast_ruby_parsing() {
    let code = r#"
require 'digest'

class UserService < BaseService
  def authenticate(username, password)
    hashed = Digest::SHA256.hexdigest(password)
    return hashed
  end
end
"#;
    let node = parse_file("service.rb", code).expect("Failed to parse Ruby code");
    assert_eq!(node.language, "ruby");
    assert_eq!(node.imports.len(), 1);
    assert_eq!(node.imports[0].module, "digest");
    assert_eq!(node.classes.len(), 1);
    assert_eq!(node.classes[0].name, "UserService");
    assert_eq!(node.classes[0].base_classes, vec!["BaseService"]);
    assert_eq!(node.functions.len(), 1);
    assert_eq!(node.functions[0].name, "authenticate");
    assert_eq!(node.functions[0].params, vec!["username", "password"]);
}

#[test]
fn test_ast_php_parsing() {
    let code = r#"<?php
use App\Models\User;

class UserController extends Controller {
    public function show($id, $format) {
        $user = User::find($id);
        return $user;
    }
}
"#;
    let node = parse_file("UserController.php", code).expect("Failed to parse PHP code");
    assert_eq!(node.language, "php");
    assert_eq!(node.imports.len(), 1);
    assert_eq!(node.imports[0].module, "App\\Models\\User");
    assert_eq!(node.classes.len(), 1);
    assert_eq!(node.classes[0].name, "UserController");
    assert_eq!(node.classes[0].base_classes, vec!["Controller"]);
    assert_eq!(node.functions.len(), 1);
    assert_eq!(node.functions[0].name, "show");
    assert_eq!(node.functions[0].params, vec!["$id", "$format"]);
}
