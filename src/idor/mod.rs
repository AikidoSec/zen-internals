use core::ops::ControlFlow;
use serde::Serialize;
use sqlparser::ast::{BinaryOperator, Expr, ObjectName, TableFactor, Value, Visit, Visitor};
use sqlparser::parser::Parser;

use crate::sql_injection::helpers::select_dialect_based_on_enum::select_dialect_based_on_enum;

#[derive(Debug, Clone, Serialize)]
pub struct TableRef {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FilterColumn {
    /// Table name or alias (if qualified, e.g. `u.tenant_id`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    pub column: String,
    pub operator: String,
    pub value: String,
    /// 0-based position of a `?` placeholder in the query (MySQL-style).
    /// Used to resolve the placeholder to the actual parameter value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholder_number: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct SelectQueryResult {
    pub tables: Vec<TableRef>,
    pub filters: Vec<FilterColumn>,
}

struct SelectVisitor {
    tables: Vec<TableRef>,
    filters: Vec<FilterColumn>,
    /// Counts `?` placeholders in visit order (matches SQL text order)
    placeholder_counter: usize,
}

impl Visitor for SelectVisitor {
    type Break = ();

    fn pre_visit_table_factor(&mut self, table_factor: &TableFactor) -> ControlFlow<Self::Break> {
        if let TableFactor::Table { name, alias, .. } = table_factor {
            self.tables.push(TableRef {
                name: last_ident(name),
                alias: alias.as_ref().map(|a| a.name.value.clone()),
            });
        }

        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
        // Count ? placeholders in visit order (left-to-right, matching SQL text order).
        // This runs for every expression node, but only Placeholder("?") increments.
        if matches!(expr, Expr::Value(Value::Placeholder(p)) if p == "?") {
            self.placeholder_counter += 1;
        }

        if let Expr::BinaryOp { left, op, right } = expr {
            if let Some(op_str) = binary_op_str(op) {
                // Try left = column, right = value
                if let Some(col) = extract_column(left) {
                    let placeholder_number = placeholder_number(right, self.placeholder_counter);
                    self.filters.push(FilterColumn {
                        table: col.table,
                        column: col.column,
                        operator: op_str.to_string(),
                        value: expr_value_str(right),
                        placeholder_number,
                    });
                } else if let Some(col) = extract_column(right) {
                    // Try right = column, left = value (reversed)
                    let placeholder_number = placeholder_number(left, self.placeholder_counter);
                    self.filters.push(FilterColumn {
                        table: col.table,
                        column: col.column,
                        operator: op_str.to_string(),
                        value: expr_value_str(left),
                        placeholder_number,
                    });
                }
            }
        }

        ControlFlow::Continue(())
    }
}

struct ColumnRef {
    table: Option<String>,
    column: String,
}

fn extract_column(expr: &Expr) -> Option<ColumnRef> {
    match expr {
        Expr::Identifier(ident) => Some(ColumnRef {
            table: None,
            column: ident.value.clone(),
        }),
        Expr::CompoundIdentifier(parts) if parts.len() >= 2 => Some(ColumnRef {
            table: Some(parts[parts.len() - 2].value.clone()),
            column: parts[parts.len() - 1].value.clone(),
        }),
        _ => None,
    }
}

/// Returns the 0-based position of a `?` placeholder.
/// `counter` is the number of `?` already seen before this expression.
/// Since the BinaryOp parent is visited before its children, the counter
/// at this point equals the 0-based index of this `?` in the query.
fn placeholder_number(expr: &Expr, counter: usize) -> Option<usize> {
    match expr {
        Expr::Value(Value::Placeholder(p)) if p == "?" => Some(counter),
        _ => None,
    }
}

fn expr_value_str(expr: &Expr) -> String {
    match expr {
        Expr::Value(Value::Placeholder(p)) => p.clone(),
        _ => format!("{}", expr),
    }
}

fn binary_op_str(op: &BinaryOperator) -> Option<&'static str> {
    match op {
        BinaryOperator::Eq => Some("="),
        BinaryOperator::NotEq => Some("!="),
        BinaryOperator::Gt => Some(">"),
        BinaryOperator::Lt => Some("<"),
        BinaryOperator::GtEq => Some(">="),
        BinaryOperator::LtEq => Some("<="),
        _ => None,
    }
}

fn last_ident(name: &ObjectName) -> String {
    name.0.last().map(|i| i.value.clone()).unwrap_or_default()
}

pub fn idor_analyze_sql(query: &str, dialect: i32) -> Result<Vec<SelectQueryResult>, String> {
    let dialect = select_dialect_based_on_enum(dialect);

    let statements = Parser::parse_sql(&*dialect, query).map_err(|e| e.to_string())?;

    let mut selects = Vec::new();

    for stmt in &statements {
        let mut visitor = SelectVisitor {
            tables: Vec::new(),
            filters: Vec::new(),
            placeholder_counter: 0,
        };

        let _ = stmt.visit(&mut visitor);

        selects.push(SelectQueryResult {
            tables: visitor.tables,
            filters: visitor.filters,
        });
    }

    Ok(selects)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_select() {
        let selects = idor_analyze_sql("SELECT * FROM users WHERE tenant_id = $1", 9).unwrap();
        assert_eq!(selects.len(), 1);
        assert_eq!(selects[0].tables[0].name, "users");
        assert_eq!(selects[0].filters[0].column, "tenant_id");
        assert_eq!(selects[0].filters[0].value, "$1");
        assert_eq!(selects[0].filters[0].operator, "=");
        assert_eq!(selects[0].filters[0].placeholder_number, None);
    }

    #[test]
    fn test_join() {
        let selects = idor_analyze_sql(
            "SELECT * FROM users u JOIN orders o ON o.user_id = u.id WHERE u.tenant_id = $1",
            9,
        )
        .unwrap();

        assert_eq!(selects[0].tables.len(), 2);
        assert_eq!(selects[0].tables[0].name, "users");
        assert_eq!(selects[0].tables[0].alias.as_deref(), Some("u"));
        assert_eq!(selects[0].tables[1].name, "orders");

        assert!(selects[0]
            .filters
            .iter()
            .any(|f| f.column == "tenant_id" && f.value == "$1"));
    }

    #[test]
    fn test_mysql_placeholder() {
        let selects = idor_analyze_sql("SELECT * FROM users WHERE tenant_id = ?", 8).unwrap();
        assert_eq!(selects[0].filters[0].value, "?");
        assert_eq!(selects[0].filters[0].placeholder_number, Some(0));
    }

    #[test]
    fn test_mysql_multiple_placeholders() {
        let selects = idor_analyze_sql(
            "SELECT * FROM users WHERE status = ? AND tenant_id = ? AND name = ?",
            8,
        )
        .unwrap();
        // status = ? is placeholder 0
        assert_eq!(selects[0].filters[0].column, "status");
        assert_eq!(selects[0].filters[0].placeholder_number, Some(0));
        // tenant_id = ? is placeholder 1
        assert_eq!(selects[0].filters[1].column, "tenant_id");
        assert_eq!(selects[0].filters[1].placeholder_number, Some(1));
        // name = ? is placeholder 2
        assert_eq!(selects[0].filters[2].column, "name");
        assert_eq!(selects[0].filters[2].placeholder_number, Some(2));
    }

    #[test]
    fn test_parse_error() {
        let result = idor_analyze_sql("NOT VALID SQL !!!", 9);
        assert!(result.is_err());
    }
}
