use core::ops::ControlFlow;
use serde::Serialize;
use sqlparser::ast::{
    BinaryOperator, Expr, FromTable, ObjectName, Query, SetExpr, Statement, TableFactor,
    TableWithJoins, Value, Visit, Visitor,
};
use sqlparser::parser::Parser;

use crate::sql_injection::helpers::select_dialect_based_on_enum::select_dialect_based_on_enum;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TableRef {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FilterColumn {
    /// Table name or alias (if qualified, e.g. `u.tenant_id`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    pub column: String,
    pub value: String,
    /// 0-based position of a `?` placeholder in the query (MySQL-style).
    /// Used to resolve the placeholder to the actual parameter value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholder_number: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InsertColumn {
    pub column: String,
    pub value: String,
    /// 0-based position of a `?` placeholder in the query (MySQL-style).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholder_number: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SqlQueryResult {
    pub kind: String,
    pub tables: Vec<TableRef>,
    pub filters: Vec<FilterColumn>,
    /// For INSERT statements: column-value pairs for each row.
    /// Each inner Vec represents one row of inserted values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insert_columns: Option<Vec<Vec<InsertColumn>>>,
}

/// Visitor that collects tables and WHERE clause filters from a SQL subtree.
/// Used for SELECT queries where all BinaryOps are in WHERE/JOIN ON clauses.
struct WhereFilterVisitor {
    tables: Vec<TableRef>,
    filters: Vec<FilterColumn>,
    /// Counts `?` placeholders in visit order (matches SQL text order)
    placeholder_counter: usize,
}

impl Visitor for WhereFilterVisitor {
    type Break = ();

    fn pre_visit_table_factor(&mut self, table_factor: &TableFactor) -> ControlFlow<Self::Break> {
        if let TableFactor::Table { name, alias, .. } = table_factor {
            self.tables.push(TableRef {
                name: full_name(name),
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
            if is_eq_op(op) {
                // Try left = column, right = value
                if let Some(col) = extract_column(left) {
                    let placeholder_number = placeholder_number(right, self.placeholder_counter);
                    self.filters.push(FilterColumn {
                        table: col.table,
                        column: col.column,
                        value: expr_value_str(right),
                        placeholder_number,
                    });
                } else if let Some(col) = extract_column(right) {
                    // Try right = column, left = value (reversed)
                    let placeholder_number = placeholder_number(left, self.placeholder_counter);
                    self.filters.push(FilterColumn {
                        table: col.table,
                        column: col.column,
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

/// Returns the 0-based placeholder number for a `?` placeholder in an expression,
/// using a mutable counter that tracks position across the entire query.
fn expr_placeholder_number(expr: &Expr, counter: &mut usize) -> Option<usize> {
    match expr {
        Expr::Value(Value::Placeholder(p)) if p == "?" => {
            let num = *counter;
            *counter += 1;
            Some(num)
        }
        _ => None,
    }
}

fn is_eq_op(op: &BinaryOperator) -> bool {
    matches!(op, BinaryOperator::Eq)
}

fn full_name(name: &ObjectName) -> String {
    name.0
        .iter()
        .map(|i| i.value.clone())
        .collect::<Vec<_>>()
        .join(".")
}

/// Extract filters from an expression (WHERE clause) by walking it recursively.
fn extract_filters_from_expr(expr: &Expr, counter: &mut usize) -> Vec<FilterColumn> {
    let mut filters = Vec::new();
    walk_expr_for_filters(expr, counter, &mut filters);
    filters
}

fn walk_expr_for_filters(expr: &Expr, counter: &mut usize, filters: &mut Vec<FilterColumn>) {
    // Count ? placeholders
    if matches!(expr, Expr::Value(Value::Placeholder(p)) if p == "?") {
        *counter += 1;
    }

    match expr {
        Expr::BinaryOp { left, op, right } => {
            if is_eq_op(op) {
                if let Some(col) = extract_column(left) {
                    let pn = placeholder_number(right, *counter);
                    filters.push(FilterColumn {
                        table: col.table,
                        column: col.column,
                        value: expr_value_str(right),
                        placeholder_number: pn,
                    });
                } else if let Some(col) = extract_column(right) {
                    let pn = placeholder_number(left, *counter);
                    filters.push(FilterColumn {
                        table: col.table,
                        column: col.column,
                        value: expr_value_str(left),
                        placeholder_number: pn,
                    });
                }
            }
            // Recurse into both sides (for AND/OR chains)
            walk_expr_for_filters(left, counter, filters);
            walk_expr_for_filters(right, counter, filters);
        }
        Expr::Nested(inner) => {
            walk_expr_for_filters(inner, counter, filters);
        }
        _ => {}
    }
}

/// Count `?` placeholders in a list of expressions (e.g. SET assignment values).
fn count_placeholders_in_exprs(exprs: &[Expr]) -> usize {
    let mut count = 0;
    for expr in exprs {
        count_placeholders_in_expr(expr, &mut count);
    }
    count
}

fn count_placeholders_in_expr(expr: &Expr, count: &mut usize) {
    struct PlaceholderCounter<'a> {
        count: &'a mut usize,
    }
    impl<'a> Visitor for PlaceholderCounter<'a> {
        type Break = ();
        fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
            if matches!(expr, Expr::Value(Value::Placeholder(p)) if p == "?") {
                *self.count += 1;
            }
            ControlFlow::Continue(())
        }
    }
    let mut visitor = PlaceholderCounter { count };
    let _ = expr.visit(&mut visitor);
}

/// Extract table references from a TableWithJoins.
fn extract_tables_from_table_with_joins(twj: &TableWithJoins) -> Vec<TableRef> {
    let mut tables = Vec::new();
    if let TableFactor::Table { name, alias, .. } = &twj.relation {
        tables.push(TableRef {
            name: full_name(name),
            alias: alias.as_ref().map(|a| a.name.value.clone()),
        });
    }
    for join in &twj.joins {
        if let TableFactor::Table { name, alias, .. } = &join.relation {
            tables.push(TableRef {
                name: full_name(name),
                alias: alias.as_ref().map(|a| a.name.value.clone()),
            });
        }
    }
    tables
}

/// Recursively flatten a SetExpr into separate SqlQueryResult entries.
/// Each leaf SELECT becomes its own entry; SetOperation (UNION/EXCEPT/INTERSECT)
/// branches are split so that each side is analyzed independently.
fn flatten_set_expr(
    set_expr: &SetExpr,
    results: &mut Vec<SqlQueryResult>,
    placeholder_counter: &mut usize,
) {
    match set_expr {
        SetExpr::Select(_) => {
            let mut visitor = WhereFilterVisitor {
                tables: Vec::new(),
                filters: Vec::new(),
                placeholder_counter: *placeholder_counter,
            };
            let _ = set_expr.visit(&mut visitor);
            *placeholder_counter = visitor.placeholder_counter;
            results.push(SqlQueryResult {
                kind: "select".into(),
                tables: visitor.tables,
                filters: visitor.filters,
                insert_columns: None,
            });
        }
        SetExpr::SetOperation { left, right, .. } => {
            flatten_set_expr(left, results, placeholder_counter);
            flatten_set_expr(right, results, placeholder_counter);
        }
        SetExpr::Query(query) => {
            flatten_set_expr(&query.body, results, placeholder_counter);
        }
        _ => {
            // Values, Insert, Update, Table — use visitor as fallback
            let mut visitor = WhereFilterVisitor {
                tables: Vec::new(),
                filters: Vec::new(),
                placeholder_counter: *placeholder_counter,
            };
            let _ = set_expr.visit(&mut visitor);
            *placeholder_counter = visitor.placeholder_counter;
            results.push(SqlQueryResult {
                kind: "select".into(),
                tables: visitor.tables,
                filters: visitor.filters,
                insert_columns: None,
            });
        }
    }
}

/// Flatten a Query (which wraps a SetExpr body) into separate results.
/// If the query has CTEs (WITH clause), their bodies are resolved inline:
/// any table reference in the main query that matches a CTE name is replaced
/// with the actual tables and filters from that CTE.
fn flatten_query(
    query: &Query,
    results: &mut Vec<SqlQueryResult>,
    placeholder_counter: &mut usize,
) {
    // Build CTE map: name -> Vec<SqlQueryResult>
    let mut cte_map: Vec<(String, Vec<SqlQueryResult>)> = Vec::new();
    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            let cte_name = cte.alias.name.value.clone();
            let mut cte_results = Vec::new();
            flatten_query(&cte.query, &mut cte_results, placeholder_counter);
            cte_map.push((cte_name, cte_results));
        }
    }

    // Flatten the main query body
    let mut main_results = Vec::new();
    flatten_set_expr(&query.body, &mut main_results, placeholder_counter);

    if cte_map.is_empty() {
        results.extend(main_results);
        return;
    }

    // Resolve CTE references in main query results
    for mut result in main_results {
        let mut resolved_tables: Vec<TableRef> = Vec::new();
        let mut prepend_filters: Vec<FilterColumn> = Vec::new();
        let mut had_multi_result_cte = false;

        for table in &result.tables {
            // Check if this table name matches a CTE (use alias if present, else name)
            let lookup_name = &table.name;
            if let Some((_cte_name, cte_results)) =
                cte_map.iter().find(|(name, _)| name == lookup_name)
            {
                if cte_results.len() == 1 {
                    // Single-result CTE: merge tables and filters inline
                    resolved_tables.extend(cte_results[0].tables.clone());
                    prepend_filters.extend(cte_results[0].filters.clone());
                } else {
                    // Multi-result CTE (e.g. UNION inside CTE): emit each result separately
                    for cte_result in cte_results {
                        results.push(cte_result.clone());
                    }
                    had_multi_result_cte = true;
                }
            } else {
                // Not a CTE reference, keep the table as-is
                resolved_tables.push(table.clone());
            }
        }

        if had_multi_result_cte && resolved_tables.is_empty() && result.filters.is_empty() {
            // The main query only referenced a multi-result CTE with no extra filters,
            // so we already emitted the CTE results above — skip the main result.
            continue;
        }

        result.tables = resolved_tables;
        let mut merged_filters = prepend_filters;
        merged_filters.extend(result.filters);
        result.filters = merged_filters;
        results.push(result);
    }
}

pub fn idor_analyze_sql(query: &str, dialect: i32) -> Result<Vec<SqlQueryResult>, String> {
    let dialect = select_dialect_based_on_enum(dialect);

    let statements = Parser::parse_sql(&*dialect, query).map_err(|e| e.to_string())?;

    let mut results = Vec::new();

    for stmt in &statements {
        match stmt {
            Statement::Query(query) => {
                let mut placeholder_counter = 0;
                flatten_query(query, &mut results, &mut placeholder_counter);
            }
            Statement::Update {
                table,
                from,
                selection,
                ..
            } => {
                let mut tables = extract_tables_from_table_with_joins(table);

                // Include tables from the FROM clause (e.g. PostgreSQL UPDATE ... FROM ...)
                if let Some(from_twj) = from {
                    tables.extend(extract_tables_from_table_with_joins(from_twj));
                }

                // Count placeholders in SET assignments so we offset correctly for WHERE
                let mut placeholder_counter = 0;
                if let Statement::Update { assignments, .. } = stmt {
                    let assignment_exprs: Vec<Expr> =
                        assignments.iter().map(|a| a.value.clone()).collect();
                    placeholder_counter = count_placeholders_in_exprs(&assignment_exprs);
                }

                // Extract filters only from the WHERE clause (not SET assignments)
                let filters = if let Some(selection) = selection {
                    extract_filters_from_expr(selection, &mut placeholder_counter)
                } else {
                    Vec::new()
                };

                results.push(SqlQueryResult {
                    kind: "update".into(),
                    tables,
                    filters,
                    insert_columns: None,
                });
            }
            Statement::Delete(delete) => {
                let mut tables = match &delete.from {
                    FromTable::WithFromKeyword(twjs) | FromTable::WithoutKeyword(twjs) => {
                        let mut tables = Vec::new();
                        for twj in twjs {
                            tables.extend(extract_tables_from_table_with_joins(twj));
                        }
                        tables
                    }
                };

                // Include tables from the USING clause (e.g. PostgreSQL DELETE ... USING ...)
                if let Some(using_twjs) = &delete.using {
                    for twj in using_twjs {
                        tables.extend(extract_tables_from_table_with_joins(twj));
                    }
                }

                let mut placeholder_counter = 0;
                let filters = if let Some(selection) = &delete.selection {
                    extract_filters_from_expr(selection, &mut placeholder_counter)
                } else {
                    Vec::new()
                };

                results.push(SqlQueryResult {
                    kind: "delete".into(),
                    tables,
                    filters,
                    insert_columns: None,
                });
            }
            Statement::Insert(insert) => {
                let table = TableRef {
                    name: full_name(&insert.table_name),
                    alias: insert.table_alias.as_ref().map(|a| a.value.clone()),
                };
                let tables = vec![table];

                let columns: Vec<String> = insert.columns.iter().map(|c| c.value.clone()).collect();

                // Extract insert column-value pairs from VALUES rows
                let insert_columns = if let Some(source) = &insert.source {
                    if let SetExpr::Values(values) = source.body.as_ref() {
                        let mut placeholder_counter = 0;
                        let mut all_rows = Vec::new();
                        for row in &values.rows {
                            let mut row_columns = Vec::new();
                            for (i, expr) in row.iter().enumerate() {
                                if i < columns.len() {
                                    let pn =
                                        expr_placeholder_number(expr, &mut placeholder_counter);
                                    row_columns.push(InsertColumn {
                                        column: columns[i].clone(),
                                        value: expr_value_str(expr),
                                        placeholder_number: pn,
                                    });
                                }
                            }
                            all_rows.push(row_columns);
                        }
                        Some(all_rows)
                    } else {
                        // INSERT ... SELECT — no insert_columns
                        None
                    }
                } else {
                    None
                };

                // For INSERT...SELECT, flatten the source query into separate
                // select results (handling UNION/EXCEPT/INTERSECT), then append
                // the insert entry.
                if insert_columns.is_none() {
                    if let Some(source) = &insert.source {
                        let mut placeholder_counter = 0;
                        flatten_query(source, &mut results, &mut placeholder_counter);
                    }
                }

                results.push(SqlQueryResult {
                    kind: "insert".into(),
                    tables,
                    filters: Vec::new(),
                    insert_columns,
                });
            }
            _ => {
                return Err(format!(
                    "Unsupported SQL statement type. Use withoutIdorProtection() to bypass the check."
                ));
            }
        }
    }

    Ok(results)
}

pub mod idor_analyze_sql_test;
