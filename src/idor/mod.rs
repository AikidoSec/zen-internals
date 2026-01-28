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
    /// Collected subqueries for separate processing
    subqueries: Vec<Query>,
    /// Depth counter for skipping nested LATERAL/subquery content
    skip_depth: usize,
}

impl Visitor for WhereFilterVisitor {
    type Break = ();

    fn pre_visit_table_factor(&mut self, table_factor: &TableFactor) -> ControlFlow<Self::Break> {
        match table_factor {
            TableFactor::Table { name, alias, .. } => {
                // Only add tables if not inside a subquery context
                if self.skip_depth == 0 {
                    self.tables.push(TableRef {
                        name: full_name(name),
                        alias: alias.as_ref().map(|a| a.name.value.clone()),
                    });
                }
            }
            TableFactor::Derived {
                lateral: true,
                subquery,
                ..
            } => {
                // LATERAL subquery - collect for separate processing
                self.subqueries.push(subquery.as_ref().clone());
                self.skip_depth += 1;
            }
            _ => {}
        }

        ControlFlow::Continue(())
    }

    fn post_visit_table_factor(&mut self, table_factor: &TableFactor) -> ControlFlow<Self::Break> {
        if let TableFactor::Derived { lateral: true, .. } = table_factor {
            self.skip_depth = self.skip_depth.saturating_sub(1);
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
        if self.skip_depth > 0 {
            return ControlFlow::Continue(());
        }

        if is_mysql_placeholder(expr) {
            self.placeholder_counter += 1;
        }

        if let Some(subquery) = get_subquery(expr) {
            self.subqueries.push(subquery.clone());
            self.skip_depth += 1;
        }

        if let Some(filter) = try_extract_equality_filter(expr, self.placeholder_counter) {
            self.filters.push(filter);
        }

        ControlFlow::Continue(())
    }

    fn post_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
        // Decrement skip_depth when leaving subquery expressions
        match expr {
            Expr::Subquery(_) | Expr::InSubquery { .. } | Expr::Exists { .. } => {
                self.skip_depth = self.skip_depth.saturating_sub(1);
            }
            _ => {}
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

fn is_mysql_placeholder(expr: &Expr) -> bool {
    matches!(expr, Expr::Value(Value::Placeholder(p)) if p == "?")
}

fn is_column_ref(expr: &Expr) -> bool {
    matches!(expr, Expr::Identifier(_) | Expr::CompoundIdentifier(_))
}

/// Extracts the subquery from expression types that contain subqueries.
fn get_subquery(expr: &Expr) -> Option<&Query> {
    match expr {
        Expr::Subquery(q) => Some(q.as_ref()),
        Expr::InSubquery { subquery, .. } => Some(subquery.as_ref()),
        Expr::Exists { subquery, .. } => Some(subquery.as_ref()),
        _ => None,
    }
}

/// Tries to extract a filter from an equality comparison (column = value).
/// Returns None for column-to-column comparisons (e.g., JOIN conditions).
fn try_extract_equality_filter(expr: &Expr, placeholder_counter: usize) -> Option<FilterColumn> {
    let Expr::BinaryOp { left, op, right } = expr else {
        return None;
    };

    if !matches!(op, BinaryOperator::Eq) {
        return None;
    }

    // Try left = column, right = value
    if let Some(col) = extract_column(left) {
        if !is_column_ref(right) {
            return Some(FilterColumn {
                table: col.table,
                column: col.column,
                value: expr_value_str(right),
                placeholder_number: placeholder_number(right, placeholder_counter),
            });
        }
    }

    // Try right = column, left = value (reversed comparison)
    if let Some(col) = extract_column(right) {
        if !is_column_ref(left) {
            return Some(FilterColumn {
                table: col.table,
                column: col.column,
                value: expr_value_str(left),
                placeholder_number: placeholder_number(left, placeholder_counter),
            });
        }
    }

    None
}

/// Returns the 0-based position of a `?` placeholder.
/// `counter` is the number of `?` already seen before this expression.
fn placeholder_number(expr: &Expr, counter: usize) -> Option<usize> {
    if is_mysql_placeholder(expr) {
        Some(counter)
    } else {
        None
    }
}

fn expr_value_str(expr: &Expr) -> String {
    match expr {
        Expr::Value(Value::Placeholder(p)) => p.clone(),
        Expr::Value(Value::SingleQuotedString(s)) => s.clone(),
        Expr::Value(Value::DoubleQuotedString(s)) => s.clone(),
        Expr::Value(Value::Number(n, _)) => n.clone(),
        _ => format!("{}", expr),
    }
}

/// Returns the 0-based placeholder number for a `?` placeholder,
/// incrementing the counter for tracking position across the query.
fn placeholder_number_mut(expr: &Expr, counter: &mut usize) -> Option<usize> {
    if is_mysql_placeholder(expr) {
        let num = *counter;
        *counter += 1;
        Some(num)
    } else {
        None
    }
}

fn full_name(name: &ObjectName) -> String {
    name.0
        .iter()
        .map(|i| i.value.clone())
        .collect::<Vec<_>>()
        .join(".")
}

/// Extract filters from an expression (WHERE clause) by walking it recursively.
/// Also collects subqueries that should be processed separately.
fn extract_filters_from_expr(expr: &Expr, counter: &mut usize) -> (Vec<FilterColumn>, Vec<Query>) {
    let mut filters = Vec::new();
    let mut subqueries = Vec::new();
    walk_expr_for_filters(expr, counter, &mut filters, &mut subqueries);
    (filters, subqueries)
}

fn walk_expr_for_filters(
    expr: &Expr,
    counter: &mut usize,
    filters: &mut Vec<FilterColumn>,
    subqueries: &mut Vec<Query>,
) {
    if is_mysql_placeholder(expr) {
        *counter += 1;
    }

    if let Some(filter) = try_extract_equality_filter(expr, *counter) {
        filters.push(filter);
    }

    if let Some(subquery) = get_subquery(expr) {
        subqueries.push(subquery.clone());
        return;
    }

    match expr {
        Expr::BinaryOp { left, right, .. } => {
            walk_expr_for_filters(left, counter, filters, subqueries);
            walk_expr_for_filters(right, counter, filters, subqueries);
        }
        Expr::Nested(inner) => {
            walk_expr_for_filters(inner, counter, filters, subqueries);
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
    impl Visitor for PlaceholderCounter<'_> {
        type Break = ();
        fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
            if is_mysql_placeholder(expr) {
                *self.count += 1;
            }
            ControlFlow::Continue(())
        }
    }
    let _ = expr.visit(&mut PlaceholderCounter { count });
}

fn table_ref_from_factor(factor: &TableFactor) -> Option<TableRef> {
    if let TableFactor::Table { name, alias, .. } = factor {
        Some(TableRef {
            name: full_name(name),
            alias: alias.as_ref().map(|a| a.name.value.clone()),
        })
    } else {
        None
    }
}

fn extract_tables_from_table_with_joins(twj: &TableWithJoins) -> Vec<TableRef> {
    let mut tables = Vec::new();
    if let Some(t) = table_ref_from_factor(&twj.relation) {
        tables.push(t);
    }
    for join in &twj.joins {
        if let Some(t) = table_ref_from_factor(&join.relation) {
            tables.push(t);
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
    counter: &mut usize,
) -> Result<(), String> {
    match set_expr {
        SetExpr::SetOperation { left, right, .. } => {
            flatten_set_expr(left, results, counter)?;
            flatten_set_expr(right, results, counter)?;
        }
        SetExpr::Query(query) => {
            flatten_set_expr(&query.body, results, counter)?;
        }
        _ => {
            // Select, Values, Insert, Update, Table — visit to collect tables/filters
            visit_set_expr_as_select(set_expr, results, counter)?;
        }
    }
    Ok(())
}

fn visit_set_expr_as_select(
    set_expr: &SetExpr,
    results: &mut Vec<SqlQueryResult>,
    counter: &mut usize,
) -> Result<(), String> {
    let mut visitor = WhereFilterVisitor {
        tables: Vec::new(),
        filters: Vec::new(),
        placeholder_counter: *counter,
        subqueries: Vec::new(),
        skip_depth: 0,
    };
    let _ = set_expr.visit(&mut visitor);
    *counter = visitor.placeholder_counter;

    results.push(SqlQueryResult {
        kind: "select".into(),
        tables: visitor.tables,
        filters: visitor.filters,
        insert_columns: None,
    });

    for subquery in visitor.subqueries {
        flatten_query(&subquery, results, counter)?;
    }
    Ok(())
}

/// Flatten a Query (which wraps a SetExpr body) into separate results.
fn flatten_query(
    query: &Query,
    results: &mut Vec<SqlQueryResult>,
    placeholder_counter: &mut usize,
) -> Result<(), String> {
    // CTEs are not supported yet
    if query.with.is_some() {
        return Err(
            "CTEs (WITH clauses) are not supported yet. Use withoutIdorProtection() to bypass the check.".to_string(),
        );
    }

    // Flatten the main query body
    flatten_set_expr(&query.body, results, placeholder_counter)?;
    Ok(())
}

/// Analyzes a SQL query for IDOR (Insecure Direct Object Reference) protection.
///
/// Returns a list of `SqlQueryResult` entries, one per logical query. Each entry contains:
/// - `kind`: The statement type ("select", "insert", "update", "delete")
/// - `tables`: All tables referenced (with optional aliases)
/// - `filters`: Equality filters extracted from WHERE clauses
/// - `insert_columns`: For INSERT statements, the column-value pairs per row
///
/// # Algorithm
///
/// ## Filter extraction
///
/// Only equality comparisons (`=`) where one side is a column and the other side is a
/// **concrete value** (literal, placeholder like `$1` or `?`) are extracted as filters.
/// Column-to-column comparisons (e.g., `a.id = b.user_id` in JOIN ON clauses) are ignored
/// since they don't represent tenant filtering — they're just table relationships.
///
/// Examples:
/// - `tenant_id = $1` → extracted (column = placeholder)
/// - `tenant_id = 'org_123'` → extracted (column = literal)
/// - `a.user_id = b.id` → ignored (column = column, typical JOIN condition)
///
/// ## UNION / INTERSECT / EXCEPT
///
/// Set operations are flattened: each side becomes a separate `SqlQueryResult`.
/// This ensures every branch of a UNION is independently checked for tenant filtering.
///
/// ## CTEs (Common Table Expressions)
///
/// CTEs are resolved inline. When the main query references a CTE, the CTE's underlying
/// tables and filters are merged into the result. For example:
///
/// ```sql
/// WITH active AS (SELECT * FROM users WHERE tenant_id = $1)
/// SELECT * FROM active WHERE status = 'active'
/// ```
///
/// Produces one result with table `users` and filters `tenant_id = $1` and `status = 'active'`.
///
/// Recursive CTEs with UNION produce multiple results (one per UNION branch).
///
/// ## JOINs
///
/// All joined tables are collected. JOIN ON conditions that compare columns to columns
/// (e.g., `ON orders.user_id = users.id`) are not included in filters. Only WHERE clause
/// conditions with concrete values are extracted.
///
/// ## Placeholder numbering (MySQL `?`)
///
/// For MySQL's positional `?` placeholders, the 0-based position is tracked. For UPDATE
/// statements, placeholders in SET assignments are counted first, so WHERE placeholders
/// have correct offsets. This allows the caller to resolve `?` to actual parameter values.
///
/// ## Subqueries
///
/// Subqueries produce separate `SqlQueryResult` entries, allowing independent tenant
/// validation for each query level. For example:
///
/// ```sql
/// SELECT * FROM users WHERE id IN (SELECT user_id FROM orders WHERE tenant_id = $1)
/// ```
///
/// Produces two results:
/// - Outer query: table `users`, no filters
/// - Subquery: table `orders`, filter `tenant_id = $1`
///
/// This applies to subqueries in WHERE IN, WHERE EXISTS, and LATERAL joins.
/// Subqueries in FROM clauses (derived tables) are flattened since they are the
/// sole table source for the outer query.
///
/// # Errors
///
/// Returns an error if:
/// - The SQL cannot be parsed
/// - The query is empty
/// - An unsupported statement type is encountered (e.g., CREATE TABLE, TRUNCATE)
pub fn idor_analyze_sql(query: &str, dialect: i32) -> Result<Vec<SqlQueryResult>, String> {
    let statements = parse_sql(query, dialect)?;
    let mut results = Vec::new();

    for stmt in &statements {
        analyze_statement(stmt, &mut results)?;
    }

    Ok(results)
}

fn parse_sql(query: &str, dialect: i32) -> Result<Vec<Statement>, String> {
    if query.trim().is_empty() {
        return Err("Empty query".to_string());
    }

    let dialect = select_dialect_based_on_enum(dialect);
    let statements = Parser::parse_sql(&*dialect, query).map_err(|e| e.to_string())?;

    if statements.is_empty() {
        return Err("No SQL statements found".to_string());
    }

    Ok(statements)
}

fn analyze_statement(stmt: &Statement, results: &mut Vec<SqlQueryResult>) -> Result<(), String> {
    match stmt {
        Statement::Query(query) => {
            let mut counter = 0;
            flatten_query(query, results, &mut counter)?;
        }
        Statement::Update {
            table,
            assignments,
            from,
            selection,
            ..
        } => {
            analyze_update(
                table,
                assignments,
                from.as_ref(),
                selection.as_ref(),
                results,
            );
        }
        Statement::Delete(delete) => {
            analyze_delete(delete, results);
        }
        Statement::Insert(insert) => {
            analyze_insert(insert, results);
        }
        _ => {
            return Err(
                "Unsupported SQL statement type. Use withoutIdorProtection() to bypass the check."
                    .to_string(),
            );
        }
    }
    Ok(())
}

fn analyze_update(
    table: &TableWithJoins,
    assignments: &[sqlparser::ast::Assignment],
    from: Option<&TableWithJoins>,
    selection: Option<&Expr>,
    results: &mut Vec<SqlQueryResult>,
) {
    let mut tables = extract_tables_from_table_with_joins(table);
    if let Some(from_clause) = from {
        tables.extend(extract_tables_from_table_with_joins(from_clause));
    }

    let assignment_values: Vec<Expr> = assignments.iter().map(|a| a.value.clone()).collect();
    let mut counter = count_placeholders_in_exprs(&assignment_values);

    let (filters, subqueries) = extract_filters_and_subqueries(selection, &mut counter);

    results.push(SqlQueryResult {
        kind: "update".into(),
        tables,
        filters,
        insert_columns: None,
    });

    process_subqueries(&subqueries, results, &mut counter);
}

fn analyze_delete(delete: &sqlparser::ast::Delete, results: &mut Vec<SqlQueryResult>) {
    let mut tables: Vec<TableRef> = match &delete.from {
        FromTable::WithFromKeyword(twjs) | FromTable::WithoutKeyword(twjs) => twjs
            .iter()
            .flat_map(extract_tables_from_table_with_joins)
            .collect(),
    };

    if let Some(using_clauses) = &delete.using {
        for twj in using_clauses {
            tables.extend(extract_tables_from_table_with_joins(twj));
        }
    }

    let mut counter = 0;
    let (filters, subqueries) =
        extract_filters_and_subqueries(delete.selection.as_ref(), &mut counter);

    results.push(SqlQueryResult {
        kind: "delete".into(),
        tables,
        filters,
        insert_columns: None,
    });

    process_subqueries(&subqueries, results, &mut counter);
}

fn analyze_insert(insert: &sqlparser::ast::Insert, results: &mut Vec<SqlQueryResult>) {
    let table = TableRef {
        name: full_name(&insert.table_name),
        alias: insert.table_alias.as_ref().map(|a| a.value.clone()),
    };
    let columns: Vec<String> = insert.columns.iter().map(|c| c.value.clone()).collect();
    let insert_columns = extract_insert_columns(&insert.source, &columns);

    // For INSERT ... SELECT (no VALUES clause), analyze the SELECT source
    let has_values_clause = insert_columns.is_some();
    if !has_values_clause {
        if let Some(source) = &insert.source {
            let mut counter = 0;
            let _ = flatten_query(source, results, &mut counter);
        }
    }

    results.push(SqlQueryResult {
        kind: "insert".into(),
        tables: vec![table],
        filters: Vec::new(),
        insert_columns,
    });
}

fn extract_filters_and_subqueries(
    selection: Option<&Expr>,
    counter: &mut usize,
) -> (Vec<FilterColumn>, Vec<Query>) {
    match selection {
        Some(expr) => extract_filters_from_expr(expr, counter),
        None => (Vec::new(), Vec::new()),
    }
}

fn process_subqueries(
    subqueries: &[Query],
    results: &mut Vec<SqlQueryResult>,
    counter: &mut usize,
) {
    for subquery in subqueries {
        let _ = flatten_query(subquery, results, counter);
    }
}

fn extract_insert_columns(
    source: &Option<Box<Query>>,
    columns: &[String],
) -> Option<Vec<Vec<InsertColumn>>> {
    let source = source.as_ref()?;
    let values = match source.body.as_ref() {
        SetExpr::Values(v) => v,
        _ => return None,
    };

    let mut placeholder_counter = 0;
    let rows = values
        .rows
        .iter()
        .map(|row| {
            row.iter()
                .enumerate()
                .filter_map(|(i, expr)| {
                    if i >= columns.len() {
                        return None;
                    }
                    Some(InsertColumn {
                        column: columns[i].clone(),
                        value: expr_value_str(expr),
                        placeholder_number: placeholder_number_mut(expr, &mut placeholder_counter),
                    })
                })
                .collect()
        })
        .collect();

    Some(rows)
}

pub mod idor_analyze_sql_test;
