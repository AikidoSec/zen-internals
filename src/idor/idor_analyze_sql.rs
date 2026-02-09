use crate::idor::sql_query_result::{FilterColumn, InsertColumn, SqlQueryResult, TableRef};
use crate::sql_injection::helpers::select_dialect_based_on_enum::select_dialect_based_on_enum;
use core::ops::ControlFlow;
use sqlparser::ast::{
    BinaryOperator, Expr, FromTable, ObjectName, Query, SetExpr, Statement, TableFactor,
    TableWithJoins, Value, Visit, Visitor,
};
use sqlparser::parser::Parser;
use std::collections::HashSet;

/// Analyzes a SQL query for IDOR (Insecure Direct Object Reference) protection.
///
/// Returns a list of `SqlQueryResult` entries, one per logical query. Each entry contains:
/// - `kind`: The statement type ("select", "insert", "update", "delete")
/// - `tables`: All tables referenced (with optional aliases)
/// - `filters`: Equality filters extracted from WHERE clauses
/// - `insert_columns`: For INSERT statements, the column-value pairs per row
///
/// # Filter Extraction
///
/// Only equality comparisons (`=`) where one side is a column and the other is a
/// concrete value (literal or placeholder) are extracted. Column-to-column comparisons
/// (e.g., JOIN conditions like `a.id = b.user_id`) are ignored.
///
/// # UNION / INTERSECT / EXCEPT
///
/// These are flattened: each side becomes a separate result.
///
/// # Subqueries
///
/// Subqueries in WHERE IN, WHERE EXISTS, and LATERAL joins produce separate results.
///
/// # MySQL Placeholder Numbering
///
/// For MySQL's positional `?` placeholders, the 0-based position is tracked. For UPDATE
/// statements, placeholders in SET assignments are counted first, so WHERE placeholders
/// have correct offsets.
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
            analyze_query(query, results, &mut counter)?;
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
                &mut 0,
                &HashSet::new(),
            )?;
        }
        Statement::Delete(delete) => {
            analyze_delete(delete, results, &mut 0, &HashSet::new())?;
        }
        Statement::Insert(insert) => {
            analyze_insert(insert, results, &mut 0, &HashSet::new())?;
        }
        Statement::Commit { .. }
        | Statement::Rollback { .. }
        | Statement::StartTransaction { .. }
        | Statement::Savepoint { .. }
        | Statement::SetTransaction { .. }
        | Statement::ReleaseSavepoint { .. }
        | Statement::CreateTable { .. }
        | Statement::AlterTable { .. }
        | Statement::Drop { .. }
        | Statement::CreateIndex { .. }
        | Statement::CreateView { .. }
        | Statement::AlterView { .. }
        | Statement::CreateSchema { .. }
        | Statement::CreateDatabase { .. }
        | Statement::CreateFunction { .. }
        | Statement::CreateProcedure { .. }
        | Statement::CreateTrigger { .. }
        | Statement::CreateSequence { .. }
        | Statement::CreateExtension { .. }
        | Statement::DropFunction { .. }
        | Statement::DropProcedure { .. }
        | Statement::DropTrigger { .. }
        | Statement::Truncate { .. }
        | Statement::Grant { .. }
        | Statement::Revoke { .. }
        | Statement::SetVariable { .. }
        | Statement::SetNames { .. }
        | Statement::SetNamesDefault { .. }
        | Statement::SetTimeZone { .. }
        | Statement::SetRole { .. }
        | Statement::ShowVariable { .. }
        | Statement::ShowStatus { .. }
        | Statement::ShowVariables { .. }
        | Statement::ShowCreate { .. }
        | Statement::ShowColumns { .. }
        | Statement::ShowTables { .. }
        | Statement::ShowCollation { .. }
        | Statement::Use { .. }
        | Statement::ExplainTable { .. }
        | Statement::Explain { .. }
        | Statement::Fetch { .. }
        | Statement::Close { .. } => {}
        _ => {
            return Err(
                "Unsupported SQL statement type: only SELECT, INSERT, UPDATE, and DELETE are supported".to_string()
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
    counter: &mut usize,
    cte_names: &HashSet<String>,
) -> Result<(), String> {
    let mut tables = extract_tables_from_table_with_joins(table);
    if let Some(from_clause) = from {
        tables.extend(extract_tables_from_table_with_joins(from_clause));
    }

    // Filter out common table expression names
    tables.retain(|t| !cte_names.contains(&t.name.to_lowercase()));

    let assignment_exprs: Vec<&Expr> = assignments.iter().map(|a| &a.value).collect();
    let assignment_subqueries = extract_subqueries_from_exprs(&assignment_exprs);
    *counter += count_placeholders_in_exprs(&assignment_exprs);

    let (filters, subqueries) = match selection {
        Some(expr) => extract_filters_from_where(expr, counter),
        None => (Vec::new(), Vec::new()),
    };

    results.push(SqlQueryResult {
        kind: "update".into(),
        tables,
        filters,
        insert_columns: None,
    });

    for subquery in assignment_subqueries {
        analyze_query_with_ctes(&subquery, results, counter, cte_names)?;
    }

    for subquery in subqueries {
        analyze_query_with_ctes(&subquery, results, counter, cte_names)?;
    }

    Ok(())
}

fn analyze_delete(
    delete: &sqlparser::ast::Delete,
    results: &mut Vec<SqlQueryResult>,
    counter: &mut usize,
    cte_names: &HashSet<String>,
) -> Result<(), String> {
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

    // Filter out common table expression names
    tables.retain(|t| !cte_names.contains(&t.name.to_lowercase()));

    let (filters, subqueries) = match &delete.selection {
        Some(expr) => extract_filters_from_where(expr, counter),
        None => (Vec::new(), Vec::new()),
    };

    results.push(SqlQueryResult {
        kind: "delete".into(),
        tables,
        filters,
        insert_columns: None,
    });

    for subquery in subqueries {
        analyze_query_with_ctes(&subquery, results, counter, cte_names)?;
    }

    Ok(())
}

fn analyze_insert(
    insert: &sqlparser::ast::Insert,
    results: &mut Vec<SqlQueryResult>,
    counter: &mut usize,
    cte_names: &HashSet<String>,
) -> Result<(), String> {
    let table = TableRef {
        name: object_name_to_string(&insert.table_name),
        alias: insert.table_alias.as_ref().map(|a| a.value.clone()),
    };
    let columns: Vec<&str> = insert.columns.iter().map(|c| c.value.as_str()).collect();
    let insert_columns = extract_insert_columns(&insert.source, &columns);

    // For INSERT ... SELECT, analyze the SELECT source
    if insert_columns.is_none() {
        if let Some(source) = &insert.source {
            analyze_query_with_ctes(source, results, counter, cte_names)?;
        }
    }

    results.push(SqlQueryResult {
        kind: "insert".into(),
        tables: vec![table],
        filters: Vec::new(),
        insert_columns,
    });

    Ok(())
}

/// Analyzes a Query AST node, producing a SqlQueryResult for each query part.
///
/// Example: `SELECT * FROM users UNION SELECT * FROM admins`
/// produces two results (one for users, one for admins).
///
/// Example: `WITH active AS (SELECT * FROM users) SELECT * FROM active`
/// produces one result for users (the common table expression name "active" is excluded).
fn analyze_query(
    query: &Query,
    results: &mut Vec<SqlQueryResult>,
    counter: &mut usize,
) -> Result<(), String> {
    analyze_query_with_ctes(query, results, counter, &HashSet::new())
}

fn analyze_query_with_ctes(
    query: &Query,
    results: &mut Vec<SqlQueryResult>,
    counter: &mut usize,
    parent_cte_names: &HashSet<String>,
) -> Result<(), String> {
    let mut cte_names = parent_cte_names.clone();

    if let Some(with) = &query.with {
        // First pass: collect all names (needed when one references another)
        for cte in &with.cte_tables {
            cte_names.insert(cte.alias.name.value.to_lowercase());
        }

        // Second pass: analyze each common table expression's body
        for cte in &with.cte_tables {
            analyze_query_with_ctes(&cte.query, results, counter, &cte_names)?;
        }
    }

    analyze_set_expr(&query.body, results, counter, &cte_names)
}

fn analyze_set_expr(
    set_expr: &SetExpr,
    results: &mut Vec<SqlQueryResult>,
    counter: &mut usize,
    cte_names: &HashSet<String>,
) -> Result<(), String> {
    match set_expr {
        SetExpr::SetOperation { left, right, .. } => {
            analyze_set_expr(left, results, counter, cte_names)?;
            analyze_set_expr(right, results, counter, cte_names)?;
        }
        SetExpr::Query(query) => {
            // Nested query may have its own common table expressions
            analyze_query_with_ctes(query, results, counter, cte_names)?;
        }
        SetExpr::Update(stmt) => {
            if let Statement::Update {
                table,
                assignments,
                from,
                selection,
                ..
            } = stmt
            {
                analyze_update(
                    table,
                    assignments,
                    from.as_ref(),
                    selection.as_ref(),
                    results,
                    counter,
                    cte_names,
                )?;
            }
        }
        SetExpr::Insert(stmt) => {
            if let Statement::Insert(insert) = stmt {
                analyze_insert(insert, results, counter, cte_names)?;
            }
        }
        _ => {
            visit_select(set_expr, results, counter, cte_names)?;
        }
    }
    Ok(())
}

fn visit_select(
    set_expr: &SetExpr,
    results: &mut Vec<SqlQueryResult>,
    counter: &mut usize,
    cte_names: &HashSet<String>,
) -> Result<(), String> {
    let mut visitor = SelectVisitor::new(*counter, cte_names.clone());
    let _ = set_expr.visit(&mut visitor);
    *counter = visitor.placeholder_counter;

    results.push(SqlQueryResult {
        kind: "select".into(),
        tables: visitor.tables,
        filters: visitor.filters,
        insert_columns: None,
    });

    for subquery in visitor.subqueries {
        analyze_query_with_ctes(&subquery, results, counter, cte_names)?;
    }
    Ok(())
}

struct SelectVisitor {
    tables: Vec<TableRef>,
    filters: Vec<FilterColumn>,
    placeholder_counter: usize,
    subqueries: Vec<Query>,
    /// Tracks nesting depth inside subqueries. When > 0, we skip collecting tables/filters
    /// because the Visitor walks into subquery children automatically, but we want to
    /// process subqueries separately (they're stored in `subqueries` for later processing).
    /// Incremented when entering a subquery, decremented when leaving.
    skip_depth: usize,
    /// Common table expression names to skip when collecting tables (virtual tables, not real ones)
    cte_names: HashSet<String>,
}

impl SelectVisitor {
    fn new(initial_placeholder_count: usize, cte_names: HashSet<String>) -> Self {
        Self {
            tables: Vec::new(),
            filters: Vec::new(),
            placeholder_counter: initial_placeholder_count,
            subqueries: Vec::new(),
            skip_depth: 0,
            cte_names,
        }
    }
}

impl Visitor for SelectVisitor {
    type Break = ();

    fn pre_visit_table_factor(&mut self, table_factor: &TableFactor) -> ControlFlow<Self::Break> {
        match table_factor {
            TableFactor::Table { name, alias, .. } if self.skip_depth == 0 => {
                let table_name = object_name_to_string(name);
                // Skip common table expression references (virtual tables, not real ones)
                if !self.cte_names.contains(&table_name.to_lowercase()) {
                    self.tables.push(TableRef {
                        name: table_name,
                        alias: alias.as_ref().map(|a| a.name.value.clone()),
                    });
                }
            }
            TableFactor::Derived {
                lateral: true,
                subquery,
                ..
            } => {
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

        if let Some(subquery) = extract_subquery(expr) {
            self.subqueries.push(subquery.clone());
            self.skip_depth += 1;
        }

        if let Some(filter) = try_extract_filter(expr, self.placeholder_counter) {
            self.filters.push(filter);
        }

        ControlFlow::Continue(())
    }

    fn post_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
        if extract_subquery(expr).is_some() {
            self.skip_depth = self.skip_depth.saturating_sub(1);
        }
        ControlFlow::Continue(())
    }
}

fn is_mysql_placeholder(expr: &Expr) -> bool {
    matches!(expr, Expr::Value(Value::Placeholder(p)) if p == "?")
}

fn extract_subquery(expr: &Expr) -> Option<&Query> {
    match expr {
        Expr::Subquery(q) => Some(q.as_ref()),
        Expr::InSubquery { subquery, .. } => Some(subquery.as_ref()),
        Expr::Exists { subquery, .. } => Some(subquery.as_ref()),
        _ => None,
    }
}

fn try_extract_filter(expr: &Expr, placeholder_counter: usize) -> Option<FilterColumn> {
    let Expr::BinaryOp { left, op, right } = expr else {
        return None;
    };

    if *op != BinaryOperator::Eq {
        return None;
    }

    extract_column_value_pair(left, right, placeholder_counter)
        .or_else(|| extract_column_value_pair(right, left, placeholder_counter))
}

fn extract_column_value_pair(
    maybe_column: &Expr,
    maybe_value: &Expr,
    placeholder_counter: usize,
) -> Option<FilterColumn> {
    let (table, column) = extract_column_ref(maybe_column)?;

    if is_column_ref(maybe_value) {
        return None;
    }

    let placeholder_number = if is_mysql_placeholder(maybe_value) {
        Some(placeholder_counter)
    } else {
        None
    };

    Some(FilterColumn {
        table,
        column,
        value: expr_to_value_string(maybe_value),
        placeholder_number,
    })
}

fn extract_column_ref(expr: &Expr) -> Option<(Option<String>, String)> {
    match expr {
        Expr::Identifier(ident) => Some((None, ident.value.clone())),
        Expr::CompoundIdentifier(parts) if parts.len() >= 2 => {
            let table = parts[parts.len() - 2].value.clone();
            let column = parts[parts.len() - 1].value.clone();
            Some((Some(table), column))
        }
        _ => None,
    }
}

fn is_column_ref(expr: &Expr) -> bool {
    matches!(expr, Expr::Identifier(_) | Expr::CompoundIdentifier(_))
}

fn expr_to_value_string(expr: &Expr) -> String {
    match expr {
        Expr::Value(Value::Placeholder(p)) => p.clone(),
        Expr::Value(Value::SingleQuotedString(s)) => s.clone(),
        Expr::Value(Value::DoubleQuotedString(s)) => s.clone(),
        Expr::Value(Value::Number(n, _)) => n.clone(),
        Expr::Value(Value::EscapedStringLiteral(s)) => s.clone(),
        Expr::Value(Value::DollarQuotedString(dqs)) => dqs.value.clone(),
        Expr::Value(Value::NationalStringLiteral(s)) => s.clone(),
        _ => format!("{}", expr),
    }
}

fn object_name_to_string(name: &ObjectName) -> String {
    name.0
        .iter()
        .map(|i| i.value.as_str())
        .collect::<Vec<_>>()
        .join(".")
}

fn extract_filters_from_where(expr: &Expr, counter: &mut usize) -> (Vec<FilterColumn>, Vec<Query>) {
    let mut filters = Vec::new();
    let mut subqueries = Vec::new();
    walk_expr(expr, counter, &mut filters, &mut subqueries);
    (filters, subqueries)
}

fn walk_expr(
    expr: &Expr,
    counter: &mut usize,
    filters: &mut Vec<FilterColumn>,
    subqueries: &mut Vec<Query>,
) {
    if is_mysql_placeholder(expr) {
        *counter += 1;
    }

    if let Some(filter) = try_extract_filter(expr, *counter) {
        filters.push(filter);
    }

    if let Some(subquery) = extract_subquery(expr) {
        subqueries.push(subquery.clone());
        return;
    }

    match expr {
        Expr::BinaryOp { left, right, .. } => {
            walk_expr(left, counter, filters, subqueries);
            walk_expr(right, counter, filters, subqueries);
        }
        Expr::Nested(inner) => {
            walk_expr(inner, counter, filters, subqueries);
        }
        _ => {}
    }
}

fn extract_subqueries_from_exprs(exprs: &[&Expr]) -> Vec<Query> {
    let mut subqueries = Vec::new();
    for expr in exprs {
        if let Some(subquery) = extract_subquery(expr) {
            subqueries.push(subquery.clone());
        }
    }
    subqueries
}

fn count_placeholders_in_exprs(exprs: &[&Expr]) -> usize {
    let mut count = 0;
    for expr in exprs {
        count_placeholders(expr, &mut count);
    }
    count
}

fn count_placeholders(expr: &Expr, count: &mut usize) {
    struct Counter<'a> {
        count: &'a mut usize,
    }
    impl Visitor for Counter<'_> {
        type Break = ();
        fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
            if is_mysql_placeholder(expr) {
                *self.count += 1;
            }
            ControlFlow::Continue(())
        }
    }
    let _ = expr.visit(&mut Counter { count });
}

fn table_ref_from_factor(factor: &TableFactor) -> Option<TableRef> {
    if let TableFactor::Table { name, alias, .. } = factor {
        Some(TableRef {
            name: object_name_to_string(name),
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

fn extract_insert_columns(
    source: &Option<Box<Query>>,
    columns: &[&str],
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

                    let placeholder_number = if is_mysql_placeholder(expr) {
                        let num = placeholder_counter;
                        placeholder_counter += 1;
                        Some(num)
                    } else {
                        None
                    };

                    Some(InsertColumn {
                        column: columns[i].to_string(),
                        value: expr_to_value_string(expr),
                        placeholder_number,
                    })
                })
                .collect()
        })
        .collect();

    Some(rows)
}
