use crate::idor::sql_query_result::{FilterColumn, InsertColumn, SqlQueryResult, TableRef};
use crate::sql_injection::helpers::select_dialect_based_on_enum::select_dialect_based_on_enum;
use core::ops::ControlFlow;
use sqlparser::ast::{
    BinaryOperator, Expr, FromTable, FunctionArg, FunctionArgExpr, JoinConstraint, JoinOperator,
    ObjectName, ObjectNamePart, Query, SetExpr, Statement, TableFactor, TableObject,
    TableWithJoins, Value, ValueWithSpan, Visit, Visitor,
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
/// Equality comparisons (`=`) where one side is a column and the other is a concrete
/// value (literal or placeholder) are extracted directly.
///
/// Column-to-column comparisons in JOIN ON or WHERE clauses (e.g.
/// `r.sys_group_id = t.sys_group_id`) are also collected. After extraction, we
/// propagate known values through these pairs in a loop until no new filters can
/// be derived. This means JOIN chains like `a=b`, `b=c`, `c=$1` will resolve all
/// three columns to `$1`. We only create filters for tables that belong to the
/// current query, so subquery tables don't leak into the outer query.
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
        Statement::Update(update) => {
            analyze_update(
                &update.table,
                &update.assignments,
                update.from.as_ref(),
                update.selection.as_ref(),
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
        | Statement::Set(_)
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
        | Statement::Close { .. }
        | Statement::Analyze { .. } => {}
        _ => {
            return Err("Unrecognized SQL statement".to_string());
        }
    }
    Ok(())
}

fn analyze_update(
    table: &TableWithJoins,
    assignments: &[sqlparser::ast::Assignment],
    from: Option<&sqlparser::ast::UpdateTableFromKind>,
    selection: Option<&Expr>,
    results: &mut Vec<SqlQueryResult>,
    counter: &mut usize,
    cte_names: &HashSet<String>,
) -> Result<(), String> {
    let mut tables = extract_tables_from_table_with_joins(table);
    if let Some(from_kind) = from {
        let from_tables = match from_kind {
            sqlparser::ast::UpdateTableFromKind::BeforeSet(twjs)
            | sqlparser::ast::UpdateTableFromKind::AfterSet(twjs) => twjs,
        };
        for twj in from_tables {
            tables.extend(extract_tables_from_table_with_joins(twj));
        }
    }

    // Filter out common table expression names
    tables.retain(|t| !cte_names.contains(&t.name.to_lowercase()));

    let assignment_exprs: Vec<&Expr> = assignments.iter().map(|a| &a.value).collect();
    let assignment_subqueries = extract_subqueries_from_exprs(&assignment_exprs);
    *counter += count_placeholders_in_exprs(&assignment_exprs);

    let (mut filters, mut col_col_pairs, subqueries) = match selection {
        Some(expr) => extract_filters_from_where(expr, counter),
        None => (Vec::new(), Vec::new(), Vec::new()),
    };

    col_col_pairs.extend(collect_col_col_pairs_from_joins(std::slice::from_ref(
        table,
    )));
    if let Some(from_clause) = from {
        let from_tables = match from_clause {
            sqlparser::ast::UpdateTableFromKind::BeforeSet(twjs)
            | sqlparser::ast::UpdateTableFromKind::AfterSet(twjs) => twjs,
        };
        col_col_pairs.extend(collect_col_col_pairs_from_joins(from_tables));
    }

    if !col_col_pairs.is_empty() {
        let resolved = resolve_col_col_filters(&filters, &col_col_pairs, &tables);
        filters.extend(resolved);
    }

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

    let (mut filters, mut col_col_pairs, subqueries) = match &delete.selection {
        Some(expr) => extract_filters_from_where(expr, counter),
        None => (Vec::new(), Vec::new(), Vec::new()),
    };

    let from_twjs: &[TableWithJoins] = match &delete.from {
        FromTable::WithFromKeyword(twjs) | FromTable::WithoutKeyword(twjs) => twjs,
    };
    col_col_pairs.extend(collect_col_col_pairs_from_joins(from_twjs));
    if let Some(using_clauses) = &delete.using {
        col_col_pairs.extend(collect_col_col_pairs_from_joins(using_clauses));
    }

    if !col_col_pairs.is_empty() {
        let resolved = resolve_col_col_filters(&filters, &col_col_pairs, &tables);
        filters.extend(resolved);
    }

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
    let table_name = match &insert.table {
        TableObject::TableName(name) => object_name_to_string(name),
        TableObject::TableFunction(func) => format!("{}", func),
    };
    let table = TableRef {
        name: table_name,
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
            if let Statement::Update(update) = stmt {
                analyze_update(
                    &update.table,
                    &update.assignments,
                    update.from.as_ref(),
                    update.selection.as_ref(),
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

    let mut filters = visitor.filters;
    if visitor.potential_col_col {
        let col_col_pairs = collect_col_col_pairs_for_select(set_expr);
        if !col_col_pairs.is_empty() {
            let resolved = resolve_col_col_filters(&filters, &col_col_pairs, &visitor.tables);
            filters.extend(resolved);
        }
    }

    results.push(SqlQueryResult {
        kind: "select".into(),
        tables: visitor.tables,
        filters,
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
    /// Tracks nesting depth inside OR expressions. When > 0, we skip collecting filters
    /// because filters inside OR branches may not be applied (e.g. `WHERE tenant_id = 1 OR admin = true`
    /// does not guarantee that `tenant_id = 1` is enforced).
    or_depth: usize,
    /// Common table expression names to skip when collecting tables (virtual tables, not real ones)
    cte_names: HashSet<String>,
    /// Set to true when a col=col equality expression is encountered (e.g. `a.id = b.id`).
    /// Used to skip the col-col resolution pass entirely for queries that cannot have any.
    potential_col_col: bool,
}

impl SelectVisitor {
    fn new(initial_placeholder_count: usize, cte_names: HashSet<String>) -> Self {
        Self {
            tables: Vec::new(),
            filters: Vec::new(),
            placeholder_counter: initial_placeholder_count,
            subqueries: Vec::new(),
            skip_depth: 0,
            or_depth: 0,
            cte_names,
            potential_col_col: false,
        }
    }
}

impl Visitor for SelectVisitor {
    type Break = ();

    fn pre_visit_table_factor(&mut self, table_factor: &TableFactor) -> ControlFlow<Self::Break> {
        match table_factor {
            TableFactor::Table { name, alias, .. }
                if self.skip_depth == 0 && !is_table_valued_function(table_factor) =>
            {
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

        if matches!(
            expr,
            Expr::BinaryOp {
                op: BinaryOperator::Or,
                ..
            }
        ) {
            self.or_depth += 1;
        }

        // Skip filters inside OR branches: OR does not guarantee the filter is enforced
        if self.or_depth > 0 {
            return ControlFlow::Continue(());
        }

        if let Some(filter) = try_extract_filter(expr, self.placeholder_counter) {
            self.filters.push(filter);
        } else if !self.potential_col_col {
            if let Expr::BinaryOp {
                op: BinaryOperator::Eq,
                left,
                right,
            } = expr
            {
                if is_column_ref(left) && is_column_ref(right) {
                    self.potential_col_col = true;
                }
            }
        }

        ControlFlow::Continue(())
    }

    fn post_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
        if extract_subquery(expr).is_some() {
            self.skip_depth = self.skip_depth.saturating_sub(1);
        }
        if matches!(
            expr,
            Expr::BinaryOp {
                op: BinaryOperator::Or,
                ..
            }
        ) {
            self.or_depth = self.or_depth.saturating_sub(1);
        }
        ControlFlow::Continue(())
    }
}

fn is_mysql_placeholder(expr: &Expr) -> bool {
    matches!(expr, Expr::Value(ValueWithSpan { value: Value::Placeholder(p), .. }) if p == "?")
}

fn is_placeholder(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Value(ValueWithSpan {
            value: Value::Placeholder(_),
            ..
        })
    )
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

struct ColColPair {
    left_table: Option<String>,
    left_col: String,
    right_table: Option<String>,
    right_col: String,
}

/// Extracts a column-to-column equality pair (e.g. `r.sys_group_id = t.sys_group_id`).
fn try_extract_col_col_pair(expr: &Expr) -> Option<ColColPair> {
    let Expr::BinaryOp { left, op, right } = expr else {
        return None;
    };

    if *op != BinaryOperator::Eq {
        return None;
    }

    let (left_table, left_col) = extract_column_ref(left)?;
    let (right_table, right_col) = extract_column_ref(right)?;
    Some(ColColPair {
        left_table,
        left_col,
        right_table,
        right_col,
    })
}

/// Returns true if the column's table qualifier belongs to the current query.
/// Unqualified columns (no table prefix) are always considered in scope.
fn is_table_in_scope(table: &Option<String>, tables: &[TableRef]) -> bool {
    match table {
        None => true,
        Some(t) => tables.iter().any(|tr| {
            tr.name.eq_ignore_ascii_case(t)
                || tr.alias.as_ref().is_some_and(|a| a.eq_ignore_ascii_case(t))
        }),
    }
}

/// If `source_key` has a known value and `target_key` doesn't yet, creates a new
/// filter for `target_key` with that value. Returns `None` if `target_key` already
/// has a value, `source_key` has no value, or the target table is out of scope.
fn try_derive_filter(
    target_key: &(Option<String>, String),
    source_key: &(Option<String>, String),
    col_values: &[FilterColumn],
    tables: &[TableRef],
) -> Option<FilterColumn> {
    if col_values
        .iter()
        .any(|f| f.table == target_key.0 && f.column == target_key.1)
    {
        return None;
    }
    let source = col_values
        .iter()
        .find(|f| f.table == source_key.0 && f.column == source_key.1)?;
    if !is_table_in_scope(&target_key.0, tables) {
        return None;
    }
    Some(FilterColumn {
        table: target_key.0.clone(),
        column: target_key.1.clone(),
        value: source.value.clone(),
        placeholder_number: source.placeholder_number,
        is_placeholder: source.is_placeholder,
    })
}

/// Collects col-col pairs from INNER JOIN ON conditions.
/// Outer join (LEFT/RIGHT/FULL) ON conditions are excluded.
fn collect_col_col_pairs_from_joins(tables: &[TableWithJoins]) -> Vec<ColColPair> {
    let mut pairs = Vec::new();
    for twj in tables {
        for join in &twj.joins {
            if let JoinOperator::Join(JoinConstraint::On(on_expr))
            | JoinOperator::Inner(JoinConstraint::On(on_expr)) = &join.join_operator
            {
                collect_col_col_pairs_only(on_expr, &mut pairs, false);
            }
        }
    }
    pairs
}

/// Collects col-col pairs for a SELECT statement from INNER JOIN ON conditions,
/// the WHERE clause, and the HAVING clause.
fn collect_col_col_pairs_for_select(set_expr: &SetExpr) -> Vec<ColColPair> {
    let select = match set_expr {
        SetExpr::Select(s) => s.as_ref(),
        _ => return Vec::new(),
    };

    let mut pairs = collect_col_col_pairs_from_joins(&select.from);

    if let Some(selection) = &select.selection {
        collect_col_col_pairs_only(selection, &mut pairs, false);
    }

    if let Some(having) = &select.having {
        collect_col_col_pairs_only(having, &mut pairs, false);
    }

    pairs
}

fn collect_col_col_pairs_only(expr: &Expr, pairs: &mut Vec<ColColPair>, in_or: bool) {
    if !in_or {
        if let Some(pair) = try_extract_col_col_pair(expr) {
            pairs.push(pair);
        }
    }
    if extract_subquery(expr).is_some() {
        return;
    }
    match expr {
        Expr::BinaryOp { left, op, right } => {
            let in_or = in_or || *op == BinaryOperator::Or;
            collect_col_col_pairs_only(left, pairs, in_or);
            collect_col_col_pairs_only(right, pairs, in_or);
        }
        Expr::Nested(inner) => collect_col_col_pairs_only(inner, pairs, in_or),
        _ => {}
    }
}

/// Given pairs like `a.x = b.x` and `b.x = c.x`, spreads known filter values
/// through the chain. If `c.x = $1` is a known filter, this derives `b.x = $1`
/// and then `a.x = $1`. Loops until nothing new is found. Only creates filters
/// for tables that belong to the current query.
fn resolve_col_col_filters(
    filters: &[FilterColumn],
    col_col_pairs: &[ColColPair],
    tables: &[TableRef],
) -> Vec<FilterColumn> {
    if col_col_pairs.is_empty() {
        return Vec::new();
    }

    // Pre-compute (table, column) key tuples from pairs once.
    // This avoids cloning them on every iteration of the resolution loop
    let pair_keys: Vec<_> = col_col_pairs
        .iter()
        .map(|p| {
            (
                (p.left_table.clone(), p.left_col.clone()),
                (p.right_table.clone(), p.right_col.clone()),
            )
        })
        .collect();

    // Uses a Vec rather than HashMap because filter counts are small,
    // so linear scan avoids hash computation and allocator overhead.
    let mut col_values = filters.to_vec();
    col_values.reserve(col_col_pairs.len());
    let initial_len = col_values.len();

    loop {
        let mut added_in_pass = false;

        for (left_key, right_key) in &pair_keys {
            if let Some(new_filter) = try_derive_filter(left_key, right_key, &col_values, tables) {
                col_values.push(new_filter);
                added_in_pass = true;
            }

            if let Some(new_filter) = try_derive_filter(right_key, left_key, &col_values, tables) {
                col_values.push(new_filter);
                added_in_pass = true;
            }
        }

        if !added_in_pass {
            break;
        }
    }

    col_values.drain(initial_len..).collect()
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
        value: expr_to_value_string(maybe_value)?,
        placeholder_number,
        is_placeholder: is_placeholder(maybe_value),
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

fn expr_to_value_string(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Value(vws) => match &vws.value {
            Value::Placeholder(p) => Some(p.clone()),
            Value::Number(n, _) => Some(n.clone()),
            Value::SingleQuotedString(s)
            | Value::DoubleQuotedString(s)
            | Value::TripleSingleQuotedString(s)
            | Value::TripleDoubleQuotedString(s)
            | Value::EscapedStringLiteral(s)
            | Value::UnicodeStringLiteral(s)
            | Value::SingleQuotedByteStringLiteral(s)
            | Value::DoubleQuotedByteStringLiteral(s)
            | Value::TripleSingleQuotedByteStringLiteral(s)
            | Value::TripleDoubleQuotedByteStringLiteral(s)
            | Value::SingleQuotedRawStringLiteral(s)
            | Value::DoubleQuotedRawStringLiteral(s)
            | Value::TripleSingleQuotedRawStringLiteral(s)
            | Value::TripleDoubleQuotedRawStringLiteral(s)
            | Value::NationalStringLiteral(s)
            | Value::HexStringLiteral(s) => Some(s.clone()),
            Value::DollarQuotedString(dqs) => Some(dqs.value.clone()),
            Value::QuoteDelimitedStringLiteral(qs)
            | Value::NationalQuoteDelimitedStringLiteral(qs) => Some(qs.value.clone()),
            Value::Boolean(_) | Value::Null => None,
        },
        _ => None,
    }
}

fn object_name_to_string(name: &ObjectName) -> String {
    name.0
        .iter()
        .filter_map(|part| match part {
            ObjectNamePart::Identifier(ident) => Some(ident.value.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn extract_filters_from_where(
    expr: &Expr,
    counter: &mut usize,
) -> (Vec<FilterColumn>, Vec<ColColPair>, Vec<Query>) {
    let mut filters = Vec::new();
    let mut col_col_pairs = Vec::new();
    let mut subqueries = Vec::new();
    // Start with in_or=false: the top-level WHERE clause is not inside an OR branch
    walk_expr(
        expr,
        counter,
        &mut filters,
        &mut col_col_pairs,
        &mut subqueries,
        false,
    );
    (filters, col_col_pairs, subqueries)
}

fn walk_expr(
    expr: &Expr,
    counter: &mut usize,
    filters: &mut Vec<FilterColumn>,
    col_col_pairs: &mut Vec<ColColPair>,
    subqueries: &mut Vec<Query>,
    in_or: bool,
) {
    if is_mysql_placeholder(expr) {
        *counter += 1;
    }

    // Skip filters inside OR branches: OR does not guarantee the filter is enforced
    if !in_or {
        if let Some(filter) = try_extract_filter(expr, *counter) {
            filters.push(filter);
        } else if let Some(pair) = try_extract_col_col_pair(expr) {
            col_col_pairs.push(pair);
        }
    }

    if let Some(subquery) = extract_subquery(expr) {
        subqueries.push(subquery.clone());
        return;
    }

    match expr {
        Expr::BinaryOp { left, op, right } => {
            let in_or = in_or || *op == BinaryOperator::Or;
            walk_expr(left, counter, filters, col_col_pairs, subqueries, in_or);
            walk_expr(right, counter, filters, col_col_pairs, subqueries, in_or);
        }
        Expr::Nested(inner) => {
            walk_expr(inner, counter, filters, col_col_pairs, subqueries, in_or);
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
    if is_table_valued_function(factor) {
        return None;
    }
    if let TableFactor::Table { name, alias, .. } = factor {
        Some(TableRef {
            name: object_name_to_string(name),
            alias: alias.as_ref().map(|a| a.name.value.clone()),
        })
    } else {
        None
    }
}

/// Returns true if `factor` is a table-valued function call (e.g.
/// `jsonb_array_elements(metadata) AS elem`, `generate_series(1, 10)`), rather than a real
/// table reference. These operate on row data or generate rows, so they are not entities
/// that need their own IDOR filter.
///
/// sqlparser represents both real tables and TVF calls as `TableFactor::Table`; the
/// distinguishing field is `args`: per sqlparser docs, it is `Some(_)` for a TVF call
/// (even with zero arguments) and `None` for a plain table reference.
/// https://github.com/apache/datafusion-sqlparser-rs/blob/b6af2aead6c611a34fed9c24943629753c0a6df0/src/ast/query.rs#L1477
///
/// One documented exception: the deprecated MSSQL `FROM foo (NOLOCK)` table-hint
/// syntax also lands in `args`. Those args are always bare hint keywords (e.g. NOLOCK,
/// READPAST), so we treat that case as a real table reference, not a TVF call.
fn is_table_valued_function(table_factor: &TableFactor) -> bool {
    let TableFactor::Table {
        args: Some(args), ..
    } = table_factor
    else {
        return false;
    };
    // Empty arg list -- treat as TVF (rare, e.g. `current_user()`).
    if args.args.is_empty() {
        return true;
    }
    // If every arg is a bare MSSQL table-hint keyword, this is the deprecated hint
    // syntax (`FROM foo (NOLOCK)`), not a function call.
    !args.args.iter().all(is_mssql_table_hint_arg)
}

/// Recognizes a bare MSSQL table-hint keyword as it appears inside the deprecated
/// `FROM foo (NOLOCK, READPAST, ...)` syntax: an unnamed positional arg holding a single
/// bare identifier whose value matches one of the 15 hints MSSQL allows without the
/// `WITH` keyword. Other hints (HOLDLOCK, KEEPIDENTITY, FORCESEEK, INDEX = ..., etc.)
/// require `WITH (...)` and land in `with_hints`, so they never reach `args`.
/// https://learn.microsoft.com/en-us/sql/t-sql/queries/hints-transact-sql-table
fn is_mssql_table_hint_arg(arg: &FunctionArg) -> bool {
    let FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Identifier(ident))) = arg else {
        return false;
    };
    matches!(
        ident.value.to_uppercase().as_str(),
        "NOLOCK"
            | "READUNCOMMITTED"
            | "UPDLOCK"
            | "REPEATABLEREAD"
            | "SERIALIZABLE"
            | "READCOMMITTED"
            | "TABLOCK"
            | "TABLOCKX"
            | "PAGLOCK"
            | "ROWLOCK"
            | "NOWAIT"
            | "READPAST"
            | "XLOCK"
            | "SNAPSHOT"
            | "NOEXPAND"
    )
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
                        value: expr_to_value_string(expr)?,
                        placeholder_number,
                        is_placeholder: is_placeholder(expr),
                    })
                })
                .collect()
        })
        .collect();

    Some(rows)
}
