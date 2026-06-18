use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use zen_internals::idor::idor_analyze_sql::idor_analyze_sql;

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("idor");

    group.bench_function("simple_select", |b| {
        b.iter(|| {
            idor_analyze_sql(
                black_box("SELECT * FROM users WHERE tenant_id = $1"),
                black_box(9),
            )
        })
    });

    group.bench_function("select_with_join", |b| {
        b.iter(|| {
            idor_analyze_sql(
                black_box("SELECT * FROM users u JOIN orders o ON o.user_id = u.id WHERE u.tenant_id = $1"),
                black_box(9),
            )
        })
    });

    group.bench_function("insert", |b| {
        b.iter(|| {
            idor_analyze_sql(
                black_box("INSERT INTO users (name, tenant_id) VALUES ('test', $1)"),
                black_box(9),
            )
        })
    });

    group.bench_function("update", |b| {
        b.iter(|| {
            idor_analyze_sql(
                black_box("UPDATE users SET name = $1 WHERE tenant_id = $2"),
                black_box(9),
            )
        })
    });

    group.bench_function("cte_with_multiple_queries", |b| {
        b.iter(|| {
            idor_analyze_sql(
                black_box("WITH active AS (SELECT * FROM users WHERE tenant_id = $1) SELECT * FROM active a JOIN orders o ON o.user_id = a.id WHERE o.tenant_id = $2"),
                black_box(9),
            )
        })
    });

    group.bench_function("union", |b| {
        b.iter(|| {
            idor_analyze_sql(
                black_box("SELECT * FROM users WHERE tenant_id = $1 UNION SELECT * FROM admins WHERE tenant_id = $2"),
                black_box(9),
            )
        })
    });

    group.bench_function("large_complex_query", |b| {
        b.iter(|| {
            idor_analyze_sql(
                black_box(concat!(
                    "WITH monthly_revenue AS (",
                        "SELECT o.tenant_id, ",
                               "DATE_TRUNC('month', o.created_at) AS month, ",
                               "SUM(oi.quantity * oi.unit_price) AS revenue, ",
                               "COUNT(DISTINCT o.id) AS order_count, ",
                               "COUNT(DISTINCT o.user_id) AS unique_customers ",
                        "FROM orders o ",
                        "JOIN order_items oi ON oi.order_id = o.id ",
                        "WHERE o.tenant_id = $1 ",
                          "AND o.status NOT IN ('cancelled', 'refunded') ",
                          "AND o.created_at >= '2024-01-01' ",
                        "GROUP BY o.tenant_id, DATE_TRUNC('month', o.created_at)",
                    "), ",
                    "top_products AS (",
                        "SELECT p.id, p.tenant_id, p.name, p.category, ",
                               "SUM(oi.quantity) AS total_sold, ",
                               "SUM(oi.quantity * oi.unit_price) AS total_revenue, ",
                               "ROW_NUMBER() OVER (PARTITION BY p.category ORDER BY SUM(oi.quantity * oi.unit_price) DESC) AS rank ",
                        "FROM products p ",
                        "JOIN order_items oi ON oi.product_id = p.id ",
                        "JOIN orders o ON o.id = oi.order_id ",
                        "WHERE p.tenant_id = $1 AND o.status = 'completed' ",
                        "GROUP BY p.id, p.tenant_id, p.name, p.category",
                    "), ",
                    "customer_segments AS (",
                        "SELECT u.id AS user_id, u.tenant_id, u.email, u.created_at AS joined_at, ",
                               "COUNT(o.id) AS lifetime_orders, ",
                               "SUM(o.total_amount) AS lifetime_value, ",
                               "MAX(o.created_at) AS last_order_at, ",
                               "CASE WHEN SUM(o.total_amount) > 10000 THEN 'vip' ",
                                    "WHEN SUM(o.total_amount) > 1000 THEN 'regular' ",
                                    "ELSE 'occasional' END AS segment ",
                        "FROM users u ",
                        "LEFT JOIN orders o ON o.user_id = u.id AND o.status = 'completed' ",
                        "WHERE u.tenant_id = $1 ",
                        "GROUP BY u.id, u.tenant_id, u.email, u.created_at ",
                        "HAVING COUNT(o.id) > 0",
                    ") ",
                    "SELECT cs.email, cs.segment, cs.lifetime_value, cs.last_order_at, ",
                           "mr.month, mr.revenue AS monthly_revenue, mr.order_count, ",
                           "tp.name AS top_product, tp.category, tp.rank AS product_rank, ",
                           "a.street, a.city, a.country, ",
                           "(SELECT COUNT(*) FROM support_tickets st ",
                             "WHERE st.user_id = cs.user_id AND st.tenant_id = $1) AS ticket_count ",
                    "FROM customer_segments cs ",
                    "JOIN monthly_revenue mr ON mr.tenant_id = cs.tenant_id ",
                    "JOIN top_products tp ON tp.tenant_id = cs.tenant_id AND tp.rank = 1 ",
                    "LEFT JOIN addresses a ON a.user_id = cs.user_id AND a.is_primary = true ",
                    "WHERE cs.segment IN ('vip', 'regular') ",
                      "AND mr.revenue > 5000 ",
                      "AND tp.total_sold > 10 ",
                    "ORDER BY cs.lifetime_value DESC, mr.month DESC ",
                    "LIMIT 50 OFFSET 0"
                )),
                black_box(9),
            )
        })
    });

    group.bench_function("col_col_simple", |b| { 
        b.iter(|| {
            idor_analyze_sql(
                black_box("SELECT r.* FROM requests r JOIN tenants t ON r.tenant_id = t.tenant_id WHERE t.tenant_id = $1"),
                black_box(9),
            )
        })
    });

    group.bench_function("col_col_deep_transitive_chain", |b| {
        b.iter(|| {
            idor_analyze_sql(
                black_box(
                    "SELECT \
                        a.id, a.name, a.status, a.created_at, \
                        b.description, b.updated_at, b.reference, \
                        c.amount, c.currency, c.due_date, \
                        d.ref_number, d.type, d.processed_at, \
                        e.email, e.phone, e.verified, \
                        f.address, f.city, f.country, f.postal_code \
                     FROM table_a a \
                     INNER JOIN table_b b ON a.tenant_id = b.tenant_id AND a.id = b.a_id \
                     INNER JOIN table_c c ON b.tenant_id = c.tenant_id AND b.id = c.b_id \
                     INNER JOIN table_d d ON c.tenant_id = d.tenant_id AND c.id = d.c_id \
                     INNER JOIN table_e e ON d.tenant_id = e.tenant_id AND d.id = e.d_id \
                     INNER JOIN table_f f ON e.tenant_id = f.tenant_id AND e.id = f.e_id \
                     WHERE f.tenant_id = $1 \
                       AND a.status = 'active' \
                       AND c.amount > 0 \
                       AND d.type IN ('standard', 'premium') \
                     ORDER BY a.created_at DESC \
                     LIMIT 100",
                ),
                black_box(9),
            )
        })
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
