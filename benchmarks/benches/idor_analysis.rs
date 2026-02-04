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

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
