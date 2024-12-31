use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use zen_internals::sql_injection::detect_sql_injection::detect_sql_injection_str;

fn criterion_benchmark(c: &mut Criterion) {
    let sql = "SELECT * FROM users WHERE id = '1' OR 1=1 # '";
    let user = "1' OR 1=1 # ";
    let dialect = 8; // MySQL

    c.bench_function("is injection", |b| {
        b.iter(|| detect_sql_injection_str(black_box(sql), black_box(user), black_box(dialect)))
    });

    c.bench_function("is not injection", |b| {
        b.iter(|| detect_sql_injection_str(black_box(sql), black_box("1"), black_box(dialect)))
    });

    c.bench_function("big sql", |b| {
        let sql = "SELECT * FROM users WHERE id = 'hello world' ".to_owned()
            + &" OR id = 'hello world'".repeat(1000);
        b.iter(|| {
            detect_sql_injection_str(
                black_box(&sql),
                black_box("hello world"),
                black_box(dialect),
            )
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
