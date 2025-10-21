use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use zen_internals::sql_injection::detect_sql_injection::detect_sql_injection_str;

fn criterion_benchmark(c: &mut Criterion) {
    let sql = "SELECT * FROM users WHERE id = '1' OR 1=1 # '";
    let user = "1' OR 1=1 # ";
    let dialect = 8; // MySQL

    let mut group = c.benchmark_group("sql");

    group.bench_function("is injection", |b| {
        b.iter(|| detect_sql_injection_str(black_box(sql), black_box(user), black_box(dialect)))
    });

    let safeUserInput = "1";

    group.bench_function("is not injection", |b| {
        b.iter(|| {
            detect_sql_injection_str(black_box(sql), black_box(safeUserInput), black_box(dialect))
        })
    });

    group.bench_function("big code", |b| {
        let sql = "SELECT * FROM users WHERE id = 'hello world' ".to_owned()
            + &" OR id = 'hello world'".repeat(1000);
        b.iter(|| {
            detect_sql_injection_str(
                black_box(&sql),
                black_box("hello world"), // user input
                black_box(dialect),
            )
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
