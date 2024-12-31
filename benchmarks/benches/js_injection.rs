use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use zen_internals::js_injection::detect_js_injection::detect_js_injection_str;

fn criterion_benchmark(c: &mut Criterion) {
    let code = "const test = 'Hello World!'; //';";
    let userinput = "Hello World!'; //";
    let sourcetype = 0;

    c.bench_function("is injection", |b| {
        b.iter(|| {
            detect_js_injection_str(black_box(code), black_box(userinput), black_box(sourcetype))
        })
    });

    c.bench_function("is not injection", |b| {
        b.iter(|| {
            detect_js_injection_str(
                black_box(code),
                black_box("Hello World!"), // user input
                black_box(sourcetype),
            )
        })
    });

    c.bench_function("big code", |b| {
        let code = "const test = 'Hello World!';".repeat(1000);
        b.iter(|| {
            detect_js_injection_str(
                black_box(&code),
                black_box("Hello World!"), // user input
                black_box(sourcetype),
            )
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
