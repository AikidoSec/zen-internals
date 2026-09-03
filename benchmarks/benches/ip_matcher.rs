use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::time::Duration;
use zen_internals::ip_matcher::IpMatcher;

fn ipv4_address(index: usize) -> String {
    format!(
        "10.{}.{}.{}",
        (index >> 16) & 0xff,
        (index >> 8) & 0xff,
        index & 0xff
    )
}

fn representative_networks(size: usize) -> Vec<String> {
    (0..size)
        .map(|index| {
            if index % 2 == 0 {
                format!("{}/32", ipv4_address(index / 2))
            } else {
                format!("2001:db8::{:x}/128", index / 2)
            }
        })
        .collect()
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("ip_matcher");
    group
        .sample_size(20)
        .measurement_time(Duration::from_secs(2));

    for size in [100, 10_000, 100_000] {
        let networks = representative_networks(size);
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::new("construction", size),
            &networks,
            |b, networks| b.iter(|| IpMatcher::new(black_box(networks.iter()))),
        );

        let matcher = IpMatcher::new(networks.iter());
        let ipv4_hit = ipv4_address((size - 2) / 2);
        let ipv6_hit = format!("2001:db8::{:x}", (size - 1) / 2);
        group.bench_with_input(
            BenchmarkId::new("lookup_ipv4_hit", size),
            &ipv4_hit,
            |b, lookup| b.iter(|| matcher.has(black_box(lookup))),
        );
        group.bench_with_input(
            BenchmarkId::new("lookup_ipv6_hit", size),
            &ipv6_hit,
            |b, lookup| b.iter(|| matcher.has(black_box(lookup))),
        );
    }

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
