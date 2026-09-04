import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const selectedOptLevel = process.argv[2];
const variants = await Promise.all(
  process.argv.slice(3).map(async (argument) => {
    const separator = argument.indexOf('=');
    if (separator === -1) {
      throw new Error(`Invalid variant: ${argument}`);
    }

    return {
      name: argument.slice(0, separator),
      internals: await import(
        pathToFileURL(resolve(argument.slice(separator + 1)))
      ),
    };
  })
);

if (!variants.some((variant) => variant.name === selectedOptLevel)) {
  throw new Error(`Missing build for selected opt-level ${selectedOptLevel}`);
}

const sql = "select * from users where id = '1' or 1=1 # '";
const userInput = "1' or 1=1 # ";
const simpleIdorQuery = 'SELECT * FROM users WHERE tenant_id = $1';
const joinedIdorQuery =
  'SELECT * FROM users u JOIN orders o ON o.user_id = u.id WHERE u.tenant_id = $1';
const complexIdorQuery = `WITH monthly_revenue AS (
  SELECT o.tenant_id, DATE_TRUNC('month', o.created_at) AS month,
         SUM(oi.quantity * oi.unit_price) AS revenue
  FROM orders o
  JOIN order_items oi ON oi.order_id = o.id
  WHERE o.tenant_id = $1
  GROUP BY o.tenant_id, DATE_TRUNC('month', o.created_at)
), top_products AS (
  SELECT p.id, p.tenant_id, p.name, SUM(oi.quantity) AS total_sold
  FROM products p
  JOIN order_items oi ON oi.product_id = p.id
  JOIN orders o ON o.id = oi.order_id
  WHERE p.tenant_id = $1
  GROUP BY p.id, p.tenant_id, p.name
)
SELECT mr.month, mr.revenue, tp.name
FROM monthly_revenue mr
JOIN top_products tp ON tp.tenant_id = mr.tenant_id
WHERE mr.revenue > 5000
ORDER BY mr.month DESC
LIMIT 50`;

const benchmarks = [
  {
    name: 'SQL injection',
    iterations: 100_000,
    warmupIterations: 20_000,
    run: (internals) =>
      internals.wasm_detect_sql_injection(sql, userInput, 8),
  },
  {
    name: 'IDOR simple SELECT',
    iterations: 20_000,
    warmupIterations: 5_000,
    run: (internals) =>
      internals.wasm_idor_analyze_sql(simpleIdorQuery, 9),
  },
  {
    name: 'IDOR SELECT with JOIN',
    iterations: 20_000,
    warmupIterations: 5_000,
    run: (internals) =>
      internals.wasm_idor_analyze_sql(joinedIdorQuery, 9),
  },
  {
    name: 'IDOR complex query',
    iterations: 2_000,
    warmupIterations: 1_000,
    run: (internals) =>
      internals.wasm_idor_analyze_sql(complexIdorQuery, 9),
  },
];

let sink = 0;

function consume(value) {
  sink ^= typeof value === 'number' ? value : value.length;
}

function runIterations(benchmark, internals, iterations) {
  const start = process.hrtime.bigint();
  for (let index = 0; index < iterations; index++) {
    consume(benchmark.run(internals));
  }
  return Number(process.hrtime.bigint() - start) / iterations;
}

function average(values) {
  return values.reduce((total, value) => total + value, 0) / values.length;
}

function compare(benchmark) {
  const samples = new Map();

  for (const variant of variants) {
    runIterations(benchmark, variant.internals, benchmark.warmupIterations);
    samples.set(variant.name, []);
  }

  for (let sample = 0; sample < 3; sample++) {
    const offset = sample % variants.length;
    const orderedVariants = variants
      .slice(offset)
      .concat(variants.slice(0, offset));

    for (const variant of orderedVariants) {
      if (global.gc) {
        global.gc();
      }
      samples
        .get(variant.name)
        .push(
          runIterations(
            benchmark,
            variant.internals,
            benchmark.iterations
          )
        );
    }
  }

  const timings = new Map(
    variants.map((variant) => [variant.name, average(samples.get(variant.name))])
  );
  const fastestVariant = variants.reduce((fastest, variant) =>
    timings.get(variant.name) < timings.get(fastest.name) ? variant : fastest
  );

  return {
    name: benchmark.name,
    timings,
    fastestOptLevel: fastestVariant.name,
    selectedRatio:
      timings.get(selectedOptLevel) / timings.get(fastestVariant.name),
  };
}

for (const variant of variants) {
  if (variant.internals.wasm_detect_sql_injection(sql, userInput, 8) !== 1) {
    throw new Error(
      `SQL injection benchmark input was not detected by opt-level ${variant.name}`
    );
  }
}

const results = benchmarks.map(compare);
const headings = variants.map((variant) => `opt-level ${variant.name}`);

console.log(
  `| Benchmark | ${headings.join(' | ')} | Fastest | selected / fastest |`
);
console.log(`|---|${variants.map(() => '---:|').join('')}---:|---:|`);
for (const result of results) {
  const timings = variants.map(
    (variant) => `${(result.timings.get(variant.name) / 1_000).toFixed(3)} µs`
  );
  console.log(
    `| ${result.name} | ${timings.join(' | ')} | ${result.fastestOptLevel} | ${result.selectedRatio.toFixed(3)} |`
  );
}

const slowResults = results.filter((result) => result.selectedRatio > 1.05);
if (slowResults.length > 0) {
  throw new Error(
    `Selected opt-level ${selectedOptLevel} is more than 5% slower than the fastest build for: ${slowResults.map((result) => result.name).join(', ')}`
  );
}

void sink;
