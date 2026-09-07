import { stat } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  isMainThread,
  parentPort,
  workerData,
  Worker,
} from 'node:worker_threads';

const sql = "select * from users where id = '1' or 1=1 # '";
const userInput = "1' or 1=1 # ";
const safeSql = "SELECT 'he 1 _ llo'";
const safeUserInput = 'he 1 _ llo';
const simpleIdorQuery = 'SELECT * FROM users WHERE tenant_id = $1';
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
    name: 'SQL injection (safe)',
    iterations: 100_000,
    warmupIterations: 20_000,
    run: (internals) =>
      internals.wasm_detect_sql_injection(safeSql, safeUserInput, 8),
  },
  {
    name: 'IDOR simple query',
    iterations: 20_000,
    warmupIterations: 5_000,
    run: (internals) =>
      internals.wasm_idor_analyze_sql(simpleIdorQuery, 9),
  },
  {
    name: 'IDOR big query',
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

function parseVariant(argument) {
  const separator = argument.indexOf('=');
  if (separator === -1) {
    throw new Error(`Invalid variant: ${argument}`);
  }

  return {
    name: argument.slice(0, separator),
    modulePath: argument.slice(separator + 1),
  };
}

async function benchmarkVariant(argument) {
  const { name, modulePath } = parseVariant(argument);
  const resolvedModulePath = resolve(modulePath);
  const internals = await import(pathToFileURL(resolvedModulePath));
  const wasmSize = (
    await stat(join(dirname(resolvedModulePath), 'zen_internals_bg.wasm'))
  ).size;

  if (internals.wasm_detect_sql_injection(sql, userInput, 8) !== 1) {
    throw new Error(
      `SQL injection benchmark input was not detected by opt-level ${name}`
    );
  }
  if (
    internals.wasm_detect_sql_injection(safeSql, safeUserInput, 8) !== 0
  ) {
    throw new Error(
      `Safe SQL injection benchmark input was detected by opt-level ${name}`
    );
  }

  const timings = {};
  for (const benchmark of benchmarks) {
    runIterations(benchmark, internals, benchmark.warmupIterations);
    const samples = [];

    for (let sample = 0; sample < 3; sample++) {
      if (global.gc) {
        global.gc();
      }
      samples.push(
        runIterations(benchmark, internals, benchmark.iterations)
      );
    }

    timings[benchmark.name] = average(samples);
  }

  return { name, timings, wasmSize };
}

function runVariantInWorker(argument) {
  return new Promise((resolveWorker, rejectWorker) => {
    const worker = new Worker(new URL(import.meta.url), {
      workerData: argument,
    });
    let result;
    let receivedResult = false;

    worker.once('message', (message) => {
      result = message;
      receivedResult = true;
    });
    worker.once('error', rejectWorker);
    worker.once('exit', (code) => {
      if (code !== 0) {
        rejectWorker(new Error(`Benchmark worker exited with code ${code}`));
      } else if (!receivedResult) {
        rejectWorker(new Error('Benchmark worker exited without a result'));
      } else {
        resolveWorker(result);
      }
    });
  });
}

async function main() {
  const variants = [];
  for (const argument of process.argv.slice(2)) {
    variants.push(await runVariantInWorker(argument));
  }

  const sizeBaseline = variants[0];
  const headings = benchmarks.map(
    (benchmark) => `${benchmark.name} vs opt-level ${sizeBaseline.name}`
  );
  console.log(
    `| Opt level | WASM size | vs opt-level ${sizeBaseline.name} | ${headings.join(' | ')} |`
  );
  console.log(`|---|---:|---:|${benchmarks.map(() => '---:|').join('')}`);
  for (const variant of variants) {
    const difference = variant.wasmSize - sizeBaseline.wasmSize;
    const percentage = (difference / sizeBaseline.wasmSize) * 100;
    const sign = difference > 0 ? '+' : '';
    const timings = benchmarks.map((benchmark) => {
      const timing = variant.timings[benchmark.name];
      const baselineTiming = sizeBaseline.timings[benchmark.name];
      const improvement = ((baselineTiming - timing) / baselineTiming) * 100;
      const improvementSign = improvement > 0 ? '+' : '';
      return `${(timing / 1_000).toFixed(3)} µs (${improvementSign}${improvement.toFixed(1)}%)`;
    });
    console.log(
      `| ${variant.name} | ${(variant.wasmSize / 1024).toFixed(1)} KiB | ${sign}${(difference / 1024).toFixed(1)} KiB (${sign}${percentage.toFixed(1)}%) | ${timings.join(' | ')} |`
    );
  }
}

if (isMainThread) {
  await main();
} else {
  parentPort.postMessage(await benchmarkVariant(workerData));
}

void sink;
