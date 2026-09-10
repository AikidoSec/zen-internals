const tag = process.argv[2];
const stableTag = /^v\d+\.\d+\.\d+$/;
const betaTag = /^v\d+\.\d+\.\d+-beta\.\d+$/;

if (!stableTag.test(tag) && !betaTag.test(tag)) {
  console.error("Release tag must match vX.Y.Z or vX.Y.Z-beta.N");
  process.exit(1);
}

process.stdout.write(String(betaTag.test(tag)));
