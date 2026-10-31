import assert from 'node:assert/strict';
import { readFileSync, lstatSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { computeProjectionRoot } from './projection-identity.mjs';

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const versions = {'theme-forge-stellar-burst':'0.7.0','theme-forge-stellar-loom':'0.5.0',
  'theme-forge-solar-sail':'0.3.0','theme-forge-nebular-fusion':'0.7.1'};
const leaf = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value);
const relativeMember = value => typeof value === 'string' && !value.startsWith('/')
  && !value.startsWith('-') && !/[\u0000-\u001f\u007f]/.test(value)
  && !value.includes('\\') && !value.split('/').some(part=>!part || part==='.' || part==='..');
const digest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);

export function validateCandidateContext(lock, lockPath, candidateValidation=false) {
  const held = lock.publicationStatus === 'held_pending_rs9_production_bridge';
  if (!candidateValidation) {
    if (held) throw new Error('Current-four publication held: explicit --candidate-validation is required for qualification only.');
    return {mode:'production-default', candidateValidation:false};
  }
  assert(held && lock.generation === 'current-four', 'Candidate mode requires the closed held current generation');
  assert.deepEqual(Object.keys(lock.products).sort(),Object.keys(versions).sort());
  for (const [name,version] of Object.entries(versions)) {
    const product=lock.products[name];
    assert.equal(product.version,version);
    assert.equal(product.canonicalRepo,'Knowledge-Forge-AI/'+name);
    assert.equal(product.releaseTag,'v'+version);
    if (name==='theme-forge-nebular-fusion') {
      assert.equal(product.releaseCommit,'f2c527ee6f3cbd53fd44e095d5355ca7f5c7519a');
      assert.equal(product.releaseTree,'6e3561855f6ee0093fb709488ad976b69bf501d2');
      assert.deepEqual(Object.keys(product.rawArchives).sort(),['aarch64-darwin','aarch64-linux','x86_64-linux']);
      assert.equal(product.releaseId,429782340);
      const releaseAssetIds={'aarch64-darwin':694680425,'aarch64-linux':694680442,'x86_64-linux':694680564};
      for (const [arch,id] of Object.entries(releaseAssetIds)) assert.equal(product.rawArchives[arch].assetId,id);
    }
    for (const asset of product.rawArchives ? Object.values(product.rawArchives) : [product]) {
      assert(leaf(asset.asset) && digest(asset.sha256) && Number.isSafeInteger(asset.bytes) && asset.bytes>0);
      assert.equal(asset.url,`https://github.com/Knowledge-Forge-AI/${name}/releases/download/v${version}/${asset.asset}`);
      if (product.rawArchives) assert(relativeMember(asset.executablePath) && digest(asset.executableSha256) && !asset.asset.includes('-portable'));
    }
  }
  for (const entry of Object.values(lock.runtimeDependencies)) {
    assert(leaf(entry.tarball) && digest(entry.sha256) && Number.isSafeInteger(entry.bytes) && entry.bytes>0);
    const url=new URL(entry.resolved);
    assert(url.protocol==='https:' && url.hostname==='registry.npmjs.org' && !url.port && !url.username && !url.password && !url.search && !url.hash);
    assert(url.pathname.endsWith('/'+entry.tarball));
  }
  const root=dirname(resolve(lockPath));
  const binding=JSON.parse(readFileSync(join(root,'GENERATOR-PROJECTION-BINDING.json'),'utf8'));
  assert.equal(binding.generation,'current-four');
  assert.equal(binding.publicationStatus,lock.publicationStatus);
  assert.equal(binding.releaseLockSha256,sha256(readFileSync(lockPath)));
  assert.equal(binding.treeManifestSha256,computeProjectionRoot(root));
  const key=join(root,'keys/knowledge-forge-ai-packages.asc');
  assert(lstatSync(key).isFile() && !lstatSync(key).isSymbolicLink());
  assert.equal(sha256(readFileSync(key)),'6931a99cf38e204c0adc75dd868f8c0e79d68e58e2644f575d4be1da2ea18d95');
  assert.equal(binding.productionPublicKeySha256,sha256(readFileSync(key)));
  return {mode:'candidate-validation',candidateValidation:true,productionEnabled:false,
    publicationAuthority:false,projectionRoot:binding.treeManifestSha256,releaseLockSha256:binding.releaseLockSha256};
}
