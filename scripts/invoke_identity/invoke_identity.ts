#!/usr/bin/env ts-node
/**
 * Identity Contract Client
 *
 * Invokes the Identity contract's `prove_identity` method.
 * The identity circuit proves knowledge of a Poseidon2 hash preimage.
 *
 * Example (localnet):
 *   npx ts-node invoke_identity.ts prove \
 *       --contract-id CDB... \
 *       --dataset ../../circuits/identity/target \
 *       --network local --source-account alice --send yes
 *
 * Example (testnet):
 *   npx ts-node invoke_identity.ts prove \
 *       --contract-id CDB... \
 *       --dataset ../../circuits/identity/target \
 *       --network testnet --source-account alice --send yes
 */

import * as fs from 'fs';
import * as path from 'path';
import { spawn } from 'child_process';
import { ArgumentParser } from 'argparse';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const DEFAULT_DATASET_DIR = path.resolve(REPO_ROOT, 'circuits', 'identity', 'target');

// === Data loading ============================================================

function loadArtifacts(dataset: string): { publicInputsBytes: Buffer; proofBytes: Buffer } {
  const publicInputsPath = path.join(dataset, 'public_inputs');
  const proofPath = path.join(dataset, 'proof');

  if (!fs.existsSync(publicInputsPath)) {
    throw new Error(`public inputs not found: ${publicInputsPath}`);
  }
  if (!fs.existsSync(proofPath)) {
    throw new Error(`proof not found: ${proofPath}`);
  }

  return {
    publicInputsBytes: fs.readFileSync(publicInputsPath),
    proofBytes: fs.readFileSync(proofPath),
  };
}

// === CLI helpers =============================================================

function runCommand(cmd: string[], dryRun: boolean): Promise<{ returncode: number; stdout: string; stderr: string }> {
  const display = cmd.map((p) => (p.includes(' ') ? `"${p}"` : p)).join(' ');

  if (dryRun) {
    console.log(`[dry-run] ${display}`);
    return Promise.resolve({ returncode: 0, stdout: '', stderr: '' });
  }

  return new Promise((resolve) => {
    const child = spawn(cmd[0], cmd.slice(1), { stdio: ['inherit', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => {
      stdout += d.toString();
      process.stdout.write(d);
    });
    child.stderr.on('data', (d) => {
      stderr += d.toString();
      process.stderr.write(d);
    });
    child.on('close', (code) => {
      resolve({ returncode: code ?? 0, stdout, stderr });
    });
  });
}

function buildInvokeArgs(contractId: string, source: string, network: string, send: string): string[] {
  const args = [
    'contract', 'invoke',
    '--id', contractId,
    '--source', source,
    '--network', network,
  ];
  if (send === 'yes') {
    args.push('--send', 'yes');
  } else {
    args.push('--send', 'no');
  }
  return args;
}

// === Commands ================================================================

interface ProveArgs {
  contract_id: string;
  dataset: string;
  source_account: string;
  network: string;
  send: string;
  dry_run: boolean;
}

async function prove(args: ProveArgs) {
  const artifacts = loadArtifacts(args.dataset);

  console.log('--- Identity Proof Invocation ---');
  console.log(`Contract ID:   ${args.contract_id}`);
  console.log(`Network:       ${args.network}`);
  console.log(`Public Inputs: ${artifacts.publicInputsBytes.length} bytes`);
  console.log(`Proof:         ${artifacts.proofBytes.length} bytes`);
  console.log('---------------------------------');

  // Write temporary files for stellar CLI --file-path arguments
  const tmpDir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'identity-'));
  const piFile = path.join(tmpDir, 'public_inputs');
  const proofFile = path.join(tmpDir, 'proof');
  fs.writeFileSync(piFile, artifacts.publicInputsBytes);
  fs.writeFileSync(proofFile, artifacts.proofBytes);

  const cmd = [
    'stellar',
    ...buildInvokeArgs(args.contract_id, args.source_account, args.network, args.send),
    '--',
    'prove_identity',
    '--public_inputs-file-path', piFile,
    '--proof_bytes-file-path', proofFile,
  ];

  try {
    const result = await runCommand(cmd, args.dry_run);
    if (result.returncode !== 0) {
      process.exit(result.returncode);
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// === Main =====================================================================

async function main() {
  const parser = new ArgumentParser({ description: 'Identity contract client' });
  const subparsers = parser.add_subparsers({ dest: 'command', required: true });

  // prove command
  const proveParser = subparsers.add_parser('prove', { help: 'Invoke prove_identity on the contract' });
  proveParser.add_argument('--contract-id', { required: true, help: 'Contract address (C...)' });
  proveParser.add_argument('--dataset', { default: DEFAULT_DATASET_DIR, help: 'Path to circuit target/ directory' });
  proveParser.add_argument('--source-account', { default: 'alice', help: 'Stellar source account' });
  proveParser.add_argument('--network', { default: 'local', help: 'Network name (local, testnet, mainnet)' });
  proveParser.add_argument('--send', { default: 'yes', choices: ['yes', 'no'], help: 'Actually submit tx' });
  proveParser.add_argument('--dry-run', { action: 'store_true', help: 'Print command without executing' });

  // info command
  const infoParser = subparsers.add_parser('info', { help: 'Print artifact sizes' });
  infoParser.add_argument('--dataset', { default: DEFAULT_DATASET_DIR, help: 'Path to circuit target/ directory' });

  const args = parser.parse_args();

  if (args.command === 'prove') {
    await prove(args as ProveArgs);
  } else if (args.command === 'info') {
    const artifacts = loadArtifacts(args.dataset);
    console.log(`Public Inputs: ${artifacts.publicInputsBytes.length} bytes (${artifacts.publicInputsBytes.length / 32} fields)`);
    console.log(`Proof:         ${artifacts.proofBytes.length} bytes (${artifacts.proofBytes.length / 32} fields)`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
