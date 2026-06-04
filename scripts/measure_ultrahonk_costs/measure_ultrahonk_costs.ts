#!/usr/bin/env ts-node
/**
 * Measure resource costs (CPU / memory / min resource fee) for UltraHonk
 * contract methods living on an actual Soroban network.
 *
 * Typical usage (local Quickstart):
 *   cd scripts/measure_ultrahonk_costs
 *   npm install
 *   npm run measure -- \
 *     --contract-id <CONTRACT_ID> \
 *     --source-secret <SECRET> \
 *     --rpc-url http://localhost:8000/soroban/rpc \
 *     --dataset ../../circuits/simple_circuit/target
 */

import * as fs from 'fs';
import * as path from 'path';
import { ArgumentParser } from 'argparse';
import {
  Contract,
  Keypair,
  Networks,
  SorobanRpc,
  TimeoutInfinite,
  TransactionBuilder,
  nativeToScVal,
  xdr,
} from '@stellar/stellar-sdk';

const PROJECT_ROOT = path.resolve(__dirname, '..', '..');
const DEFAULT_DATASET_DIR = path.join(PROJECT_ROOT, 'circuits', 'simple_circuit', 'target');
const DEFAULT_RPC_URL = 'http://localhost:8000/soroban/rpc';
const DEFAULT_NETWORK_PASSPHRASE = Networks.STANDALONE;
const FIELD_BYTES = 32;

interface Artifacts {
  publicInputs: Buffer;
  proofBytes: Buffer;
}

interface MeasureResult {
  cpu: bigint;
  readBytes: bigint;
  writeBytes: bigint;
  minFee: bigint;
  txEnvelopeSize: number;
  proofSize: number;
  publicInputsSize: number;
  // Populated only when --submit is used.
  actual?: ActualResult;
}

interface ActualResult {
  txHash: string;
  ledger: number;
  feeCharged: bigint;
  nonRefundableResourceFee?: bigint;
  refundableResourceFee?: bigint;
  rentFee?: bigint;
}

function loadArtifacts(datasetDir: string): Artifacts {
  const proofPath = path.resolve(datasetDir, 'proof');
  const publicInputsPath = path.resolve(datasetDir, 'public_inputs');
  for (const file of [proofPath, publicInputsPath]) {
    if (!fs.existsSync(file)) {
      throw new Error(`Missing artifact: ${file}`);
    }
  }
  const proofBytes = fs.readFileSync(proofPath);
  const publicInputs = fs.readFileSync(publicInputsPath);
  if (publicInputs.length % FIELD_BYTES !== 0) {
    throw new Error('public_inputs length is not a multiple of 32 bytes');
  }
  if (proofBytes.length % FIELD_BYTES !== 0) {
    throw new Error('proof length is not a multiple of 32 bytes');
  }
  return { publicInputs, proofBytes };
}

function bigIntFromXdr(value?: xdr.Int64 | xdr.Uint64 | number | string | null): bigint {
  if (value === undefined || value === null) {
    return 0n;
  }
  if (typeof value === 'number') {
    return BigInt(value);
  }
  if (typeof value === 'string') {
    return BigInt(value);
  }
  return BigInt(value.toString());
}

async function pollForFinal(
  server: SorobanRpc.Server,
  hash: string,
  timeoutMs = 60_000,
  intervalMs = 2_000
): Promise<SorobanRpc.Api.RawGetTransactionResponse> {
  // Use the raw response so we don't depend on the SDK's auto-parser, which
  // breaks against newer protocols (e.g. TransactionMeta v4 on protocol 23+).
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const resp = await server._getTransaction(hash);
    if (resp.status !== SorobanRpc.Api.GetTransactionStatus.NOT_FOUND) {
      return resp;
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error(`Timed out waiting for tx ${hash} to land in a ledger`);
}

function extractActual(
  hash: string,
  resp: SorobanRpc.Api.RawGetTransactionResponse
): ActualResult {
  // TransactionResult XDR is stable across protocols, so feeCharged is safe
  // to decode even when the rest of the response uses a newer meta version
  // the SDK doesn't recognize yet.
  let feeCharged = 0n;
  if (resp.resultXdr) {
    const result = xdr.TransactionResult.fromXDR(resp.resultXdr, 'base64');
    feeCharged = bigIntFromXdr(result.feeCharged());
  }
  const out: ActualResult = {
    txHash: hash,
    ledger: resp.ledger ?? 0,
    feeCharged,
  };
  // Try to decode the Soroban fee breakdown. Best-effort: skip silently if
  // the meta is a version we don't know how to read.
  if (resp.resultMetaXdr) {
    try {
      const meta = xdr.TransactionMeta.fromXDR(resp.resultMetaXdr, 'base64');
      if (meta.switch() === 3) {
        const sorobanMeta = meta.v3().sorobanMeta();
        const ext = sorobanMeta?.ext();
        if (ext && ext.switch() === 1) {
          const v1 = ext.v1();
          out.nonRefundableResourceFee = bigIntFromXdr(v1.totalNonRefundableResourceFeeCharged());
          out.refundableResourceFee = bigIntFromXdr(v1.totalRefundableResourceFeeCharged());
          out.rentFee = bigIntFromXdr(v1.rentFeeCharged());
        }
      }
    } catch {
      // Meta uses a protocol the SDK can't parse — feeCharged alone is fine.
    }
  }
  return out;
}

async function measureMethod(
  server: SorobanRpc.Server,
  keypair: Keypair,
  networkPassphrase: string,
  contractId: string,
  method: string,
  args: xdr.ScVal[],
  submit: boolean
): Promise<MeasureResult> {
  const account = await server.getAccount(keypair.publicKey());
  const contract = new Contract(contractId);
  const tx = new TransactionBuilder(account, {
    fee: '100',
    networkPassphrase,
  })
    .addOperation(contract.call(method, ...args))
    .setTimeout(TimeoutInfinite)
    .build();

  const sim = await server.simulateTransaction(tx);
  if (!SorobanRpc.Api.isSimulationSuccess(sim)) {
    throw new Error(`Simulation for ${method} failed: ${JSON.stringify(sim)}`);
  }

  const resources = sim.transactionData.build().resources();
  const cpu = bigIntFromXdr(resources.instructions());
  const readBytes = bigIntFromXdr(resources.readBytes());
  const writeBytes = bigIntFromXdr(resources.writeBytes());
  const minFee = bigIntFromXdr(sim.minResourceFee);

  // Sign the *assembled* tx (sim resources + footprint attached) so the
  // envelope size reflects what's actually broadcast on-chain — including the
  // InvokeHostFunctionOp args (proof + public inputs).
  const assembled = SorobanRpc.assembleTransaction(tx, sim).build();
  assembled.sign(keypair);
  const txEnvelopeSize = assembled.toEnvelope().toXDR().length;

  let actual: ActualResult | undefined;
  if (submit) {
    const send = await server.sendTransaction(assembled);
    if (send.status !== 'PENDING') {
      throw new Error(
        `sendTransaction returned status ${send.status}: ${JSON.stringify(send)}`
      );
    }
    console.log(`Submitted tx ${send.hash}; waiting for ledger close...`);
    const final = await pollForFinal(server, send.hash);
    actual = extractActual(send.hash, final);
    if (final.status === SorobanRpc.Api.GetTransactionStatus.FAILED) {
      console.error(`Tx ${send.hash} FAILED on-chain (still reporting fee charged).`);
    }
  }

  return {
    cpu,
    readBytes,
    writeBytes,
    minFee,
    txEnvelopeSize,
    proofSize: args[1].bytes()?.length ?? 0,
    publicInputsSize: args[0].bytes()?.length ?? 0,
    actual,
  };
}

function formatStroops(stroops: bigint): string {
  const xlm = Number(stroops) / 10_000_000;
  return `${stroops} stroops (${xlm.toFixed(7)} XLM)`;
}

function printResult(name: string, result: MeasureResult) {
  const cpuLimit = 100_000_000n;
  const cpuPercent = ((Number(result.cpu) * 100) / Number(cpuLimit)).toFixed(2);

  const label = (text: string) => `\x1b[1m${text.padEnd(25)}\x1b[0m`;

  console.log(`\n\x1b[1m\x1b[36m=== Performance Report: ${name} ===\x1b[0m`);
  console.log(`${label('CPU Instructions')} : ${result.cpu.toLocaleString()} (${cpuPercent}% of limit)`);
  console.log(`${label('Ledger Read Bytes')} : ${result.readBytes.toLocaleString()}`);
  console.log(`${label('Ledger Write Bytes')} : ${result.writeBytes.toLocaleString()}`);
  console.log(`${label('Min Resource Fee')} : ${formatStroops(result.minFee)}`);
  console.log(`${label('Tx Envelope Size')} : ${result.txEnvelopeSize.toLocaleString()} bytes`);
  console.log(`${label('Proof Size')} : ${result.proofSize.toLocaleString()} bytes`);
  console.log(`${label('Public Inputs Size')} : ${result.publicInputsSize.toLocaleString()} bytes`);

  if (result.actual) {
    const a = result.actual;
    console.log(`\n\x1b[1m\x1b[36m--- Actual on-chain (tx ${a.txHash.slice(0, 12)}...) ---\x1b[0m`);
    console.log(`${label('Ledger')} : ${a.ledger.toLocaleString()}`);
    console.log(`${label('Fee Charged')} : ${formatStroops(a.feeCharged)}`);
    if (a.nonRefundableResourceFee !== undefined) {
      console.log(`${label('  Non-refundable')} : ${formatStroops(a.nonRefundableResourceFee)}`);
    }
    if (a.refundableResourceFee !== undefined) {
      console.log(`${label('  Refundable')} : ${formatStroops(a.refundableResourceFee)}`);
    }
    if (a.rentFee !== undefined) {
      console.log(`${label('  Rent fee')} : ${formatStroops(a.rentFee)}`);
    }
  }

  console.log(`\x1b[36m${'='.repeat(40 + name.length)}\x1b[0m\n`);
}

async function main() {
  const parser = new ArgumentParser({
    description: 'Measure UltraHonk verifier contract costs',
  });
  parser.add_argument('--contract-id', { required: true, help: 'Contract ID' });
  parser.add_argument('--source-secret', {
    required: true,
    help: 'Secret key for the funding account',
  });
  parser.add_argument('--dataset', {
    default: DEFAULT_DATASET_DIR,
    help: 'Directory with public_inputs and proof',
  });
  parser.add_argument('--rpc-url', {
    default: DEFAULT_RPC_URL,
    help: 'Soroban RPC URL',
  });
  parser.add_argument('--network-passphrase', {
    default: DEFAULT_NETWORK_PASSPHRASE,
    help: 'Network passphrase',
  });
  parser.add_argument('--submit', {
    action: 'store_true',
    help: 'Also submit the tx and report actual fee charged on-chain',
  });
  parser.add_argument('--method', {
    default: 'verify_proof',
    help: 'Contract method to measure (default: verify_proof)',
  });

  const args = parser.parse_args();
  const artifacts = loadArtifacts(args.dataset);
  const server = new SorobanRpc.Server(args.rpc_url, { allowHttp: true });
  const keypair = Keypair.fromSecret(args.source_secret);
  const publicInputsScVal = nativeToScVal(artifacts.publicInputs, { type: 'bytes' });
  const proofBytesScVal = nativeToScVal(artifacts.proofBytes, { type: 'bytes' });

  console.log(`Dataset       : ${args.dataset}`);
  console.log(`Contract ID   : ${args.contract_id}`);
  console.log(`Method        : ${args.method}`);
  console.log(`Source account: ${keypair.publicKey()}`);

  const result = await measureMethod(
    server,
    keypair,
    args.network_passphrase,
    args.contract_id,
    args.method,
    [publicInputsScVal, proofBytesScVal],
    args.submit
  );
  printResult(args.method, result);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
