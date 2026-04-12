// Safari/WebKit on HTTP throws when native randomUUID exists but is
// broken in insecure contexts.  Test whether it actually works before
// deciding to keep the native implementation.
(function polyfillRandomUUID() {
  const c = typeof globalThis !== 'undefined' ? globalThis.crypto : null;
  if (!c) return;
  let needsPatch = typeof c.randomUUID !== 'function';
  if (!needsPatch) {
    try { c.randomUUID(); } catch (_) { needsPatch = true; }
  }
  if (!needsPatch) return;
  c.randomUUID = function randomUUID() {
    const b = new Uint8Array(16);
    if (typeof c.getRandomValues === 'function') c.getRandomValues(b);
    else for (let i = 0; i < 16; i++) b[i] = (Math.random() * 256) | 0;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const h = [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  };
})();

// ═══════════════════════════════════════════════════════════
// MISAKA Wallet — Post-Quantum Wallet (ML-DSA-65)
// ═══════════════════════════════════════════════════════════

const API_BASE = '';
const CHAIN_ID = 2;
const POLL_MS = 5000;
const UTXO_TX_VERSION = 0x02;
const GENESIS_PK_HEX =
  '7c7b22c5481981a8c7ea93c34546da99e191e8c8c1d0dd27dc9a47c0bdd3f8411902cfb4a1c8d67a9557c63d92c22baacb995dcaadf56a3d76bddfaa28a9ed2963414bcfbe9c2a5d19ee758786f09ccb5e7e7b5d10c755139cff884995404fa0a024d230b015d6faab23e47e7f7822b3432ba13fa13c5a409ec34e664a0f53039254475196c34b3e40a9516910a51e492ea80cdd5068fa0a95603028a65653a88f02158aa7c6edbe9462b8d3bdfe6f6bdb8be3b9ec37d39064d9a2bf119118a023d26e5bdbf75bf33af0ce13fce3b418ec5e1c24a17b90668ff958cb57e21e5ac63f7c055f74cce0c423b20378efc57cd225ab5fef0d1772342f07d75fa13418cc08c1d070579c6c439e322caf13439ea3624ba39e856651d0969f12e8ea971049b916ac4a5adad2017c752a8f02061e255a420fcc1c7ac73e366f445b39c93e439c9a7bd9de33d369191e58ba76cd4aae2dcab8a24e898f271716f4fb28c40905341bdead4f823cc343b33342ccd5efd5ffa76e5ac40f20ceba593ee90e3e4d554d35ac424a55d8e783d46e2a91b35e282913de42edb833d61b1a7f26dda2ddee7c83f368c000e5a26bf38a2a849f4e24a08580c43583062ddd13e60657c03d8fb4ae696ecdae3f385a18787310c828820ec8a07061cd9e81b34778c5c17efc6899c756c4497762ebcab81bf9b5089c84ef3d9e23540bf0bdbf100f1aebf71528bc826e5a98b94f49d4be25aa9971a90e65ad8c842012df198d7a4d9f83ca070843c9ba766d12eb79947a2822bc985274a7fecec0ef74e357817da403101ad81866c7198f66b1a43edd5a40394bb867345d8463a871c7d4b3a66ca7cc5efa059e7eee753f334cef8de2a618db8f61831e704ab0e07edecc8969fe25f95ce946a175bbbdd3b18085fbddee0992e71f8065bf0cb02422ceb18fe4d530d305550b519bf1df31591fc54751bf36e566575a57af230589016ed3370207703fa26906bebe7f0b9eca38a1df4fd3f2fe0bf7f686bfbd69af514952f7ede9a2dbcf2e999d2b5df521e6a973d2f04d6131bea3ae7f3b4423c12cf9bc6492d4f711a4ee012a090b087d2554ec2701a5d30afe8ec8d4f4ef0349f6f1e08151e35698829b370b8ebe72bf8bdcff4c37af02bcbd75294bbb25dc39be34b145b099e452a6506813c3b34e8ce024ef5b9c975f992d6187a8d74336b46505cc55bf447d8b98ab22f99e09259a325c4a5c970233b844ac764c4424a89fe01445bd61390f9dee0a169e93544d94ecbd7a2af536b496a2f213838424340a6d3aeaa932fdf1005b5003a4f09b90b480366e80538d3a8ca21846da5791799239ed05d430bcde31205b008dc3f0c50723ce3c4af607e9eaea2bb2eb3e31593e53c79993db64d1f0f57de28e0cf069d3ede81d088ddb24f7942264fdefb3bc4c4133a82e6fc4aa5152a164d5a7b1427704d77b093f7e872bb02c6dd6cce9843af6b4ff02ab03c360816f98780cc763422e06126d52fed128575e56c22417996567392f7c5c9191dec79e59be506588a9917b5f3c3a11c8f2f192ad794151068abb1ef611f56370cab003b30822481f0e3e33e56a8b72f304616ace7344082bf27963e76c6c232b2d3b253661fd8e8707bef933c86ec7613d3520ed47334e31335f7e0d8e22703066ec834776c2bc9a580f7d2c2850ba1b3ad0a4e2f04d65b546a6d1f8bc35b1fc7013823690a4c1eca65665a96089939b6bf91bacf711b8e961c1c2ed6c124f47e2b0687c32e857320b906f4a0b1572953b22b8e09c9c092cd3dce636d5e60354a1b69c346c9586b8a631724ce229e0a96daf137dd8fdae294469f3835a9f36ecabe14245b83a02d6e4656a6a30b9b5aa9c9e275edb03c73be1567b00cf8dd9e366864e0ccce7406d406b9c55fd8d78273ec07aa89914b34d930bcd38bac3331d913f581cc5fb4ba1ace8a41d927cb635e4a1370fed4edbd69338b9b5ad945ba27f0b2293f5503ec27a3599e78adbb88ff7e112956ce5656ee9fbad3c2d7fe64ae6221b1847e17e53fdb8fb88371b130a02e9d618797ef237f2aa5c340735c6254dabb9bd3d6109704d105f8e5244f73b2feefe8a8cca15f807d5624839d4992e880be1109950ca74342825d23b4c682aa987f9ae1d6c254d6efaef169b999018e6eaaad693ad79a0ac5450b3f537f487e1939c64fb011b5be58cf533c6468dfb2264aa7c49b2d2a5898069451d186fd60aa16326f71124697878caca2d1d9933c455ba0f14d694c45772e9bdb875da6d05118a67078422587c98bf8dff6a67d13a282513dceec354472e76db5ca6890e423abaca8745d9acbbfae480c45d682d0f3001590cc65f52c45b8b409b50f921ed00d412a9b096565835d092f4150e38d15b44610741d0d5d86ca69c45ca28e6063a9c64218c390e393fc1c0e776bcd3f2a928af5acde1740e60ae980a5da667b43c7813eeec2682fde5046f7abb52b6ce0e1d2e73fb5dc787fe04bb5e84e72932ba393318fba26d74b8f2e00670a87693a12079c6533d1d8117890913436288671d0da5bf58f210faf4552f12c8dc547435005875d3e0c89395283d5644c04b5cc0958ecf0030fd17a4fa2a656b6dee13d37967cb6281ebd5f20804e9de546b0592e6f6721dcd738fcce4b4ed736b02f661e58135936e99af8b58b1e80a7057f60bf14672a89a386ba6812c6cfb2ad19adf0bd09f3c533136cd7c7586a4f130af08a248f49ce900377a8832b343c72de7d83d53';

// Web3Auth Client ID (Replace with your own client ID in production)
const WEB3AUTH_CLIENT_ID = 'BPi5PB_UiIZ-cPz1NsV5iZjI-ND3Gz2yXcbZt9q4LwSjPZzC4N_eHk9S2GxkC_V1hD5A5U-9J4W6gU2lV9O-E4w';

// ── Helpers ─────────────────────────────────────────────
const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);
const toHex = (b) => Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, '0')).join('');
const fromHex = (h) => new Uint8Array(h.match(/.{2}/g).map((x) => parseInt(x, 16)));
const fmtMSK = (base) => {
  const v = (Number(base) / 1e9);
  return v === 0 ? '0' : v.toFixed(9).replace(/0+$/, '').replace(/\.$/, '');
};
const shortAddr = (a) => a ? a.slice(0, 14) + '…' + a.slice(-8) : '—';

// ── Crypto globals ─────────────────────────────────────
let ml_dsa65 = null, sha3_256 = null;
let bip39 = null, qrcode = null;
let web3auth = null, lucide = null;
let web3authInitPromise = null;

/** 軽量バンドル（BIP39 / QR / Lucide）。巨大な Web3Auth は別ファイルで遅延読み込みする。 */
async function loadDeps() {
  const [crypto, core] = await Promise.all([
    import('./crypto-bundle.js').catch((e) => { console.error('crypto-bundle', e); return null; }),
    import('./wallet-core-bundle.js').catch((e) => { console.error('wallet-core-bundle', e); return null; }),
  ]);
  if (crypto) {
    ml_dsa65 = crypto.ml_dsa65;
    sha3_256 = crypto.sha3_256;
  }
  if (core) {
    bip39 = core;
    qrcode = core.qrcode;
    lucide = core;
    if (lucide.createIcons) {
      lucide.createIcons({ icons: lucide.icons });
    }
  }
  const hasBip39 = typeof bip39?.generateMnemonic === 'function';
  return { crypto: !!sha3_256, pq: !!ml_dsa65, bip39: hasBip39 };
}

/** Web3Auth は ~5MB のため、SNS ログインボタン押下時のみ読み込む */
async function ensureWeb3Auth() {
  if (web3auth) return web3auth;
  if (web3authInitPromise) return web3authInitPromise;
  web3authInitPromise = (async () => {
    const w = await import('./web3auth-bundle.js').catch((e) => {
      console.error('web3auth-bundle', e);
      return null;
    });
    if (!w?.Web3Auth || !w.CommonPrivateKeyProvider || !w.CHAIN_NAMESPACES || !w.WEB3AUTH_NETWORK) {
      console.error('Web3Auth exports missing');
      return null;
    }
    const chainConfig = {
      chainNamespace: w.CHAIN_NAMESPACES.OTHER,
      chainId: '0x2',
      rpcTarget: window.location.origin,
      displayName: 'MISAKA Testnet',
      blockExplorerUrl: window.location.origin,
      ticker: 'MSK',
      tickerName: 'MISAKA',
    };
    const privateKeyProvider = new w.CommonPrivateKeyProvider({
      config: { chainConfig },
    });
    const net =
      w.WEB3AUTH_NETWORK.SAPPHIRE_DEVNET ??
      w.WEB3AUTH_NETWORK.SAPPHIRE_MAINNET ??
      w.WEB3AUTH_NETWORK.TESTNET;
    const w3a = new w.Web3Auth({
      clientId: WEB3AUTH_CLIENT_ID,
      web3AuthNetwork: net,
      privateKeyProvider,
    });
    await w3a.initModal();
    web3auth = w3a;
    return web3auth;
  })();
  return web3authInitPromise;
}

// SHA3-256 with domain prefix
function sha3(domain, ...parts) {
  const d = new TextEncoder().encode(domain);
  let len = d.length;
  for (const p of parts) len += p.length;
  const buf = new Uint8Array(len);
  let off = 0;
  buf.set(d, off); off += d.length;
  for (const p of parts) { buf.set(p, off); off += p.length; }
  return sha3_256(buf);
}

function deriveAddress(pk, chainId) {
  const body = toHex(sha3('MISAKA:address:v1:', pk));
  const cLE = new Uint8Array(4);
  new DataView(cLE.buffer).setUint32(0, chainId, true);
  const cs = sha3('MISAKA:addr:checksum:v2:', cLE, new TextEncoder().encode(body));
  return 'misaka1' + body + toHex(cs.slice(0, 2));
}

function computeGenesisHash(chainId, pks) {
  const cLE = new Uint8Array(4);
  new DataView(cLE.buffer).setUint32(0, chainId, true);
  return sha3('MISAKA-GENESIS:v1:', cLE, ...pks);
}

// ── Borsh Encoder (matches Rust) ───────────────────────
class BorshWriter {
  constructor() { this.buf = []; }
  u8(v) { this.buf.push(v & 0xff); }
  u32(v) { this.buf.push(v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff); }
  u64(v) {
    const lo = Number(BigInt(v) & 0xffffffffn);
    const hi = Number((BigInt(v) >> 32n) & 0xffffffffn);
    this.u32(lo); this.u32(hi);
  }
  fixed(b) { for (const x of b) this.buf.push(x); }
  vec_u8(a) { this.u32(a.length); for (const x of a) this.buf.push(x); }
  vec(a, fn) { this.u32(a.length); a.forEach((x) => fn(x, this)); }
  option(v, fn) { if (v == null) this.u8(0); else { this.u8(1); fn(v, this); } }
  result() { return new Uint8Array(this.buf); }
}

const TX_TYPE_BYTE = {
  SystemEmission: 1, Faucet: 2, StakeDeposit: 3,
  StakeWithdraw: 4, SlashEvidence: 5, TransparentTransfer: 6,
};

function borshSignablePayload(p) {
  const w = new BorshWriter();
  w.u8(p.version);
  w.u8(TX_TYPE_BYTE[p.tx_type]);
  w.vec(p.inputs, (inp, w2) => w2.vec(inp.utxo_refs, (r, w3) => { w3.fixed(r.tx_hash); w3.u32(r.output_index); }));
  w.vec(p.outputs, (o, w2) => { w2.u64(o.amount); w2.fixed(o.address); w2.option(o.spending_pubkey, (pk, w3) => w3.vec_u8(pk)); });
  w.u64(p.fee); w.vec_u8(p.extra); w.u64(p.expiry);
  return w.result();
}

function signingDigest(appId, payloadBytes) {
  const w = new BorshWriter();
  w.u8(0); // IntentScope::TransparentTransfer
  w.u32(appId.chain_id);
  w.fixed(appId.genesis_hash);
  w.vec_u8(payloadBytes);
  return sha3('MISAKA-INTENT:v1:', w.result());
}

function txHash(payloadBytes) {
  return sha3('MISAKA-TX-HASH:v2:', payloadBytes);
}

// ── State ──────────────────────────────────────────────
const W = {
  seed: null, mnemonic: null,
  pk: null, sk: null, pkHex: '',
  address: '', addrBytes: null,
  genesisHash: null, appId: null,
  utxos: [], balance: 0, chainInfo: null,
  txs: [], // local tx log
  pendingFaucets: [], // faucet hashes waiting for on-chain confirmation
  pendingSends: [],   // send tx hashes waiting for on-chain confirmation
  polling: null, connected: false,
};

// ── Wallet persistence ─────────────────────────────────
const STORE_KEY = 'misaka_wallet_v2';

function saveWallet() {
  const data = { seed: toHex(W.seed), mnemonic: W.mnemonic, txs: W.txs };
  localStorage.setItem(STORE_KEY, JSON.stringify(data));
}

function loadWallet() {
  const raw = localStorage.getItem(STORE_KEY);
  if (!raw) return false;
  try {
    const d = JSON.parse(raw);
    W.seed = fromHex(d.seed);
    W.mnemonic = d.mnemonic;
    W.txs = d.txs || [];
    return true;
  } catch { return false; }
}

async function deleteWallet() {
  if (web3auth && web3auth.connected) {
    try { await web3auth.logout(); } catch (e) { console.error(e); }
  }
  localStorage.removeItem(STORE_KEY);
  location.reload();
}

// ── Key derivation from seed ───────────────────────────
function deriveKeys() {
  if (!ml_dsa65 || !W.seed) return false;
  const kp = ml_dsa65.keygen(W.seed);
  W.pk = kp.publicKey;
  W.sk = kp.secretKey;
  W.pkHex = toHex(kp.publicKey);
  W.addrBytes = sha3('MISAKA:address:v1:', kp.publicKey);
  W.address = deriveAddress(kp.publicKey, CHAIN_ID);
  W.genesisHash = computeGenesisHash(CHAIN_ID, [fromHex(GENESIS_PK_HEX)]);
  W.appId = { chain_id: CHAIN_ID, genesis_hash: W.genesisHash };
  return true;
}

// ── API ────────────────────────────────────────────────
async function api(path, opts = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), opts.timeout || 12000);
  try {
    return await fetch(`${API_BASE}${path}`, { ...opts, signal: ctrl.signal });
  } finally { clearTimeout(t); }
}

async function getChainInfo() {
  const r = await api('/v1/chain/info');
  return r.ok ? r.json() : null;
}

async function getUtxos() {
  const r = await api(`/v1/wallet/${W.address}`);
  if (!r.ok) return null;
  return r.json();
}

/** ノードが `error: "..."` の文字列で返すと、従来の !wd.error?.code だけでは残高0として誤採用されていた */
function walletPayloadOk(wd) {
  if (!wd || typeof wd !== 'object') return false;
  if (wd.error != null && wd.error !== false && wd.error !== '') {
    if (typeof wd.error === 'string') return false;
    if (typeof wd.error === 'object') return false;
  }
  return true;
}

function computeBalanceFromUtxos(utxos) {
  if (!Array.isArray(utxos)) return 0;
  return utxos.reduce((s, u) => s + (Number(u.amount) || 0), 0);
}

function spendableBalance() {
  if (!Array.isArray(W.utxos)) return 0;
  return W.utxos.reduce((s, u) => s + (Number(u.amount) || 0), 0);
}

/** 残高・UTXO を反映（payload が無効なら false、DOM も更新しない） */
function applyWalletPayload(wd) {
  if (!walletPayloadOk(wd)) return false;
  const utxos = wd.utxos ?? [];
  let balance = wd.balance;
  if (balance == null || balance === undefined) {
    balance = computeBalanceFromUtxos(utxos);
  } else {
    balance = Number(balance);
  }
  const sum = computeBalanceFromUtxos(utxos);
  if (sum > 0 && balance === 0) balance = sum;

  detectConfirmedTxs(utxos);

  W.utxos = utxos;
  W.balance = balance;
  $('#bal-amount').textContent = fmtMSK(W.balance);
  const sb = spendableBalance();
  $('#send-available').textContent = fmtMSK(sb) + ' MSK';
  const hint = $('#send-funding-hint');
  if (hint) hint.classList.add('hidden');
  return true;
}

function detectConfirmedTxs(newUtxos) {
  if (!Array.isArray(newUtxos)) return;
  const knownHashes = new Set(W.txs.map((t) => t.hash));
  const oldUtxoHashes = new Set((W.utxos || []).map((u) => u.txHash));
  const newUtxoHashes = new Set(newUtxos.map((u) => u.txHash));
  let changed = false;

  // Detect confirmed sends: UTXOs consumed (old UTXO disappeared) matching a pending send
  const confirmedSendIdxs = [];
  for (let i = 0; i < W.pendingSends.length; i++) {
    const ps = W.pendingSends[i];
    if (knownHashes.has(ps.hash)) { confirmedSendIdxs.push(i); continue; }
    // A send is confirmed when the balance changes or enough polls pass
    // Check if any old UTXO that was used as input has disappeared
    const oldIds = new Set((W.utxos || []).map((u) => u.id || `${u.txHash}:${u.index}`));
    const newIds = new Set(newUtxos.map((u) => u.id || `${u.txHash}:${u.index}`));
    const consumed = [...oldIds].some((id) => !newIds.has(id));
    // Also check time-based: if >2 min old, consider confirmed or timed out
    const age = Date.now() - ps.time;
    if (consumed || age > 120_000) {
      W.txs.push({ ...ps });
      confirmedSendIdxs.push(i);
      changed = true;
    }
  }
  if (confirmedSendIdxs.length) {
    W.pendingSends = W.pendingSends.filter((_, i) => !confirmedSendIdxs.includes(i));
  }

  // Detect incoming: new UTXOs appearing
  for (const u of newUtxos) {
    if (!u.txHash || oldUtxoHashes.has(u.txHash) || knownHashes.has(u.txHash)) continue;
    // Check if it's a confirmed faucet
    const pf = W.pendingFaucets.find((f) => f.hash === u.txHash);
    // Skip if it's a change output from our own send
    const isSendChange = W.txs.some((t) => t.type === 'send' && t.hash === u.txHash) ||
                          W.pendingSends.some((s) => s.hash === u.txHash);
    if (isSendChange) continue;
    W.txs.push({
      type: pf ? 'faucet' : 'receive',
      amount: Number(u.amount) || 0,
      hash: u.txHash,
      time: pf ? pf.time : Date.now(),
    });
    changed = true;
  }

  if (changed) {
    const confirmedHashes = new Set(W.txs.map((t) => t.hash));
    W.pendingFaucets = W.pendingFaucets.filter((f) => !confirmedHashes.has(f.hash));
    saveWallet();
    refreshActivity();
  }
}

async function submitTx(tx) {
  const r = await api('/v1/tx/submit', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(tx), timeout: 20000,
  });
  return r.json();
}

async function requestFaucet() {
  if (!W.address) throw new Error('ウォレットが初期化されていません');
  const body = { address: W.address };
  if (W.pkHex) body.spendingPubkey = W.pkHex;
  const r = await api('/api/v1/faucet/request', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body), timeout: 15000,
  });
  const text = await r.text();
  try { return JSON.parse(text); }
  catch (_) { throw new Error(`API応答の解析に失敗 (HTTP ${r.status}): ${text.slice(0, 120)}`); }
}

// ── TX Builder ─────────────────────────────────────────
function selectUtxos(target) {
  const avail = W.utxos.sort((a, b) => b.amount - a.amount);
  const sel = []; let sum = 0;
  for (const u of avail) { sel.push(u); sum += u.amount; if (sum >= target) break; }
  return sum >= target ? { sel, sum } : null;
}

function buildTx(toAddr, amountBase, fee = 0) {
  const total = amountBase + fee;
  const coin = selectUtxos(total);
  if (!coin) {
    const sb = spendableBalance();
    if (sb === 0 && W.balance > 0) {
      throw new Error('送金可能な残高がありません。Faucet から新しいコインを取得してください。');
    }
    throw new Error(`残高不足: ${fmtMSK(total)} MSK 必要（送金可能: ${fmtMSK(sb)} MSK）`);
  }

  const toBytes = fromHex(toAddr.slice(7, 71));
  const payload = {
    version: UTXO_TX_VERSION, tx_type: 'TransparentTransfer',
    inputs: coin.sel.map((u) => ({ utxo_refs: [{ tx_hash: fromHex(u.txHash), output_index: u.outputIndex }] })),
    outputs: [{ amount: amountBase, address: toBytes, spending_pubkey: null }],
    fee, extra: Array.from(W.pk), expiry: 0,
  };
  const change = coin.sum - total;
  if (change > 0) payload.outputs.push({ amount: change, address: W.addrBytes, spending_pubkey: W.pk });

  const encoded = borshSignablePayload(payload);
  const digest = signingDigest(W.appId, encoded);
  const proofs = coin.sel.map(() => ml_dsa65.sign(W.sk, digest));
  const hash = txHash(encoded);

  const fullTx = {
    version: UTXO_TX_VERSION, tx_type: 'TransparentTransfer',
    inputs: coin.sel.map((u, i) => ({
      utxo_refs: [{ tx_hash: Array.from(fromHex(u.txHash)), output_index: u.outputIndex }],
      proof: Array.from(proofs[i]),
    })),
    outputs: payload.outputs.map((o) => ({
      amount: o.amount, address: Array.from(o.address),
      spending_pubkey: o.spending_pubkey ? Array.from(o.spending_pubkey) : null,
    })),
    fee, extra: Array.from(W.pk), expiry: 0,
  };
  return { tx: fullTx, hash: toHex(hash) };
}

// ═══════════════════════════════════════════════════════
// UI Controller
// ═══════════════════════════════════════════════════════

function showView(id) {
  $$('.view').forEach((v) => v.classList.remove('active'));
  const el = $(`#v-${id}`);
  if (el) el.classList.add('active');
}

const VALID_TABS = ['home', 'send', 'receive', 'history'];

function showTab(name, pushHash = true) {
  if (!VALID_TABS.includes(name)) name = 'home';
  $$('.tab').forEach((t) => t.classList.remove('active'));
  $$('.nav-btn').forEach((b) => b.classList.remove('active'));
  const tab = $(`#tab-${name}`);
  const btn = $(`.nav-btn[data-tab="${name}"]`);
  if (tab) tab.classList.add('active');
  if (btn) btn.classList.add('active');
  if (pushHash) history.replaceState(null, '', `#${name}`);
  lucide?.createIcons({ icons: lucide.icons });
}

function openModal(id) { $(`#${id}`).classList.remove('hidden'); }
function closeModal(id) {
  $(`#${id}`).classList.add('hidden');
  if (id === 'modal-qr') stopQrScan();
}

function openTxDetail(tx) {
  const isSend = tx.type === 'send';
  const isFaucet = tx.type === 'faucet';
  const typeLabel = isFaucet ? 'Faucet' : (isSend ? '送金' : (tx.type === 'receive' ? '受取' : (tx.type || '取引')));
  $('#txd-type').textContent = typeLabel;
  const sign = isSend ? '-' : '+';
  $('#txd-amount').textContent = `${sign}${fmtMSK(tx.amount)} MSK`;
  $('#txd-time').textContent = tx.time ? new Date(tx.time).toLocaleString('ja-JP') : '—';
  const h = String(tx.hash || tx.txHash || '').trim();
  const hashEl = $('#txd-hash');
  hashEl.textContent = h || '（記録なし）';
  hashEl.dataset.copy = h;
  const rowTo = $('#txd-row-to');
  if (isSend && tx.to) {
    rowTo.classList.remove('hidden');
    $('#txd-to').textContent = tx.to;
  } else {
    rowTo.classList.add('hidden');
  }

  const statusRow = $('#txd-row-status');
  const heightRow = $('#txd-row-height');
  const linkEl = $('#txd-link');
  statusRow.classList.add('hidden');
  heightRow.classList.add('hidden');
  linkEl.classList.add('hidden');

  if (h) {
    linkEl.href = `/tx.html?tx=${h}`;
    linkEl.classList.remove('hidden');

    api(`/v1/tx/${h}`).then(r => r.ok ? r.json() : null).then(d => {
      if (!d) return;
      if (d.status) {
        const labels = { confirmed: '承認済み', pending: '処理中', unknown: '不明' };
        $('#txd-status').textContent = labels[d.status] || d.status;
        statusRow.classList.remove('hidden');
      }
      if (d.blockHeight != null) {
        $('#txd-height').textContent = Number(d.blockHeight).toLocaleString();
        heightRow.classList.remove('hidden');
      }
    }).catch(() => {});
  }

  openModal('modal-tx-detail');
  lucide?.createIcons({ icons: lucide.icons });
}

function toast(msg, dur = 2500) {
  const el = document.createElement('div');
  el.className = 'toast'; el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), dur);
}

async function copyText(text) {
  const s = String(text ?? '');
  if (!s) {
    toast('コピーする内容がありません');
    return;
  }
  // HTTPS / localhost では Clipboard API が使える
  if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(s);
      toast('コピーしました');
      return;
    } catch (_) { /* フォールバックへ */ }
  }
  // HTTP（IP直アクセス等）では execCommand が必要
  try {
    const ta = document.createElement('textarea');
    ta.value = s;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    ta.style.top = '0';
    ta.setAttribute('autocomplete', 'off');
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    ta.setSelectionRange(0, s.length);
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    if (ok) toast('コピーしました');
    else toast('コピーできませんでした（手動で選択してください）');
  } catch {
    toast('コピーできませんでした');
  }
}

function renderSeedGrid(container, words) {
  container.innerHTML = '';
  words.forEach((w, i) => {
    const el = document.createElement('div');
    el.className = 'seed-word';
    el.innerHTML = `<span class="num">${i + 1}</span><span class="word">${w}</span>`;
    container.appendChild(el);
  });
}

function generateQR(text, container) {
  container.innerHTML = '';
  if (!qrcode) { container.textContent = text; return; }
  const qr = qrcode(0, 'M');
  qr.addData(text);
  qr.make();
  const size = 200;
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');
  const count = qr.getModuleCount();
  const cellSize = Math.floor(size / count);
  canvas.width = canvas.height = cellSize * count;
  ctx.fillStyle = '#fff';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = '#000';
  for (let r = 0; r < count; r++)
    for (let c = 0; c < count; c++)
      if (qr.isDark(r, c)) ctx.fillRect(c * cellSize, r * cellSize, cellSize, cellSize);
  container.appendChild(canvas);
}

// ── Render activity items ──────────────────────────────
function renderTxItem(tx, isPending) {
  const el = document.createElement('div');
  el.className = 'tx-item' + (isPending ? ' tx-pending' : '');
  const isSend = tx.type === 'send';
  const isFaucet = tx.type === 'faucet';
  const iconCls = isFaucet ? 'faucet-icon' : (isSend ? 'sent' : 'received');

  let iconName = 'arrow-down';
  if (isSend) iconName = 'arrow-up';
  if (isFaucet) iconName = 'droplet';
  if (isPending) iconName = 'clock';

  const label = isFaucet ? 'Faucet' : (isSend ? '送金' : '受取');
  const statusBadge = isPending ? '<span class="tx-badge-pending">承認待ち</span>' : '';
  const amtCls = isSend ? 'neg' : 'pos';
  const sign = isSend ? '-' : '+';
  const time = tx.time ? new Date(tx.time).toLocaleString('ja-JP', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '';
  el.innerHTML = `
    <div class="tx-icon ${iconCls}${isPending ? ' pending' : ''}"><i data-lucide="${iconName}"></i></div>
    <div class="tx-info">
      <div class="tx-label">${label} ${statusBadge}</div>
      <div class="tx-addr">${tx.to ? shortAddr(tx.to) : (tx.hash ? tx.hash.slice(0, 16) + '…' : '')}</div>
    </div>
    <div class="tx-right">
      <div class="tx-amount ${amtCls}">${sign}${fmtMSK(tx.amount)} MSK</div>
      <div class="tx-time">${time}</div>
    </div>`;
  if (!isPending) {
    el.setAttribute('role', 'button');
    el.setAttribute('tabindex', '0');
    el.setAttribute('aria-label', `${label}の詳細を表示`);
    el.addEventListener('click', () => openTxDetail(tx));
    el.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        openTxDetail(tx);
      }
    });
  }
  return el;
}

function refreshActivity() {
  const home = $('#home-activity');
  const history = $('#tx-list');
  const pending = [...W.pendingSends, ...W.pendingFaucets.map((f) => ({ type: 'faucet', amount: f.amount, hash: f.hash, time: f.time }))].sort((a, b) => b.time - a.time);
  const confirmed = [...W.txs].reverse();
  const hasTxs = pending.length + confirmed.length > 0;
  for (const container of [home, history]) {
    container.innerHTML = '';
    if (!hasTxs) {
      container.innerHTML = '<div class="empty-state">まだ取引はありません</div>';
    } else {
      const isHome = container === home;
      let count = 0;
      for (const tx of pending) {
        if (isHome && count >= 5) break;
        container.appendChild(renderTxItem(tx, true));
        count++;
      }
      for (const tx of confirmed) {
        if (isHome && count >= 5) break;
        container.appendChild(renderTxItem(tx, false));
        count++;
      }
    }
  }
  lucide?.createIcons({ icons: lucide.icons });
}

/** 残高0のときだけ Faucet 案内を表示 */
function updateFundingHints() {}

async function refreshWalletState() {
  const wd = await getUtxos();
  if (applyWalletPayload(wd)) updateFundingHints();
}

// ── Polling ────────────────────────────────────────────
function startPolling() {
  let errs = 0;
  async function poll() {
    try {
      const ci = await getChainInfo();
      if (ci) {
        W.chainInfo = ci; W.connected = true; errs = 0;
        $('#conn-dot').className = 'conn-dot green';
        $('#bal-sub').textContent = `Block #${(ci.blockHeight ?? 0).toLocaleString()}`;
        $('#s-height').textContent = (ci.blockHeight ?? 0).toLocaleString();
        $('#s-validators').textContent = ci.validatorCount ?? '—';
        $('#s-version').textContent = ci.version ?? '—';
        if (ci.genesisHash) {
          const apiHash = fromHex(ci.genesisHash);
          if (toHex(W.genesisHash) !== ci.genesisHash) {
            W.genesisHash = apiHash;
            W.appId = { chain_id: CHAIN_ID, genesis_hash: apiHash };
          }
        }
      }
      const wd = await getUtxos();
      if (applyWalletPayload(wd)) {
        updateFundingHints();
        refreshActivity();
      }
    } catch (e) {
      errs++;
      if (errs >= 5) {
        $('#conn-dot').className = 'conn-dot red';
        W.connected = false;
      }
    }
  }
  poll();
  W.polling = setInterval(poll, POLL_MS);
}

// ═══════════════════════════════════════════════════════
// QR Scanner
// ═══════════════════════════════════════════════════════
let qrStream = null;
let qrAnimFrame = null;

function startQrScan() {
  openModal('modal-qr');
  const video = $('#qr-video');
  const errMsg = $('#qr-err-msg');
  if (errMsg) errMsg.style.display = 'none';

  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    if (errMsg) {
      errMsg.textContent = 'カメラはHTTPS接続でのみ使用可能です。下のボタンから画像を選んでください。';
      errMsg.style.display = 'block';
    }
    return;
  }

  navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } })
    .then((stream) => {
      qrStream = stream;
      video.srcObject = stream;
      video.play();
      scanQrFrame();
    })
    .catch((e) => {
      if (errMsg) {
        errMsg.textContent = 'カメラにアクセスできません: ' + (e.name || e.message) + '。画像を選んでください。';
        errMsg.style.display = 'block';
      }
    });
}

function scanQrFrame() {
  const video = $('#qr-video');
  if (!video || video.readyState < 2) {
    qrAnimFrame = requestAnimationFrame(scanQrFrame);
    return;
  }
  const canvas = document.createElement('canvas');
  canvas.width = video.videoWidth;
  canvas.height = video.videoHeight;
  const ctx = canvas.getContext('2d');
  ctx.drawImage(video, 0, 0);
  const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  if (typeof jsQR === 'function') {
    const code = jsQR(imgData.data, canvas.width, canvas.height);
    if (code && code.data) {
      let addr = code.data.trim();
      if (addr.startsWith('misaka:')) addr = addr.replace(/^misaka:/, '');
      if (addr.startsWith('misaka1')) {
        $('#inp-to').value = addr;
        toast('アドレスを読み取りました');
        stopQrScan();
        return;
      }
    }
  }
  qrAnimFrame = requestAnimationFrame(scanQrFrame);
}

function stopQrScan() {
  if (qrAnimFrame) { cancelAnimationFrame(qrAnimFrame); qrAnimFrame = null; }
  if (qrStream) { qrStream.getTracks().forEach((t) => t.stop()); qrStream = null; }
  const video = $('#qr-video');
  if (video) video.srcObject = null;
  const modal = $('#modal-qr');
  if (modal && !modal.classList.contains('hidden')) {
    closeModal('modal-qr');
  }
}

function handleQrFileInput(e) {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (ev) => {
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0);
      const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      if (typeof jsQR === 'function') {
        const code = jsQR(imgData.data, canvas.width, canvas.height);
        if (code && code.data) {
          let addr = code.data.trim();
          if (addr.startsWith('misaka:')) addr = addr.replace(/^misaka:/, '');
          if (addr.startsWith('misaka1')) {
            $('#inp-to').value = addr;
            toast('画像からアドレスを読み取りました');
            stopQrScan();
            e.target.value = '';
            return;
          }
        }
        toast('QRコード（misaka1...）が見つかりませんでした');
        e.target.value = '';
      }
    };
    img.src = ev.target.result;
  };
  reader.readAsDataURL(file);
}

// ═══════════════════════════════════════════════════════
// Event Handlers
// ═══════════════════════════════════════════════════════

function setupEvents() {
  // ── Navigation ──
  $$('.nav-btn').forEach((btn) => btn.addEventListener('click', () => showTab(btn.dataset.tab)));
  $$('.qa-btn[data-tab]').forEach((btn) => btn.addEventListener('click', () => showTab(btn.dataset.tab)));
  window.addEventListener('hashchange', () => {
    const t = location.hash.replace('#', '');
    if (VALID_TABS.includes(t)) showTab(t, false);
  });
  $$('.back-btn[data-goto]').forEach((btn) => btn.addEventListener('click', () => showView(btn.dataset.goto)));

  // ── Modals ──
  $('#btn-settings').addEventListener('click', () => openModal('modal-settings'));
  $$('.modal-close').forEach((btn) => btn.addEventListener('click', () => closeModal(btn.dataset.close)));
  $$('.modal-bg').forEach((bg) => bg.addEventListener('click', () => {
    bg.closest('.modal').classList.add('hidden');
  }));

  $('#btn-copy-tx-hash')?.addEventListener('click', (e) => {
    e.stopPropagation();
    const h = $('#txd-hash')?.dataset?.copy;
    if (h) copyText(h);
  });

  // ── Welcome ──
  $('#btn-web3auth').addEventListener('click', handleWeb3Auth);
  $('#btn-create').addEventListener('click', handleCreate);
  $('#btn-import').addEventListener('click', () => showView('import'));
  $('#btn-do-import').addEventListener('click', handleImport);

  // ── Create ──
  $('#btn-copy-seed').addEventListener('click', () => {
    if (W.mnemonic) copyText(W.mnemonic);
  });
  $('#btn-seed-done').addEventListener('click', () => {
    saveWallet();
    initApp();
  });

  // ── Receive ──
  $('#btn-copy-addr').addEventListener('click', () => copyText(W.address));
  $('#btn-share').addEventListener('click', async () => {
    if (navigator.share) {
      try { await navigator.share({ text: W.address }); } catch {}
    } else {
      copyText(W.address);
    }
  });

  // ── Send ──
  $('#btn-max').addEventListener('click', () => {
    $('#inp-amount').value = fmtMSK(spendableBalance());
  });
  $('#btn-send').addEventListener('click', handleSendConfirm);
  $('#btn-confirm-tx').addEventListener('click', handleSendExecute);
  $('#btn-scan-qr').addEventListener('click', startQrScan);
  const qrInput = $('#qr-file-input');
  if (qrInput) qrInput.addEventListener('change', handleQrFileInput);

  // ── Faucet ──
  $('#btn-faucet').addEventListener('click', handleFaucet);

  // ── Settings ──
  $('#btn-show-seed').addEventListener('click', () => {
    if (!W.mnemonic) {
      toast('ソーシャルログインのためシードフレーズはありません');
      return;
    }
    renderSeedGrid($('#reveal-grid'), W.mnemonic.split(' '));
    closeModal('modal-settings');
    openModal('modal-seed');
  });
  $('#btn-copy-revealed').addEventListener('click', () => {
    if (W.mnemonic) copyText(W.mnemonic);
  });
  $('#btn-logout').addEventListener('click', () => {
    if (confirm('ウォレットを削除(ログアウト)しますか？')) {
      deleteWallet();
    }
  });
}

// ── Web3Auth Login ──
async function handleWeb3Auth() {
  try {
    $('#btn-web3auth').disabled = true;
    toast('Web3Auth を準備しています…');
    const w3a = await ensureWeb3Auth();
    if (!w3a) {
      toast('Web3Auth の読み込みに失敗しました。ネットワークを確認してください。');
      return;
    }
    const provider = await w3a.connect();
    if (!provider) {
      throw new Error("プロバイダーがありません");
    }
    const pkHex = await provider.request({ method: "private_key" });
    let pkStr = pkHex;
    if (pkStr.startsWith("0x")) pkStr = pkStr.slice(2);
    
    // We need 32 bytes (64 hex chars) for the seed. Web3Auth private keys are typically 32 bytes.
    W.seed = fromHex(pkStr.padStart(64, '0'));
    W.mnemonic = null; // No mnemonic for social login
    
    if (deriveKeys()) {
      saveWallet();
      initApp();
      toast('ログイン成功');
    } else {
      toast('鍵の生成に失敗しました');
    }
  } catch (e) {
    console.error(e);
    toast('ログインに失敗しました: ' + (e.message || e));
  } finally {
    $('#btn-web3auth').disabled = false;
  }
}

// ── Create wallet ──
function handleCreate() {
  if (!bip39) { toast('BIP39 モジュールが読み込めませんでした'); return; }
  const mnemonic = bip39.generateMnemonic(bip39.wordlist, 256);
  const entropy = bip39.mnemonicToEntropy(mnemonic, bip39.wordlist);
  W.seed = entropy;
  W.mnemonic = mnemonic;
  deriveKeys();
  renderSeedGrid($('#seed-grid'), mnemonic.split(' '));
  showView('create');
}

// ── Import wallet ──
function handleImport() {
  const words = $('#import-words').value.trim().toLowerCase().replace(/\s+/g, ' ');
  const errEl = $('#import-error');
  if (!bip39) { errEl.textContent = 'BIP39 モジュールが読み込めませんでした'; return; }
  if (!bip39.validateMnemonic(words, bip39.wordlist)) {
    errEl.textContent = '無効なシードフレーズです。24個の正しい英単語を入力してください。';
    return;
  }
  errEl.textContent = '';
  const entropy = bip39.mnemonicToEntropy(words, bip39.wordlist);
  W.seed = entropy;
  W.mnemonic = words;
  deriveKeys();
  saveWallet();
  initApp();
}

// ── Send: show confirmation ──
let pendingTx = null;
function handleSendConfirm() {
  const to = $('#inp-to').value.trim();
  const amt = parseFloat($('#inp-amount').value);
  const statusEl = $('#send-status');
  statusEl.textContent = ''; statusEl.className = 'status-msg';

  if (W.balance <= 0) {
    statusEl.textContent = '残高がありません。ホームの「テストコインを受け取る」または Faucet を先に実行してください。';
    statusEl.className = 'status-msg err';
    return;
  }

  if (!to.startsWith('misaka1') || to.length !== 75) {
    statusEl.textContent = 'アドレスが無効です (misaka1... 75文字)';
    statusEl.className = 'status-msg err'; return;
  }
  if (!amt || amt <= 0) {
    statusEl.textContent = '金額を入力してください';
    statusEl.className = 'status-msg err'; return;
  }
  if (to === W.address) {
    statusEl.textContent = '自分自身には送金できません';
    statusEl.className = 'status-msg err'; return;
  }
  const amtBase = Math.round(amt * 1e9);
  const sb = spendableBalance();
  if (sb === 0 && W.balance > 0) {
    statusEl.textContent = '送金可能な残高がありません。Faucet から新しいコインを取得してください。';
    statusEl.className = 'status-msg err'; return;
  }
  if (amtBase > sb) {
    statusEl.textContent = `残高不足（送金可能: ${fmtMSK(sb)} MSK）`;
    statusEl.className = 'status-msg err'; return;
  }
  pendingTx = { to, amtBase };
  $('#c-to').textContent = shortAddr(to);
  $('#c-to').title = to;
  $('#c-amount').textContent = fmtMSK(amtBase) + ' MSK';
  $('#c-total').textContent = fmtMSK(amtBase) + ' MSK';
  openModal('modal-confirm');
}

// ── Send: execute ──
async function handleSendExecute() {
  if (!pendingTx) return;
  const btn = $('#btn-confirm-tx');
  btn.disabled = true; btn.innerHTML = '<i data-lucide="loader"></i> 署名中…';
  lucide?.createIcons({ icons: lucide.icons });
  try {
    const wd = await getUtxos();
    if (wd && walletPayloadOk(wd)) applyWalletPayload(wd);

    const { tx, hash } = buildTx(pendingTx.to, pendingTx.amtBase);
    btn.innerHTML = '<i data-lucide="loader"></i> 送信中…';
    lucide?.createIcons({ icons: lucide.icons });
    const resp = await submitTx(tx);
    closeModal('modal-confirm');
    if (resp.accepted) {
      W.pendingSends.push({ type: 'send', to: pendingTx.to, amount: pendingTx.amtBase, hash, time: Date.now() });
      saveWallet();
      refreshActivity();
      toast('送金リクエストを送信しました。承認後に反映されます');
      $('#inp-to').value = ''; $('#inp-amount').value = '';
      $('#send-status').textContent = '';
      showTab('home');
    } else {
      const m = resp.error?.message || resp.error || 'rejected';
      $('#send-status').textContent = `送金失敗: ${m}`;
      $('#send-status').className = 'status-msg err';
    }
  } catch (e) {
    closeModal('modal-confirm');
    $('#send-status').textContent = `エラー: ${e.message}`;
    $('#send-status').className = 'status-msg err';
  }
  btn.disabled = false; btn.textContent = '署名して送金';
  pendingTx = null;
}

/** API の error が string / { message } / { code, message } などのときに人が読める文字へ */
function formatErrorPayload(x) {
  if (x == null || x === '') return '';
  const t = typeof x;
  if (t === 'string' || t === 'number' || t === 'boolean') return String(x);
  if (t === 'object') {
    if (typeof x.message === 'string') return x.message;
    if (typeof x.msg === 'string') return x.msg;
    if (typeof x.code === 'string' && typeof x.message === 'string') return `${x.code}: ${x.message}`;
    if (typeof x.code === 'string' && typeof x.detail === 'string') return `${x.code}: ${x.detail}`;
    try {
      const s = JSON.stringify(x);
      return s.length > 280 ? s.slice(0, 280) + '…' : s;
    } catch {
      return '不明なエラー内容';
    }
  }
  return String(x);
}

function formatFaucetError(d) {
  if (!d || typeof d !== 'object') return '不明なエラー';
  const parts = [];
  const err = formatErrorPayload(d.error) || formatErrorPayload(d.message);
  if (err) parts.push(err);
  if (d.status === 'rate_limited' && d.retry_after != null) {
    parts.push(`再試行まで約 ${d.retry_after} 秒`);
  }
  if (d.status === 'timeout' && d.retry_after != null) {
    parts.push(`しばらくしてから再試行してください（目安 ${d.retry_after} 秒）`);
  }
  if (parts.length) return parts.join(' — ');
  const st = formatErrorPayload(d.status);
  if (st && st !== 'failed') return st;
  return 'リクエストに失敗しました';
}

// ── Faucet ──
async function handleFaucet() {
  const btn = $('#btn-faucet');
  const span = btn?.querySelector('span:last-child');
  if (span) span.textContent = '送信中…';
  try {
    const d = await requestFaucet();
    const ok = d && (d.status === 'success' || d.tx_hash);
    if (ok) {
      const amt = d.amount ?? 10_000_000_000;
      toast(`Faucet リクエスト送信済み。承認後に残高と履歴に反映されます`);
      if (d.tx_hash) {
        W.pendingFaucets.push({ hash: d.tx_hash, amount: amt, time: Date.now() });
        saveWallet();
        refreshActivity();
      }
      await refreshWalletState();
      [1000, 3000, 8000, 15000, 30000, 60000].forEach((ms) => {
        setTimeout(() => refreshWalletState(), ms);
      });
    } else {
      const msg = formatFaucetError(d);
      if (d && d.status === 'rate_limited') {
        toast(
          `Faucet: ${msg}。クールダウン中は新しいコインは付与されません。` +
            '前回の配布が成功していれば、チェーン反映まで数十秒〜1分で残高が増えます（この画面は自動更新されます）。',
        );
      } else {
        toast(`Faucet: ${msg}`);
      }
    }
  } catch (e) {
    toast(`Faucet エラー: ${e.message || e}`);
  }
  if (span) span.textContent = 'Faucet';
}

// ═══════════════════════════════════════════════════════
// Init
// ═══════════════════════════════════════════════════════

async function initApp() {
  $('#addr-text').textContent = W.address;
  generateQR(W.address, $('#qr-box'));
  refreshActivity();

  try { await refreshWalletState(); } catch (_) {}
  updateFundingHints();

  showView('app');

  const hashTab = location.hash.replace('#', '');
  showTab(VALID_TABS.includes(hashTab) ? hashTab : 'home', true);

  startPolling();
  lucide?.createIcons({ icons: lucide.icons });
}

async function main() {
  const deps = await loadDeps();
  if (!deps.crypto || !deps.pq) {
    showView('welcome');
    toast('暗号モジュールの読み込みに失敗しました');
    return;
  }
  if (!deps.bip39) {
    showView('welcome');
    toast('ウォレット用モジュール（BIP39）の読み込みに失敗しました');
    return;
  }
  setupEvents();
  if (loadWallet() && W.seed) {
    if (!deriveKeys()) {
      showView('welcome');
      toast('ウォレットの復元に失敗しました');
      return;
    }
    await initApp();
  } else {
    showView('welcome');
  }
  lucide?.createIcons({ icons: lucide.icons });
}

main();
