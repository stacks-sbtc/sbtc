import { afterEach, describe, expect, it, vi } from "vitest";
import { bufferCV, listCV, serializeCV, tupleCV, uintCV } from "@stacks/transactions";
import {
  SBTC_DEPLOYERS,
  buildV2DepositScript,
  computeDepositAddress,
  fetchRegistrySignerData,
  findWalletValues,
  formatAsmLines,
  hexToBytes,
  normalizeXOnlyPublicKey,
  parseRegistrySignerData,
  requireRegistryField,
  scriptToAsm,
} from "./deposit";

const KEY = "033920f589c2b367400732d2dd61d11b300ad95b2b1bbf008eabcf8cddfee0c12c";
const VECTOR_KEY = "026c44dfe47941b0271c642c549d9a763afce7c6b0495c72f1a32c2f09898ea3df";
const MAINNET_RECIPIENT = "SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4";
const BURN_RECIPIENT = "SP000000000000000000002Q6VF78";
// Identity keys for the secret keys [i; 32] with i from 1 through 16. The
// expected v2 scripts and addresses below were generated with the sbtc
// crate, whose stability tests pin the same 2-of-3 commitment and address.
const IDENTITY_KEYS = [
  "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
  "024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766",
  "02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337",
  "03462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b",
  "0362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7",
  "03f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a",
  "02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f",
  "03f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661b",
  "0256b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967",
  "03f76a39d05686e34a4420897e359371836145dd3973e3982568b60f8433adde6e",
  "02552c630b64b54bf50210c9e253d38bd4949c72e22873500f6285c2bede312a84",
  "030f0fb9a244ad31a369ee02b7abfbbb0bfa3812b9a39ed93346d03d67d412d177",
  "022f1b310f4c065331bc0d79ba4661bb9822d67d7c4a1b0a1892e1fd0cd23aa68d",
  "0299c2aa85d2b21a62f396907a802a58e521dafd5bddaccbd72786eea189bc4dc9",
  "021a7a569e91dbf60581509c7fc946d1003b60c7dee85299538db6353538d59574",
  "03a92c9b7cac68758de5783ed8e5123598e4ad137091e42987d3bad8a08e35bf3d",
];

describe("deposit address computation", () => {
  const validInput = {
    network: "mainnet" as const,
    version: "v1" as const,
    recipient: MAINNET_RECIPIENT,
    maxFee: 80_000,
    lockTime: 950,
    reclaimPublicKey: KEY,
    signersPublicKey: KEY,
  };

  it.each(["reclaimPublicKey", "signersPublicKey"] as const)(
    "rejects invalid curve points in %s",
    (field) => {
      for (const invalidKey of ["00".repeat(32), "ff".repeat(32), `02${"00".repeat(32)}`]) {
        expect(() => computeDepositAddress({ ...validInput, [field]: invalidKey })).toThrow(
          "valid secp256k1 public key",
        );
      }
    },
  );

  it.each([".", ".foo.bar", ".123", ".bad name", ".foo!", `.${"a".repeat(41)}`])(
    "rejects malformed contract suffix %s",
    (suffix) => {
      expect(() =>
        computeDepositAddress({ ...validInput, recipient: MAINNET_RECIPIENT + suffix }),
      ).toThrow("valid Stacks principal");
    },
  );

  it("accepts a valid contract principal and checks the address checksum", () => {
    expect(
      computeDepositAddress({ ...validInput, recipient: `${MAINNET_RECIPIENT}.my-contract_1` })
        .address,
    ).toMatch(/^bc1p/);
    expect(() =>
      computeDepositAddress({ ...validInput, recipient: `${MAINNET_RECIPIENT.slice(0, -1)}5` }),
    ).toThrow();
  });

  it("accepts compressed and x-only keys", () => {
    expect(normalizeXOnlyPublicKey(`0x${KEY}`)).toBe(KEY.slice(2));
    expect(normalizeXOnlyPublicKey(KEY.slice(2))).toBe(KEY.slice(2));
  });

  it("builds the same address from a public key and the resulting full script", () => {
    const standard = computeDepositAddress({
      network: "mainnet",
      version: "v1",
      recipient: MAINNET_RECIPIENT,
      maxFee: 80_000,
      lockTime: 950,
      reclaimPublicKey: KEY,
      signersPublicKey: KEY,
    });
    const advanced = computeDepositAddress({
      network: "mainnet",
      version: "v1",
      recipient: MAINNET_RECIPIENT,
      maxFee: 80_000,
      reclaimScript: standard.reclaimScript,
      signersPublicKey: KEY,
    });
    expect(advanced).toEqual(standard);
    expect(standard.address).toMatch(/^bc1p/);
    expect(scriptToAsm(standard.depositScript)).toMatch(/^OP_PUSHBYTES_\d+ /);
    expect(scriptToAsm(standard.depositScript)).toContain("OP_CHECKSIG");
    expect(scriptToAsm(standard.reclaimScript)).toBe(
      `OP_PUSHBYTES_2 b603 OP_CHECKSEQUENCEVERIFY OP_DROP OP_PUSHBYTES_32 ${KEY.slice(2)} OP_CHECKSIG`,
    );
  });

  it("renders push opcodes and minimally encoded script numbers", () => {
    expect(scriptToAsm("03ffff00b26a")).toBe(
      "OP_PUSHBYTES_3 ffff00 OP_CHECKSEQUENCEVERIFY OP_RETURN",
    );
  });

  it("selects a P2WPKH address rather than a Taproot address", () => {
    expect(
      findWalletValues(
        [
          { symbol: "BTC", address: `bc1p${"q".repeat(58)}`, publicKey: KEY },
          {
            symbol: "BTC",
            purpose: "payment",
            address: `bc1q${"q".repeat(38)}`,
            publicKey: KEY,
          },
          { symbol: "STX", address: MAINNET_RECIPIENT, publicKey: KEY },
        ],
        "mainnet",
      ),
    ).toEqual({ recipient: MAINNET_RECIPIENT, reclaimPublicKey: KEY.slice(2) });
  });

  it("rejects a recipient from the wrong network", () => {
    expect(() =>
      computeDepositAddress({
        network: "testnet",
        version: "v1",
        recipient: MAINNET_RECIPIENT,
        maxFee: 80_000,
        lockTime: 950,
        reclaimPublicKey: KEY,
        signersPublicKey: KEY,
      }),
    ).toThrow("Enter a testnet Stacks recipient.");
  });

  it("uses the current testnet sBTC deployer", () => {
    expect(SBTC_DEPLOYERS.testnet).toBe("SN3VMHXEN64ZZF71JQ5VESXDWTR301XTTXGF4J8F1");
  });

  it("constructs Stacks testnet deposits on Bitcoin regtest", () => {
    const result = computeDepositAddress({
      network: "testnet",
      version: "v1",
      recipient: SBTC_DEPLOYERS.testnet,
      maxFee: 80_000,
      lockTime: 950,
      reclaimPublicKey: KEY,
      signersPublicKey: KEY,
    });
    expect(result.address).toMatch(/^bcrt1p/);
  });

  it("constructs a version 2 deposit from registry signer keys", () => {
    const result = computeDepositAddress({
      network: "mainnet",
      version: "v2",
      recipient: BURN_RECIPIENT,
      maxFee: 80_000,
      lockTime: 950,
      reclaimPublicKey: VECTOR_KEY,
      signerIdentityKeys: [VECTOR_KEY],
      signaturesRequired: 1,
    });

    expect(result.version).toBe("v2");
    expect(result.depositScript).toBe(
      "82012088a820bc94e3d783ea495b3e32378c650a0d3ebcf1db9289b9457d8fdd49e069e35392882067b65731c55d6561b0530377187f9147d6808dac379332eb8950420d7335abfcac519c",
    );
    expect(result.address).toBe("bc1prnf9r6c0y6emg36ks53yk8943c7esm2mdnsuz0y0eq95p8sk2aasf4waxx");
    expect(formatAsmLines(scriptToAsm(result.depositScript))).toBe(
      "OP_SIZE OP_PUSHBYTES_1 20 OP_EQUALVERIFY\n" +
        "OP_SHA256 OP_PUSHBYTES_32 bc94e3d783ea495b3e32378c650a0d3ebcf1db9289b9457d8fdd49e069e35392 OP_EQUALVERIFY\n" +
        "OP_PUSHBYTES_32 67b65731c55d6561b0530377187f9147d6808dac379332eb8950420d7335abfc OP_CHECKSIG\n" +
        "OP_1 OP_NUMEQUAL",
    );
    expect(result).toMatchObject({
      signingKeys: ["67b65731c55d6561b0530377187f9147d6808dac379332eb8950420d7335abfc"],
      signaturesRequired: 1,
    });
  });

  it("matches the Rust 2-of-3 vector regardless of key order or repeats", () => {
    const [first, second, third] = IDENTITY_KEYS as [string, string, string];
    const result = computeDepositAddress({
      network: "mainnet",
      version: "v2",
      recipient: `${BURN_RECIPIENT}.my-contract`,
      maxFee: 123_456,
      lockTime: 950,
      reclaimPublicKey: first,
      signerIdentityKeys: [third, first, second, first],
      signaturesRequired: 2,
    });

    expect(result.depositScript).toBe(
      "82012088a820605806257b04557450ba77a3c9b09ea07dd3f20dd54f357851e3894fc7a1809f88" +
        "20374bfe83198f423d763ddcad92837229b219117750cf8eee106f59f09ebac157ac" +
        "20b08d2faade97ce5b7159fc49ed3a98ebfde9dcfe70ba6aaa614da225f4fcf8a6ba" +
        "20c4a51ca195d4b7fe6307de43a6dc7758eb60475fabe82862bc4299350c09c21cba529c",
    );
    expect(result.reclaimScript).toBe(
      "02b603b275201b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fac",
    );
    expect(result.address).toBe("bc1pr376ygws82t4p999k5q2p2zn6ld7xnw30fmgcd9czvpp920jlxtsqryays");
    expect(result).toMatchObject({
      version: "v2",
      signingKeys: [
        "374bfe83198f423d763ddcad92837229b219117750cf8eee106f59f09ebac157",
        "b08d2faade97ce5b7159fc49ed3a98ebfde9dcfe70ba6aaa614da225f4fcf8a6",
        "c4a51ca195d4b7fe6307de43a6dc7758eb60475fabe82862bc4299350c09c21c",
      ],
      signaturesRequired: 2,
    });
  });

  it("checks the threshold against the distinct signer keys", () => {
    expect(() =>
      buildV2DepositScript({
        maxFee: 80_000,
        recipient: MAINNET_RECIPIENT,
        signerIdentityKeys: [KEY, KEY],
        signaturesRequired: 2,
      }),
    ).toThrow(/threshold/);
  });

  it("decodes single-line ASM and formats it one clause per line", () => {
    const asm = scriptToAsm("0101750102ac");
    expect(asm).toBe("OP_PUSHBYTES_1 01 OP_DROP OP_PUSHBYTES_1 02 OP_CHECKSIG");
    expect(formatAsmLines(asm)).toBe("OP_PUSHBYTES_1 01 OP_DROP\nOP_PUSHBYTES_1 02 OP_CHECKSIG");
  });

  it("matches the Rust 12-of-16 and 16-of-16 vectors", () => {
    const build = (signaturesRequired: number) =>
      computeDepositAddress({
        network: "testnet",
        version: "v2",
        recipient: "ST000000000000000000002AMW42H",
        maxFee: 1,
        lockTime: 950,
        reclaimPublicKey: IDENTITY_KEYS[0]!,
        signerIdentityKeys: IDENTITY_KEYS,
        signaturesRequired,
      });
    const keyScript =
      "82012088a8206fe7396c40c285ee8ef142fe128407552319d283394789d93eeaed3b1270129b8820" +
      "28fbfd329e046c9febc1d28c380a9abcef45c6da06efaaaa0826a409652039adac20374bfe83198f" +
      "423d763ddcad92837229b219117750cf8eee106f59f09ebac157ba2037cd8678ca096b78ae1d9bfc" +
      "424e496f59ed04c6bcecc5dad18b826c683023d5ba20481768ff03a761228b8cfe5855182a632d80" +
      "9031f0cb08a7be0b82bd4bf50f58ba207576a4df940e91f897122c7b358076371dd65bc63bf3fc9e" +
      "a77b1c6651b48e0fba2076f4a91cdb279f2ba86a4ad18b27be49da84971b8314d76b4419a3da52ed" +
      "8a97ba20774e1a9838e6c578890e50a436e3f8acd2ab9a71d41054800f3e1ec8306763ebba209978" +
      "a5e48fa48c573245c4283a8fca15afe288a9a9579fceb643f2cd69d51009ba209fb63b04482dbb8d" +
      "b0985dbc65745c0f99aa9755183c0d90426b18d9283cf6f7ba20b08d2faade97ce5b7159fc49ed3a" +
      "98ebfde9dcfe70ba6aaa614da225f4fcf8a6ba20c43e460c1505f949aa70a70103ad6a92994b960b" +
      "0d58d25cb51de99f0070b295ba20c4a51ca195d4b7fe6307de43a6dc7758eb60475fabe82862bc42" +
      "99350c09c21cba20d0b7e52a845c85ad60b491da548a39acf0febf8f240de014a690b0bf909eddf7" +
      "ba20d4af03ec9c2a90720d963abcd6a2e284962334ff81d6c6db8b584dbe60007e26ba20e0ef6a3a" +
      "a875980599f4474e65fb963a175d6dbe6e3aac8de0be6ebe632c385dba20f65811f817ff007f4baa" +
      "9d4c1908ccb27c17d3acdea678be2d1b8af376257253ba";
    expect(build(12)).toMatchObject({
      depositScript: `${keyScript}5c9c`,
      address: "bcrt1p3aqlsulcsqwnuyhlkar0cm8mn8ewl0ugsm6jeprtf8ct6uk5kd8qv2anly",
    });
    expect(build(16)).toMatchObject({
      depositScript: `${keyScript}609c`,
      address: "bcrt1pym7durzeqag27pgkm8mfs78ngh4kst9u2g5ujj5x8tddamsc5pfscg5t5w",
    });
  });

  it("rejects more than 16 signer keys", () => {
    expect(() =>
      buildV2DepositScript({
        maxFee: 1,
        recipient: MAINNET_RECIPIENT,
        signerIdentityKeys: [...IDENTITY_KEYS, KEY],
        signaturesRequired: 12,
      }),
    ).toThrow("Version 2 deposits allow at most 16 signer keys.");
  });

  it("reports unusable registry fields as registry problems", () => {
    const data = parseRegistrySignerData(
      tupleCV({
        "current-aggregate-pubkey": bufferCV(hexToBytes(`02${"00".repeat(32)}`)),
        "current-signer-set": listCV([bufferCV(hexToBytes(`03${"00".repeat(32)}`))]),
        "current-signature-threshold": uintCV(1),
      }),
    );
    expect(() => requireRegistryField(data.aggregatePublicKey)).toThrow(
      "The sBTC registry aggregate key is not a valid public key.",
    );
    expect(() => requireRegistryField(data.keySet)).toThrow(
      "The sBTC registry signer set contains an invalid public key.",
    );
  });

  it("parses the aggregate key, signer set and threshold", () => {
    const signerSet = listCV([bufferCV(hexToBytes(KEY)), bufferCV(hexToBytes(KEY))]);
    const v1 = parseRegistrySignerData(
      tupleCV({
        "current-aggregate-pubkey": bufferCV(hexToBytes(KEY)),
        "current-signer-set": signerSet,
        "current-signature-threshold": uintCV(1),
      }),
    );
    expect(v1).toEqual({
      aggregatePublicKey: KEY.slice(2),
      keySet: { signerIdentityKeys: [KEY], signaturesRequired: 1 },
    });

    // After the first key rotation with v1 signing disabled, the registry
    // stores a block-hash marker instead of an aggregate key.
    const v2 = parseRegistrySignerData(
      tupleCV({
        "current-aggregate-pubkey": bufferCV(hexToBytes(`ff${"2a".repeat(32)}`)),
        "current-signer-set": signerSet,
        "current-signature-threshold": uintCV(1),
      }),
    );
    expect(v2).toEqual({
      aggregatePublicKey: {
        error:
          "The sBTC registry no longer has a version 1 aggregate key. Choose version 2 or enter an aggregate public key.",
      },
      keySet: { signerIdentityKeys: [KEY], signaturesRequired: 1 },
    });
  });

  it("keeps the v1 aggregate key when the registry key set is unusable", () => {
    const data = parseRegistrySignerData(
      tupleCV({
        "current-aggregate-pubkey": bufferCV(hexToBytes(KEY)),
        "current-signer-set": listCV([]),
        "current-signature-threshold": uintCV(0),
      }),
    );
    expect(requireRegistryField(data.aggregatePublicKey)).toBe(KEY.slice(2));
    expect(() => requireRegistryField(data.keySet)).toThrow(/threshold is invalid/);
  });
});

describe("registry fetch", () => {
  afterEach(() => vi.unstubAllGlobals());

  const respond = (status: number, body: unknown) =>
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(JSON.stringify(body), { status })),
    );

  it("reads the registry signer data", async () => {
    respond(200, {
      okay: true,
      result: serializeCV(
        tupleCV({
          "current-aggregate-pubkey": bufferCV(hexToBytes(KEY)),
          "current-signer-set": listCV([bufferCV(hexToBytes(KEY))]),
          "current-signature-threshold": uintCV(1),
        }),
      ),
    });
    const data = await fetchRegistrySignerData("mainnet", "https://api.example/");
    expect(data.aggregatePublicKey).toBe(KEY.slice(2));
    expect(vi.mocked(globalThis.fetch).mock.calls[0]?.[0]).toBe(
      `https://api.example/v2/contracts/call-read/${SBTC_DEPLOYERS.mainnet}/sbtc-registry/get-current-signer-data`,
    );
  });

  it("reports HTTP errors", async () => {
    respond(429, { error: "rate limited" });
    await expect(fetchRegistrySignerData("mainnet", "https://api.example")).rejects.toThrow(
      "The Stacks API returned HTTP 429 for the sBTC registry.",
    );
  });

  it("reports failed read-only calls", async () => {
    respond(200, { okay: false, cause: "Unchecked(NoSuchContract)" });
    await expect(fetchRegistrySignerData("testnet", "https://api.example")).rejects.toThrow(
      "The Stacks API could not read the sBTC registry: Unchecked(NoSuchContract)",
    );
  });

  it("reports unreachable APIs", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    await expect(fetchRegistrySignerData("mainnet", "https://api.example")).rejects.toThrow(
      "Could not reach the Stacks API at https://api.example.",
    );
  });
});
