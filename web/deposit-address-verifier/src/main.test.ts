// @vitest-environment jsdom
import { readFile } from "node:fs/promises";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fetchRegistrySignerData } from "./deposit";

vi.mock("./deposit", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./deposit")>()),
  fetchRegistrySignerData: vi.fn(),
}));

const KEY = "033920f589c2b367400732d2dd61d11b300ad95b2b1bbf008eabcf8cddfee0c12c";
const RECIPIENT = "SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4";
const field = (id: string) => document.querySelector<HTMLInputElement>(`#${id}`)!;
const element = (id: string) => document.querySelector<HTMLElement>(`#${id}`)!;
const form = () => document.querySelector<HTMLFormElement>("#verifier-form")!;
const toggle = () => document.querySelector<HTMLButtonElement>("#advanced-toggle")!.click();
const selectMode = (mode: "key" | "script") => {
  document.querySelector<HTMLInputElement>(`input[name="reclaimMode"][value="${mode}"]`)!.click();
};

let removeWindowListeners = () => {};
beforeEach(async () => {
  vi.resetModules();
  vi.mocked(fetchRegistrySignerData).mockReset();
  vi.mocked(fetchRegistrySignerData).mockResolvedValue({
    aggregatePublicKey: KEY.slice(2),
    keySet: { signerIdentityKeys: [KEY], signaturesRequired: 1 },
  });
  document.body.innerHTML = await readFile("index.html", "utf8");
  const listeners = vi.spyOn(window, "addEventListener");
  removeWindowListeners = () => {
    for (const [type, listener, options] of listeners.mock.calls) {
      window.removeEventListener(type, listener, options);
    }
  };
  await import("./main");
});
afterEach(() => {
  removeWindowListeners();
  vi.restoreAllMocks();
});

function fillKeyMode(): void {
  field("recipient").value = RECIPIENT;
  field("reclaim-key").value = KEY;
}

function expectExpanded(): void {
  expect(element("advanced-fields").hidden).toBe(false);
  expect(element("advanced-toggle").getAttribute("aria-expanded")).toBe("true");
  expect(element("advanced-toggle").lastElementChild!.textContent).toBe("−");
}

describe("constructor form", () => {
  it("surfaces an empty script after switching modes and collapsing advanced options", () => {
    toggle();
    selectMode("script");
    toggle();
    form().requestSubmit();
    expectExpanded();
    expect(element("form-error").hidden).toBe(false);
    expect(element("form-error").textContent).not.toBe("");
    expect(element("result").hidden).toBe(true);
    expect(fetchRegistrySignerData).not.toHaveBeenCalled();
  });

  it.each([
    ["reclaim-script", ""],
    ["stacks-api", "not a URL"],
    ["max-fee", "-1"],
  ])("reveals and reports an invalid collapsed %s field", (id, value) => {
    fillKeyMode();
    toggle();
    if (id === "reclaim-script") selectMode("script");
    field(id).value = value;
    toggle();
    form().requestSubmit();
    expectExpanded();
    expect(element("form-error").hidden).toBe(false);
    expect(element("form-error").textContent).toBe(field(id).validationMessage);
    expect(element("result").hidden).toBe(true);
  });

  it("enables and requires only the fields for the selected reclaim mode", () => {
    toggle();
    for (const mode of ["key", "script", "key"] as const) {
      selectMode(mode);
      const scriptMode = mode === "script";
      for (const id of ["reclaim-key", "lock-time"]) {
        expect(field(id).required).toBe(!scriptMode);
        expect(field(id).disabled).toBe(scriptMode);
      }
      expect(field("reclaim-script").required).toBe(scriptMode);
      expect(field("reclaim-script").disabled).toBe(!scriptMode);
      expect(element("public-key-fields").hidden).toBe(scriptMode);
      expect(element("advanced-lock-time-field").hidden).toBe(scriptMode);
      expect(element("script-field").hidden).toBe(!scriptMode);
    }
  });

  it.each(["key", "script"] as const)(
    "computes with valid collapsed %s inputs and invalidates on edit",
    async (mode) => {
      fillKeyMode();
      if (mode === "script") {
        toggle();
        selectMode(mode);
        field("reclaim-script").value = "51";
        field("reclaim-key").value = "";
        toggle();
      }
      form().requestSubmit();
      await vi.waitFor(() => expect(element("result").hidden).toBe(false));
      expect(element("form-error").hidden).toBe(true);
      expect(element("deposit-address").textContent).toMatch(/^bc1p/);
      expect(element("result-version").textContent).toBe("Version 1");
      expect(element("advanced-fields").hidden).toBe(true);
      field("recipient").dispatchEvent(new Event("input", { bubbles: true }));
      expect(element("result").hidden).toBe(true);
      expect(element("empty-result").hidden).toBe(false);
    },
  );

  it("builds a version 2 address from the registry signer set", async () => {
    fillKeyMode();
    field("deposit-version").value = "v2";
    field("deposit-version").dispatchEvent(new Event("change", { bubbles: true }));
    expect(element("signers-key-field").hidden).toBe(true);
    expect(field("signers-key").disabled).toBe(true);

    form().requestSubmit();

    await vi.waitFor(() => expect(element("result").hidden).toBe(false));
    expect(element("result-version").textContent).toBe("Version 2");
    expect(element("result-signers-label").textContent).toBe(
      "Signers’ derived Bitcoin keys (1 of 1 required)",
    );
    expect(element("deposit-script-asm").textContent).toMatch(/^OP_SIZE/);
    expect(element("deposit-script-asm").textContent).toContain("OP_EQUALVERIFY\n");

    field("deposit-version").value = "v1";
    field("deposit-version").dispatchEvent(new Event("change", { bubbles: true }));
    expect(element("signers-key-field").hidden).toBe(false);
    expect(field("signers-key").disabled).toBe(false);
  });

  it("reports a registry without a version 1 aggregate key", async () => {
    const message =
      "The sBTC registry no longer has a version 1 aggregate key. Choose version 2 or enter an aggregate public key.";
    vi.mocked(fetchRegistrySignerData).mockResolvedValue({
      aggregatePublicKey: { error: message },
      keySet: { signerIdentityKeys: [KEY], signaturesRequired: 1 },
    });
    fillKeyMode();

    form().requestSubmit();

    await vi.waitFor(() => expect(element("form-error").hidden).toBe(false));
    expect(element("form-error").textContent).toBe(message);
    expect(element("result").hidden).toBe(true);
    expect(field("deposit-version").value).toBe("v1");
  });

  it("ignores a registry response that arrives after the network changes", async () => {
    let respond!: (data: Awaited<ReturnType<typeof fetchRegistrySignerData>>) => void;
    vi.mocked(fetchRegistrySignerData).mockReturnValueOnce(
      new Promise((resolve) => {
        respond = resolve;
      }),
    );
    fillKeyMode();
    form().requestSubmit();
    expect(fetchRegistrySignerData).toHaveBeenCalledTimes(1);

    field("network").value = "testnet";
    field("network").dispatchEvent(new Event("change", { bubbles: true }));
    respond({
      aggregatePublicKey: KEY.slice(2),
      keySet: { signerIdentityKeys: [KEY], signaturesRequired: 1 },
    });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(element("result").hidden).toBe(true);
    expect(element("form-error").hidden).toBe(true);
    expect(field("compute").disabled).toBe(false);
  });

  it("uses a supplied v1 aggregate key without querying the registry", async () => {
    fillKeyMode();
    field("deposit-version").value = "v1";
    field("signers-key").value = KEY;

    form().requestSubmit();

    await vi.waitFor(() => expect(element("result").hidden).toBe(false));
    expect(fetchRegistrySignerData).not.toHaveBeenCalled();
    expect(element("result-version").textContent).toBe("Version 1");
    expect(element("result-signers-key").textContent).toBe(KEY.slice(2));
  });

  it("computes a v1 address when the registry key set is unusable", async () => {
    vi.mocked(fetchRegistrySignerData).mockResolvedValue({
      aggregatePublicKey: KEY.slice(2),
      keySet: { error: "The sBTC registry signature threshold is invalid." },
    });
    fillKeyMode();

    form().requestSubmit();
    await vi.waitFor(() => expect(element("result").hidden).toBe(false));
    expect(element("result-version").textContent).toBe("Version 1");

    field("deposit-version").value = "v2";
    field("deposit-version").dispatchEvent(new Event("change", { bubbles: true }));
    form().requestSubmit();
    await vi.waitFor(() => expect(element("form-error").hidden).toBe(false));
    expect(element("form-error").textContent).toBe(
      "The sBTC registry signature threshold is invalid.",
    );
  });
});
