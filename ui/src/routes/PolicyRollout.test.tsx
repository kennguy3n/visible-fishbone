import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { PolicyRollout } from "./PolicyRollout";

// The roll-out route is driven entirely by the tenant context and the manual
// policy-template hooks, so we mock those boundaries and assert the route
// renders its selection UI and wires the operator's choices into the
// preview/execute mutations. No network or provider tree is needed.

const previewMutate = vi.fn();
const executeMutate = vi.fn();

// Mutable preview-hook state so individual tests can simulate a
// completed preview (isSuccess) and assert the execute gate.
let previewState: { isPending: boolean; isSuccess: boolean; data: unknown } = {
  isPending: false,
  isSuccess: false,
  data: undefined,
};

vi.mock("@/lib/tenant-context", () => ({
  useTenant: () => ({
    tenants: [
      { id: "t1", name: "Acme Ltd", slug: "acme", region: "eu", tier: "starter" },
      { id: "t2", name: "Globex", slug: "globex", region: "us", tier: "growth" },
    ],
    isLoading: false,
  }),
}));

vi.mock("@/components/Toast", () => ({
  useToast: () => ({ success: vi.fn(), error: vi.fn(), info: vi.fn() }),
}));

vi.mock("@/api/manual/hooks", () => ({
  usePolicyTemplateOptions: () => ({
    data: {
      industries: [
        { industry: "finance", name: "Finance", template_id: "industry/finance" },
      ],
      countries: [{ country: "DE", regime: "eu-gdpr" }],
    },
    isLoading: false,
  }),
  usePreviewPolicyRollout: () => ({
    mutate: previewMutate,
    reset: vi.fn(),
    isPending: previewState.isPending,
    isSuccess: previewState.isSuccess,
    data: previewState.data,
  }),
  useExecutePolicyRollout: () => ({
    mutate: executeMutate,
    reset: vi.fn(),
    isPending: false,
    data: undefined,
  }),
}));

afterEach(() => {
  cleanup();
  previewMutate.mockReset();
  executeMutate.mockReset();
  previewState = { isPending: false, isSuccess: false, data: undefined };
});

function chooseBaselineAndTenant() {
  fireEvent.change(screen.getByLabelText("Industry"), {
    target: { value: "finance" },
  });
  fireEvent.change(screen.getByLabelText("Country / data residency"), {
    target: { value: "DE" },
  });
  fireEvent.click(screen.getAllByRole("checkbox")[0]);
}

describe("PolicyRollout", () => {
  it("renders the roll-out surface with the available tenants", () => {
    render(<PolicyRollout />);
    expect(screen.getByText("Cross-tenant roll-out")).toBeTruthy();
    expect(screen.getByText("Acme Ltd")).toBeTruthy();
    expect(screen.getByText("Globex")).toBeTruthy();
  });

  it("keeps preview/execute disabled until a baseline and tenants are chosen", () => {
    render(<PolicyRollout />);
    const previewBtn = screen.getByRole("button", { name: /preview diff/i });
    expect((previewBtn as HTMLButtonElement).disabled).toBe(true);
  });

  it("passes the selected baseline and tenants into the preview mutation", () => {
    render(<PolicyRollout />);

    chooseBaselineAndTenant();

    const previewBtn = screen.getByRole("button", { name: /preview diff/i });
    expect((previewBtn as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(previewBtn);

    expect(previewMutate).toHaveBeenCalledTimes(1);
    expect(previewMutate.mock.calls[0][0]).toEqual({
      industry: "finance",
      country: "DE",
      tenant_ids: ["t1"],
    });
  });

  it("keeps execute disabled until a preview has succeeded, even with a full selection", () => {
    render(<PolicyRollout />);
    chooseBaselineAndTenant();

    const executeBtn = screen.getByRole("button", { name: /apply to/i });
    expect((executeBtn as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(/preview the per-tenant diff before applying/i)).toBeTruthy();
  });

  it("enables execute once a fresh preview has succeeded for the selection", () => {
    previewState = {
      isPending: false,
      isSuccess: true,
      data: {
        selection: { industry: "finance", country: "DE" },
        regime: "eu-gdpr",
        template_ids: [],
        graph_hash: "abc123",
        targets: [],
      },
    };
    render(<PolicyRollout />);
    chooseBaselineAndTenant();

    const executeBtn = screen.getByRole("button", { name: /apply to/i });
    expect((executeBtn as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(executeBtn);

    expect(executeMutate).toHaveBeenCalledTimes(1);
    expect(executeMutate.mock.calls[0][0]).toEqual({
      industry: "finance",
      country: "DE",
      tenant_ids: ["t1"],
    });
  });
});
