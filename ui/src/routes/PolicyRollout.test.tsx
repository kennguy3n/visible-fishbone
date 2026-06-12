import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { PolicyRollout } from "./PolicyRollout";

// The roll-out route is driven entirely by the tenant context and the manual
// policy-template hooks, so we mock those boundaries and assert the route
// renders its selection UI and wires the operator's choices into the
// preview/execute mutations. No network or provider tree is needed.

const previewMutate = vi.fn();
const executeMutate = vi.fn();

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
    isPending: false,
    data: undefined,
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
});

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

    fireEvent.change(screen.getByLabelText("Industry"), {
      target: { value: "finance" },
    });
    fireEvent.change(screen.getByLabelText("Country / data residency"), {
      target: { value: "DE" },
    });
    // Select the first tenant only.
    fireEvent.click(screen.getAllByRole("checkbox")[0]);

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
});
