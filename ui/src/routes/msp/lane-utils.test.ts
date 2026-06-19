import { AxiosError, AxiosHeaders } from "axios";
import { describe, expect, it } from "vitest";
import { httpStatus, isPermissionDenied, readableTextOn } from "./lane-utils";

function axiosErrorWithStatus(status: number): AxiosError {
  const err = new AxiosError("request failed");
  err.response = {
    status,
    statusText: "",
    data: null,
    headers: {},
    config: { headers: new AxiosHeaders() },
  };
  return err;
}

describe("httpStatus", () => {
  it("returns the HTTP status of an Axios error", () => {
    expect(httpStatus(axiosErrorWithStatus(404))).toBe(404);
  });

  it("returns null for a non-HTTP error", () => {
    expect(httpStatus(new Error("boom"))).toBeNull();
    expect(httpStatus(null)).toBeNull();
  });
});

describe("isPermissionDenied", () => {
  it("is true only for a 403 response", () => {
    expect(isPermissionDenied(axiosErrorWithStatus(403))).toBe(true);
    expect(isPermissionDenied(axiosErrorWithStatus(500))).toBe(false);
    expect(isPermissionDenied(new Error("network"))).toBe(false);
  });
});

describe("readableTextOn", () => {
  it("uses dark text on a light branding colour", () => {
    expect(readableTextOn("#ffffff")).toBe("#0b1220");
    expect(readableTextOn("#fde047")).toBe("#0b1220");
  });

  it("uses white text on a dark branding colour", () => {
    expect(readableTextOn("#0b1220")).toBe("#ffffff");
    expect(readableTextOn("#255fe5")).toBe("#ffffff");
  });

  it("accepts shorthand hex and is tolerant of a missing leading hash", () => {
    expect(readableTextOn("#fff")).toBe("#0b1220");
    expect(readableTextOn("000")).toBe("#ffffff");
  });

  it("falls back to dark text for an unparseable colour", () => {
    expect(readableTextOn("not-a-color")).toBe("#0b1220");
  });
});
