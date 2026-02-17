import { afterEach, describe, expect, it, vi } from "vitest";
import { UrlCheckClient } from "../clients/url-check.js";

describe("UrlCheckClient", () => {
	const originalFetch = globalThis.fetch;

	afterEach(() => {
		globalThis.fetch = originalFetch;
	});

	it("returns empty for empty URL list", async () => {
		const client = new UrlCheckClient();
		const results = await client.checkUrls([]);
		expect(results).toEqual([]);
	});

	it("parses malicious URL response", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({
				answers: [
					{
						key: "http://malware.test",
						result: {
							success: {
								classification: {
									result: {
										malicious: {
											findings: [
												{
													"severity-name": "malware",
													"type-name": "trojan",
												},
											],
										},
									},
								},
								flags: [],
							},
						},
					},
				],
			}),
		});

		const client = new UrlCheckClient();
		const results = await client.checkUrls(["http://malware.test"]);
		expect(results).toHaveLength(1);
		expect(results[0]?.isMalicious).toBe(true);
		expect(results[0]?.findings).toHaveLength(1);
		expect(results[0]?.findings[0]?.severityName).toBe("malware");
	});

	it("parses clean URL response", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({
				answers: [
					{
						key: "http://safe.test",
						result: {
							success: {
								classification: {
									result: {},
								},
								flags: [],
							},
						},
					},
				],
			}),
		});

		const client = new UrlCheckClient();
		const results = await client.checkUrls(["http://safe.test"]);
		expect(results).toHaveLength(1);
		expect(results[0]?.isMalicious).toBe(false);
		expect(results[0]?.findings).toHaveLength(0);
	});

	it("parses flagged URL response", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({
				answers: [
					{
						key: "http://suspicious.test",
						result: {
							success: {
								classification: { result: {} },
								flags: ["TYPOSQUATTING"],
							},
						},
					},
				],
			}),
		});

		const client = new UrlCheckClient();
		const results = await client.checkUrls(["http://suspicious.test"]);
		expect(results).toHaveLength(1);
		expect(results[0]?.flags).toContain("TYPOSQUATTING");
	});

	it("returns empty on fetch error (fail-open)", async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error("network error"));

		const client = new UrlCheckClient();
		const results = await client.checkUrls(["http://any.test"]);
		expect(results).toEqual([]);
	});

	it("returns empty on non-ok response (fail-open)", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: false,
			status: 500,
		});

		const client = new UrlCheckClient();
		const results = await client.checkUrls(["http://any.test"]);
		expect(results).toEqual([]);
	});

	it("batches URLs in groups of 50", async () => {
		const mockFetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({ answers: [] }),
		});
		globalThis.fetch = mockFetch;

		const urls = Array.from({ length: 120 }, (_, i) => `http://url${i}.test`);
		const client = new UrlCheckClient();
		await client.checkUrls(urls);

		// 120 URLs → 3 batches (50, 50, 20)
		expect(mockFetch).toHaveBeenCalledTimes(3);
	});
});
