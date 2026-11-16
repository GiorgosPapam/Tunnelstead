import { expect, Page, test } from "@playwright/test";

const PW = "my-own-secure-passphrase";  // set by phase1.spec

async function signIn(page: Page) {
  await page.goto("/");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill(PW);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
}

test.describe.serial("Phase 2: WireGuard", () => {
  test("onboarding checklist guides to the wizard", async ({ page }) => {
    await signIn(page);
    await expect(page.getByRole("region", { name: "Getting started" })).toBeVisible();
    await page.getByRole("link", { name: "Open the wizard →" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "VPN Servers" })).toBeVisible();
  });

  test("10-step wizard deploys an instance", async ({ page }) => {
    await signIn(page);
    await page.getByRole("link", { name: "VPN Servers", exact: true }).click();
    await page.getByRole("button", { name: "Deploy a VPN instance" }).click();
    const next = page.getByRole("button", { name: "Next" });
    await expect(page.getByText("Step 1 of 10")).toBeVisible();
    await next.click();                                       // protocol: WireGuard
    await page.getByLabel("Instance name").fill("WG-Primary");
    await page.getByLabel("Public endpoint").fill("vpn.example.org");
    await next.click();                                       // name
    await next.click();                                       // network interface
    await next.click();                                       // transport
    await expect(page.getByText("UDP 51820 is free")).toBeVisible();
    await page.screenshot({ path: "test-results/screens/wizard-port.png" });
    await next.click();                                       // port
    await expect(page.getByLabel("IPv4 tunnel subnet")).toHaveValue("10.8.0.0/24");
    await next.click();                                       // subnet
    await next.click();                                       // DNS (Cloudflare)
    await next.click();                                       // routing (full)
    await page.getByRole("button", { name: "Review", exact: true }).click();  // firewall & NAT
    await expect(page.getByText("All checks passed against the live server.")).toBeVisible();
    await expect(page.getByText("Allow UDP 51820 inbound")).toBeVisible();
    await page.screenshot({ path: "test-results/screens/wizard-review.png" });
    await page.getByRole("button", { name: "Deploy" }).click();
    const card = page.getByRole("article", { name: "WG-Primary" });
    await expect(card).toBeVisible();
    await expect(card.getByText("Running")).toBeVisible();
    await page.screenshot({ path: "test-results/screens/servers.png" });
  });

  test("create a client, see QR, disable it", async ({ page }) => {
    await signIn(page);
    await page.getByRole("link", { name: "Clients", exact: true }).click();
    await page.getByRole("button", { name: "New client" }).first().click();
    await page.getByLabel("Device name").fill("Maria laptop");
    await page.getByLabel("Tags (optional)").fill("staff, laptop");
    await page.getByRole("button", { name: "Create client" }).click();
    await expect(page.getByRole("img", { name: "WireGuard QR code for Maria laptop" })).toBeVisible();
    await expect(page.getByRole("link", { name: /Download Maria-laptop\.conf/ })).toBeVisible();
    await page.screenshot({ path: "test-results/screens/client-qr.png" });
    await page.getByRole("button", { name: "Close dialog" }).click();
    const row = page.getByRole("row", { name: /Maria laptop/ });
    await expect(row.getByText("10.8.0.2")).toBeVisible();
    await row.getByRole("button", { name: "Disable" }).click();
    await expect(row.getByText("Disabled")).toBeVisible();
    await page.screenshot({ path: "test-results/screens/clients.png" });
    await page.getByRole("link", { name: "Overview", exact: true }).click();
    await expect(page.getByRole("region", { name: "Getting started" })).toHaveCount(0);  // onboarding complete
  });
});
