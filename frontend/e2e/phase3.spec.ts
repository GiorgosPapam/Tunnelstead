import { expect, Page, test } from "@playwright/test";

async function signIn(page: Page) {
  await page.goto("/");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill("my-own-secure-passphrase");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
}

test("OpenVPN over TCP: wizard, detail page with certificates, .ovpn client", async ({ page }) => {
  await signIn(page);
  await page.getByRole("link", { name: "VPN Servers", exact: true }).click();
  await page.getByRole("button", { name: "New VPN instance" }).click();
  await page.getByRole("radio", { name: /^OpenVPN/ }).check({ force: true });
  const next = page.getByRole("button", { name: "Next" });
  await next.click();
  await expect(page.getByLabel("Instance name")).toHaveValue("OVPN-Primary");
  await page.getByLabel("Public endpoint").fill("vpn.example.org");
  await next.click(); await next.click();
  await page.getByRole("radio", { name: /^TCP/ }).check({ force: true });
  await next.click();
  await expect(page.getByLabel("Listening port (TCP)")).toHaveValue("1194");
  await expect(page.getByText("TCP 1194 is free")).toBeVisible();
  await next.click();
  await page.getByLabel("IPv4 tunnel subnet").fill("10.30.0.0/24");
  await page.getByLabel("IPv6 tunnel subnet (ULA)").fill("fd30:30::/64");
  await next.click(); await next.click(); await next.click();
  await page.getByRole("button", { name: "Review", exact: true }).click();
  await expect(page.getByText("All checks passed against the live server.")).toBeVisible();
  await expect(page.getByText("Allow TCP 1194 inbound")).toBeVisible();
  await page.getByRole("button", { name: "Deploy" }).click();

  await page.getByRole("link", { name: "OVPN-Primary" }).click();
  const details = page.getByRole("region", { name: "Server details" });
  await expect(details.getByText("CA fingerprint (SHA-256)")).toBeVisible();
  await expect(details.getByText(/CA valid until/)).toBeVisible();
  await page.getByRole("button", { name: "New client" }).first().click();
  await expect(page.getByLabel("Use my own public key (optional)")).toHaveCount(0);  // certificates only
  await page.getByLabel("Device name").fill("Office PC");
  await page.getByRole("button", { name: "Create client" }).click();
  await expect(page.getByRole("link", { name: /Download Office-PC\.ovpn/ })).toBeVisible();
  await expect(page.getByRole("img", { name: /QR code/ })).toHaveCount(0);
  await page.getByRole("button", { name: "Close dialog" }).click();
  await expect(page.getByRole("row", { name: /Office PC/ }).getByText(/certificate until/)).toBeVisible();
  await page.screenshot({ path: "test-results/screens/openvpn-detail.png", fullPage: true });
});
