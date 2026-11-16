import { expect, Page, test } from "@playwright/test";

async function signIn(page: Page) {
  await page.goto("/");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill("my-own-secure-passphrase");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
}

const PASS = "browser test backup passphrase";

test("Monitoring page shows host charts and every VPN server", async ({ page }) => {
  await signIn(page);
  await page.getByRole("link", { name: "Monitoring", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Monitoring" })).toBeVisible();
  for (const t of ["VPN clients online", "Network traffic (all interfaces)", "CPU", "Memory and disk"]) await expect(page.getByText(t, { exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "OVPN-Primary monitoring" })).toBeVisible();
  await page.getByRole("tab", { name: "7 days" }).click();
  await expect(page.getByRole("tab", { name: "7 days" })).toHaveAttribute("aria-selected", "true");
  await page.screenshot({ path: "test-results/screens/monitoring.png", fullPage: true });
});

test("Service logs tab filters journal lines", async ({ page }) => {
  await signIn(page);
  await page.goto("/logs");
  await page.getByRole("tab", { name: "Service logs" }).click();
  await expect(page.getByText("Application startup complete.")).toBeVisible();
  await page.getByLabel("Search").fill("warning");
  await expect(page.getByText("simulated warning")).toBeVisible();
  await expect(page.getByText("Application startup complete.")).toHaveCount(0);
});

test("Notifications: https only, saved, password never shown", async ({ page }) => {
  await signIn(page);
  await page.goto("/settings");
  await page.getByRole("tab", { name: "Notifications" }).click();
  await page.getByLabel("Webhook URL").fill("http://insecure.example");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText(/must start with https/)).toBeVisible();
  await page.getByLabel("Webhook URL").fill("https://hooks.example.org/vpnix");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText("Notification settings saved.")).toBeVisible();
});

test("Backups: create, verify, restore and sign in again", async ({ page }) => {
  await signIn(page);
  await page.goto("/settings");
  await page.getByRole("tab", { name: "Backups" }).click();
  await page.getByRole("button", { name: "Back up now" }).click();
  await page.getByRole("dialog").getByLabel("Passphrase", { exact: true }).fill(PASS);
  await page.getByLabel("Repeat passphrase").fill(PASS);
  await page.getByRole("button", { name: "Create backup" }).click();
  await expect(page.getByText(/Backup vpnix-backup-.*-manual\.vbk created/)).toBeVisible();
  await page.screenshot({ path: "test-results/screens/backups.png", fullPage: true });

  await page.getByRole("button", { name: "Restore" }).first().click();
  await page.getByLabel("Backup passphrase").fill("wrong passphrase here");
  await page.getByRole("button", { name: "Check backup" }).click();
  await expect(page.getByText("Wrong passphrase, or the file is damaged")).toBeVisible();
  await page.getByLabel("Backup passphrase").fill(PASS);
  await page.getByRole("button", { name: "Check backup" }).click();
  await expect(page.getByText("Decrypted and verified")).toBeVisible();
  const dialog = page.getByRole("dialog");
  const name = (await dialog.locator("p.break-all").first().textContent())!.trim();
  await expect(dialog.getByRole("button", { name: "Restore now" })).toBeDisabled();
  await page.getByLabel("Type the backup name to confirm").fill(name);
  await dialog.getByRole("button", { name: "Restore now" }).click();
  await expect(page.getByText("Restore complete")).toBeVisible();
  await expect(page.getByRole("dialog").getByText(/pre-restore\.vbk/)).toBeVisible();
  await page.getByRole("button", { name: "Sign in again" }).click();
  await signIn(page);
  await page.goto("/servers");
  await expect(page.getByRole("link", { name: "OVPN-Primary" })).toBeVisible();
});
