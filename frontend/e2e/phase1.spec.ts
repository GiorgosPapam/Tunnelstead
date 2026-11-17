import { expect, Page, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const NEW_PW = "my-own-secure-passphrase";
const initialPw = () => readFileSync(join(tmpdir(), "vpnix-manager-ui-admin.txt"), "utf8").trim();

async function signIn(page: Page, user: string, pw: string) {
  await page.goto("/");
  await page.getByLabel("Username").fill(user);
  await page.getByLabel("Password").fill(pw);
  await page.getByRole("button", { name: "Sign in" }).click();
}

test.describe.serial("Phase 1", () => {
  test("unknown user and wrong password get the same message", async ({ page }) => {
    await signIn(page, "nobody", "whatever-password");
    await expect(page.getByRole("alert")).toHaveText("Incorrect username or password");
  });

  test("first sign-in with the installer password forces a change", async ({ page }) => {
    await signIn(page, "admin", initialPw());
    await expect(page.getByRole("heading", { name: "Set your password" })).toBeVisible();
    await page.getByLabel("Temporary password").fill(initialPw());
    await page.getByLabel("New password", { exact: true }).fill(NEW_PW);
    await page.getByLabel("Repeat new password").fill(NEW_PW);
    await page.getByRole("button", { name: "Save and continue" }).click();
    await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
    await expect(page.getByRole("progressbar", { name: "Memory" })).toBeVisible();  // real metrics rendered
    await expect(page.getByText("0 running · 0 stopped")).toBeVisible();  // real VPN counters
  });

  test("top navigation reaches every section", async ({ page }) => {
    await signIn(page, "admin", NEW_PW);
    const nav = page.getByRole("navigation", { name: "Main" });
    for (const name of ["VPN Servers", "Networks", "Firewall", "Monitoring", "Logs", "Updates", "Settings", "Overview"]) {
      await nav.getByRole("link", { name, exact: true }).click();
      await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
    }
  });

  test("admin creates a viewer who cannot manage users", async ({ page }) => {
    await signIn(page, "admin", NEW_PW);
    await page.getByRole("link", { name: "Settings", exact: true }).click();
    await page.getByRole("tab", { name: "Users & roles" }).click();
    await page.getByRole("button", { name: "Add user" }).click();
    await page.getByLabel("Username", { exact: true }).fill("auditor");
    await page.getByLabel("Role", { exact: true }).selectOption("viewer");
    await page.getByLabel("Temporary password").fill("temporary-pass-12345");
    await page.getByRole("button", { name: "Create user" }).click();
    await expect(page.getByRole("cell", { name: "auditor", exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Sign out" }).click();

    await signIn(page, "auditor", "temporary-pass-12345");
    await page.getByLabel("Temporary password").fill("temporary-pass-12345");
    await page.getByLabel("New password", { exact: true }).fill("read-only-long-passphrase");
    await page.getByLabel("Repeat new password").fill("read-only-long-passphrase");
    await page.getByRole("button", { name: "Save and continue" }).click();
    await page.getByRole("link", { name: "Settings", exact: true }).click();
    await expect(page.getByRole("tab", { name: "Users & roles" })).toHaveCount(0);
    expect((await page.request.get("/api/users")).status()).toBe(403);
    await page.getByRole("link", { name: "Logs", exact: true }).click();
    await expect(page.getByText("Administrators only")).toBeVisible();
  });

  test("audit log shows events with intact chain", async ({ page }) => {
    await signIn(page, "admin", NEW_PW);
    await page.getByRole("link", { name: "Logs", exact: true }).click();
    await expect(page.getByText("Integrity verified")).toBeVisible();
    await expect(page.getByRole("cell", { name: "admin.user_create" })).toBeVisible();
  });

  test("phone layout: menu collapses and no sideways scroll", async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await signIn(page, "admin", NEW_PW);
    await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(0);
    await page.getByRole("button", { name: "Open menu" }).click();
    await page.locator("#mobile-nav").getByRole("link", { name: "Logs" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Logs" })).toBeVisible();
  });

  test("screens for review", async ({ page }) => {
    await page.goto("/");
    await page.screenshot({ path: "test-results/screens/login.png" });
    await signIn(page, "admin", NEW_PW);
    await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
    await page.waitForTimeout(800);
    await page.screenshot({ path: "test-results/screens/overview-dark.png" });
    await page.getByRole("button", { name: /Switch to light theme/ }).click();
    await page.waitForTimeout(300);
    await page.screenshot({ path: "test-results/screens/overview-light.png" });
  });
});
