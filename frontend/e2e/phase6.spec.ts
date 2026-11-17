import { expect, Page, test } from "@playwright/test";

async function signIn(page: Page) {
  await page.goto("/");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill("my-own-secure-passphrase");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
}

test("Updates: check, verified download, install, roll back", async ({ page }) => {
  await signIn(page);
  await page.getByRole("link", { name: "Updates", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Updates" })).toBeVisible();
  await page.getByRole("button", { name: "Check now" }).click();
  await expect(page.getByText("Version 9.9.9")).toBeVisible();
  await expect(page.getByText("Faster dashboard")).toBeVisible();
  await page.getByRole("button", { name: "Download" }).click();
  await expect(page.getByText("Downloaded, signature valid")).toBeVisible();
  await page.screenshot({ path: "test-results/screens/updates.png", fullPage: true });
  await page.getByRole("button", { name: "Install 9.9.9 now" }).click();
  await expect(page.getByText(/Updated from 0\.1\.0 to 9\.9\.9/)).toBeVisible({ timeout: 10000 });
  await page.getByRole("button", { name: "Roll back" }).click();
  await expect(page.getByText(/Changes made since then/)).toBeVisible();
  await page.getByRole("dialog").getByRole("button", { name: "Roll back" }).click();
  await expect(page.getByText("Rolled back to 0.1.0.")).toBeVisible({ timeout: 10000 });
});

test("Updates: automatic install settings", async ({ page }) => {
  await signIn(page);
  await page.goto("/updates");
  await page.getByLabel("GitHub repository").fill("not a repo");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText(/repo/i).locator("..").getByRole("alert").or(page.getByRole("alert"))).toBeVisible();
  await page.getByLabel("GitHub repository").fill("example/tunnelstead");
  await page.getByRole("radio", { name: /Install it automatically/ }).check();
  await page.getByLabel("Day").selectOption("sun");
  await page.getByLabel("Hour (UTC)").selectOption("3");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText("Saved.")).toBeVisible();
  await page.reload();
  await expect(page.getByLabel("Day")).toHaveValue("sun");
});
