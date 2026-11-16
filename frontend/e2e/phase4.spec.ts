import { expect, Page, test } from "@playwright/test";

async function signIn(page: Page) {
  await page.goto("/");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill("my-own-secure-passphrase");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
}

test("Networks: checks and routing preview", async ({ page }) => {
  await signIn(page);
  await page.getByRole("link", { name: "Networks", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Networks" })).toBeVisible();
  const card = page.locator("section.card").first();
  await expect(card).toBeVisible();
  await card.getByRole("button", { name: "Change routing" }).click();
  await expect(page.getByText("CLIENT ROUTES NOW")).toBeVisible();
  await expect(page.getByText("AFTER THE CHANGE")).toBeVisible();
  await page.getByRole("button", { name: "Cancel" }).click();
});

test("Firewall: add rule, keep it, delete it", async ({ page }) => {
  await signIn(page);
  await page.getByRole("link", { name: "Firewall", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Firewall" })).toBeVisible();
  await page.getByRole("button", { name: "Add rule" }).click();
  await page.getByLabel("Port or range (optional)").fill("8443");
  await page.getByLabel("From (optional)").fill("198.51.100.0/24");
  await page.getByLabel("Comment (optional)").fill("e2e rule");
  await page.getByRole("button", { name: "Apply rule" }).click();
  await expect(page.getByText("Keep this firewall change?")).toBeVisible();
  await page.getByRole("button", { name: "Keep changes" }).click();
  await expect(page.getByText("Change kept.")).toBeVisible();
  await expect(page.getByText("· e2e rule")).toBeVisible();
  await page.screenshot({ path: "test-results/screens/firewall.png", fullPage: true });
  const id = await page.getByRole("button", { name: /Delete rule/ }).last().getAttribute("aria-label");
  await page.getByRole("button", { name: id! }).click();
  await page.getByRole("button", { name: "Keep changes" }).click();
  await expect(page.getByText("· e2e rule")).toHaveCount(0);
});

test("Firewall: invalid rule is rejected", async ({ page }) => {
  await signIn(page);
  await page.goto("/firewall");
  await page.getByRole("button", { name: "Add rule" }).click();
  await page.getByLabel("From (optional)").fill("not-an-ip; drop");
  await page.getByRole("button", { name: "Apply rule" }).click();
  await expect(page.getByRole("dialog").getByRole("alert")).toBeVisible();
});
