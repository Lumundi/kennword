import { expect, type Browser, type BrowserContext, type Locator, type Page } from '@playwright/test';
import type { Authenticator } from './authenticator';

export interface Account {
    email: string;
    name: string;
    password: string;
}

/** A browser context of its own, like another person's browser, for the server at the URL. */
export async function newContext(browser: Browser, baseURL = process.env.VW_CLIENTS_URL): Promise<BrowserContext> {
    const created = await browser.newContext({
        baseURL,
        ignoreHTTPSErrors: true,
        locale: 'en-US',
        timezoneId: 'UTC',
        acceptDownloads: true,
    });
    created.setDefaultTimeout(20_000);
    created.setDefaultNavigationTimeout(30_000);

    return created;
}

/**
 * Clears what the web vault puts in the way, whenever it does: what it offers
 * new accounts once per browser (the browser extension and a tour of the
 * vault), and toasts, which cover the buttons at the top for a few seconds.
 * Toasts stay visible, but clicks go through them.
 */
export async function clearTheWay(page: Page): Promise<void> {
    await page.addInitScript(() => {
        document.addEventListener('DOMContentLoaded', () => {
            const style = document.createElement('style');
            style.textContent = 'bit-toast-container, bit-toast-container * { pointer-events: none !important; }';
            document.head.append(style);
        });
    });
    await page.addLocatorHandler(page.getByRole('button', { name: 'Add it later' }), async () => {
        await page.getByRole('button', { name: 'Add it later' }).click();
        await page.getByRole('link', { name: 'Skip to web app' }).click();
    });
    const tour = page.getByRole('dialog').filter({ hasText: 'Welcome to Bitwarden' });
    await page.addLocatorHandler(tour, async () => {
        await tour.getByRole('button', { name: 'Skip' }).click();
    });
}

export async function createAccount(page: Page, account: Account): Promise<void> {
    await page.goto('/#/signup');
    await page.getByRole('textbox', { name: /Email address/ }).fill(account.email);
    await page.getByRole('textbox', { name: 'Name' }).fill(account.name);
    await page.getByRole('button', { name: 'Continue' }).click();

    await page.getByRole('textbox', { name: 'Master password * (required)', exact: true }).fill(account.password);
    await page.getByRole('textbox', { name: /Confirm master password/ }).fill(account.password);
    // The check asks api.pwnedpasswords.com.
    await page.getByRole('checkbox', { name: 'Check known data breaches for this password' }).uncheck();
    await page.getByRole('button', { name: 'Create account' }).click();

    await expectVault(page);
}

export async function logIn(page: Page, account: Account, authenticator?: Authenticator): Promise<void> {
    await page.goto('/#/login');
    await page.getByRole('textbox', { name: /Email address/ }).fill(account.email);
    await page.getByRole('button', { name: 'Continue' }).click();
    await page.getByRole('textbox', { name: 'Master password * (required)', exact: true }).fill(account.password);
    await page.getByRole('button', { name: 'Log in', exact: true }).click();

    if (authenticator) {
        await expect(page.getByRole('heading', { name: 'Verify your Identity' })).toBeVisible();
        await page.getByRole('textbox', { name: /Verification code/ }).fill(await authenticator.nextCode());
        await page.getByRole('button', { name: 'Continue logging in' }).click();
    }

    await expectVault(page);
}

/** After a reload: the web vault keeps the keys in memory only. */
export async function unlock(page: Page, account: Account): Promise<void> {
    await expect(page.getByRole('heading', { name: 'Your vault is locked' })).toBeVisible();
    await page.getByRole('textbox', { name: 'Master password * (required)', exact: true }).fill(account.password);
    await page.getByRole('button', { name: 'Unlock', exact: true }).click();
    await expectVault(page);
}

export async function logOut(page: Page, account: Account): Promise<void> {
    await page.getByRole('button', { name: account.name, exact: true }).click();
    await page.getByRole('menuitem', { name: 'Log out' }).click();
    await expect(page.getByRole('heading', { name: 'Log in' })).toBeVisible();
}

export async function expectVault(page: Page): Promise<void> {
    // The vault's "Add" button ("New" before web vault 2026.10), once the onboarding is out of the way.
    await page.getByRole('main').getByRole('button', { name: 'Add', exact: true }).hover();
    await expect(page.getByRole('heading', { name: 'All vaults', level: 1 })).toBeVisible();
}

/** Opens the form of a new item ("Login", "Card", "Note", ...) or folder. */
export async function newItem(page: Page, type: string): Promise<Locator> {
    await page.getByRole('main').getByRole('button', { name: 'Add', exact: true }).click();
    await page.getByRole('menuitem', { name: type, exact: true }).click();

    return page.getByRole('dialog');
}

/** Picks an option of one of the web vault's select boxes. */
export async function choose(page: Page, select: Locator, option: string): Promise<void> {
    await select.click();
    await page.getByRole('listbox').getByRole('option', { name: option, exact: true }).click();
}

/** Opens an item of the vault's list. */
export async function openItem(page: Page, name: string): Promise<Locator> {
    await page.getByRole('main').getByRole('button', { name, exact: true }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByRole('heading', { name, exact: true })).toBeVisible();

    return dialog;
}

export async function expectToast(page: Page, text: string | RegExp): Promise<void> {
    await expect(page.getByRole('status').getByText(text).first()).toBeVisible();
}
