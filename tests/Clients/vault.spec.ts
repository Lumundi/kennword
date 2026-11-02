import { test, expect, type BrowserContext, type Page } from '@playwright/test';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Authenticator } from './support/authenticator';
import { Cli, named, type Item, type Named } from './support/cli';
import {
    choose, clearTheWay, createAccount, expectToast, expectVault, logIn, logOut, newContext, newItem, openItem, unlock,
    type Account,
} from './support/web-vault';

// One account goes through the web vault and then through the CLI: each test builds on the ones
// before it, in one browser context.
test.describe.configure({ mode: 'serial' });

const account: Account = {
    email: `alex.${Date.now()}@example.com`,
    name: 'Alex Example',
    password: 'Clients test master password 7f3a',
};
const attachment = { name: 'notes.txt', contents: 'Attachment of the clients test\n' };
const cli = new Cli();

let context: BrowserContext;
let page: Page;
let authenticator: Authenticator;
let sendUrl: string;

test.beforeAll(async ({ browser }) => {
    context = await newContext(browser);
    await context.tracing.start({ screenshots: true, snapshots: true });
    page = await context.newPage();
    await clearTheWay(page);
});

test.afterAll(async () => {
    await context.tracing.stop({ path: join('test-results', 'vault-trace.zip') });
    await context.close();
});

test('creates an account in the web vault', async () => {
    await createAccount(page, account);
});

test('keeps logins, notes and cards in folders, with attachments', async () => {
    let dialog = await newItem(page, 'Folder');
    await dialog.getByRole('textbox', { name: /Folder name/ }).fill('Work');
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expectToast(page, 'Folder saved');

    dialog = await newItem(page, 'Login');
    await dialog.getByRole('textbox', { name: /Item name/ }).fill('Example login');
    await choose(page, dialog.getByRole('combobox', { name: 'Folder' }), 'Work');
    await dialog.getByRole('textbox', { name: 'Username' }).fill('alex@example.com');
    await dialog.getByRole('textbox', { name: 'Password' }).fill('first password');
    await dialog.getByRole('textbox', { name: 'Website (URI)' }).fill('https://login.example.com');
    await dialog.getByRole('textbox', { name: 'Notes' }).fill('Notes of the login');
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expect(dialog.getByRole('heading', { name: 'View Login' })).toBeVisible();

    // Attachments go to saved items, encrypted with a key of their own.
    await dialog.getByRole('button', { name: 'Edit' }).click();
    await dialog.getByRole('button', { name: 'Attachments' }).click();
    const upload = page.getByRole('dialog', { name: 'Add attachment' });
    await upload.locator('input[type=file]').setInputFiles({
        name: attachment.name,
        mimeType: 'text/plain',
        buffer: Buffer.from(attachment.contents),
    });
    await upload.getByRole('button', { name: 'Upload' }).click();
    await expect(upload).toBeHidden();
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expect(dialog.getByRole('heading', { name: 'View Login' })).toBeVisible();
    const download = page.waitForEvent('download');
    await dialog.getByRole('button', { name: `Download ${attachment.name}` }).click();
    expect(readFileSync(await (await download).path(), 'utf8')).toBe(attachment.contents);
    await dialog.getByRole('button', { name: 'Close' }).first().click();

    dialog = await newItem(page, 'Note');
    await dialog.getByRole('textbox', { name: /Item name/ }).fill('Example note');
    await choose(page, dialog.getByRole('combobox', { name: 'Folder' }), 'Work');
    await dialog.getByRole('textbox', { name: 'Notes' }).fill('First line\nSecond line');
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expect(dialog.getByRole('heading', { name: 'View Note' })).toBeVisible();
    await dialog.getByRole('button', { name: 'Close' }).first().click();

    dialog = await newItem(page, 'Card');
    await dialog.getByRole('textbox', { name: /Item name/ }).fill('Example card');
    await dialog.getByRole('textbox', { name: 'Cardholder name' }).fill('Alex Example');
    await dialog.getByRole('textbox', { name: 'Number' }).fill('4111111111111111');
    await choose(page, dialog.getByRole('combobox', { name: 'Brand' }), 'Visa');
    await choose(page, dialog.getByRole('combobox', { name: 'Expiration month' }), '12 - December');
    await dialog.getByRole('spinbutton', { name: 'Expiration year' }).fill('2030');
    await dialog.getByRole('textbox', { name: 'Security code (CVV)' }).fill('123');
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expect(dialog.getByRole('heading', { name: 'View Card' })).toBeVisible();
    await dialog.getByRole('button', { name: 'Close' }).first().click();

    // One to delete, one to share.
    dialog = await newItem(page, 'Note');
    await dialog.getByRole('textbox', { name: /Item name/ }).fill('Temporary note');
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expect(dialog.getByRole('heading', { name: 'View Note' })).toBeVisible();
    await dialog.getByRole('button', { name: 'Close' }).first().click();

    dialog = await newItem(page, 'Login');
    await dialog.getByRole('textbox', { name: /Item name/ }).fill('Shared login');
    await dialog.getByRole('textbox', { name: 'Username' }).fill('team@example.com');
    await dialog.getByRole('textbox', { name: 'Password' }).fill('team password');
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expect(dialog.getByRole('heading', { name: 'View Login' })).toBeVisible();
    await dialog.getByRole('button', { name: 'Close' }).first().click();

    for (const name of ['Example login', 'Example note', 'Example card', 'Temporary note', 'Shared login']) {
        await expect(page.getByRole('main').getByRole('button', { name, exact: true })).toBeVisible();
    }
});

test('edits and deletes items', async () => {
    let dialog = await openItem(page, 'Example login');
    await dialog.getByRole('button', { name: 'Edit' }).click();
    await dialog.getByRole('textbox', { name: 'Password' }).fill('second password');
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expect(dialog.getByRole('heading', { name: 'View Login' })).toBeVisible();
    await dialog.getByRole('button', { name: 'Close' }).first().click();

    dialog = await openItem(page, 'Temporary note');
    await dialog.getByRole('button', { name: 'Delete' }).click();
    await page.getByRole('dialog', { name: 'Delete item' }).getByRole('button', { name: 'Yes' }).click();
    await expect(page.getByRole('main').getByRole('button', { name: 'Temporary note', exact: true })).toBeHidden();

    await page.getByRole('button', { name: 'Filter: Trash' }).click();
    await expect(page.getByRole('main').getByRole('button', { name: 'Temporary note', exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Filter: All items' }).click();
});

test('shares an item with an organization', async () => {
    await page.getByRole('link', { name: 'New organization' }).click();
    await page.getByRole('textbox', { name: /Organization name/ }).fill('Example Org');
    await page.getByRole('button', { name: 'Submit' }).click();
    await expect(page.getByRole('heading', { name: 'Example Org collections' })).toBeVisible();
    await expect(page.getByRole('main').getByRole('button', { name: 'Default collection', exact: true })).toBeVisible();

    await page.goto('/#/vault');
    await expectVault(page);
    await page.getByRole('row', { name: /Shared login/ }).getByRole('button', { name: 'More options' }).click();
    await page.getByRole('menuitem', { name: 'Assign to collections' }).click();
    // The item moves to the organization, encrypted with its key.
    const dialog = page.getByRole('dialog', { name: /Assign to collections/ });
    await choose(page, dialog.getByRole('combobox', { name: /Select collections to assign/ }), 'Default collection');
    // The list stays open for more collections.
    await dialog.getByRole('heading', { name: /Assign to collections/ }).click();
    await dialog.getByRole('button', { name: 'Assign' }).click();
    await expectToast(page, 'Item moved to collection');
    await expect(page.getByRole('row', { name: /Shared login/ }).getByRole('button', { name: /Owner, Example Org/ })).toBeVisible();
});

test('creates a Send that others can open', async ({ browser }) => {
    await page.getByRole('link', { name: 'Send', exact: true }).click();
    // "Create" with an icon, "New Send" before web vault 2026.10.
    await page.getByRole('main').getByRole('button', { name: /^\W*Create$/ }).click();
    await page.getByRole('menuitem', { name: 'Text' }).click();
    await page.getByRole('textbox', { name: /Send name/ }).fill('Example send');
    await page.getByRole('textbox', { name: /Text to share/ }).fill('Text of the Send');
    await page.getByRole('button', { name: 'Save' }).click();
    sendUrl = await page.getByRole('textbox', { name: 'Send link' }).inputValue();
    expect(sendUrl).toContain(`${process.env.VW_CLIENTS_URL}/#/send/`);
    // The button with the label, not the icons of the panel and the toasts.
    await page.getByRole('button', { name: 'Close' }).filter({ hasText: 'Close' }).click();

    const other = await newContext(browser);
    const anonymous = await other.newPage();
    await anonymous.goto(sendUrl);
    await expect(anonymous.getByRole('heading', { name: 'View Send' })).toBeVisible();
    await expect(anonymous.getByRole('main').getByRole('textbox')).toHaveValue('Text of the Send');
    await other.close();
});

test('logs in on another browser with a request this one approves', async ({ browser }) => {
    const other = await newContext(browser);
    const device = await other.newPage();
    await clearTheWay(device);
    // Only devices that have logged in before may ask.
    await logIn(device, account);
    await logOut(device, account);
    await device.getByRole('textbox', { name: /Email address/ }).fill(account.email);
    await device.getByRole('button', { name: 'Continue' }).click();
    await device.getByRole('button', { name: 'Log in with device' }).click();
    const fingerprint = await device.getByRole('main').getByRole('code').innerText();

    await page.goto('/#/settings/security/device-management');
    await page.getByRole('row', { name: /Request pending/ }).getByRole('link').click();
    const dialog = page.getByRole('dialog', { name: 'Login request' });
    await expect(dialog.getByText(fingerprint)).toBeVisible();
    await dialog.getByRole('button', { name: 'Confirm access' }).click();

    // The approval hands the other browser the key to the vault.
    await expectVault(device);
    await expect(device.getByRole('main').getByRole('button', { name: 'Example login', exact: true })).toBeVisible();
    await other.close();

    await page.goto('/#/vault');
    await expectVault(page);
});

test('switches the key derivation to Argon2id', async () => {
    await page.goto('/#/settings/security/security-keys');
    await choose(page, page.getByRole('combobox', { name: /Algorithm/ }), 'Argon2id');
    await page.getByRole('spinbutton', { name: /KDF memory/ }).fill('32');
    await page.getByRole('spinbutton', { name: /KDF iterations/ }).fill('3');
    await page.getByRole('spinbutton', { name: /KDF parallelism/ }).fill('2');
    await page.getByRole('button', { name: 'Update encryption settings' }).click();
    const dialog = page.getByRole('dialog', { name: 'Update your encryption settings' });
    await dialog.getByRole('textbox', { name: /Master password/ }).fill(account.password);
    await dialog.getByRole('button', { name: 'Update settings' }).click();

    // Since web vault 2026.10 this session goes on; a new login derives the key with the new settings.
    await expectToast(page, 'Encryption key settings saved');
    await logOut(page, account);
    await logIn(page, account);
    await expect(page.getByRole('main').getByRole('button', { name: 'Example login', exact: true })).toBeVisible();
});

test('changes the master password and rotates the account key', async () => {
    const password = 'Changed clients test master password 2b9d';
    await page.goto('/#/settings/security/password');
    await page.getByRole('textbox', { name: /Current master password/ }).fill(account.password);
    await page.getByRole('textbox', { name: /^New master password/ }).fill(password);
    await page.getByRole('textbox', { name: /Confirm new master password/ }).fill(password);
    await page.getByRole('checkbox', { name: 'Check known data breaches for this password' }).uncheck();
    // Everything encrypted with the account key is encrypted again: items, folders, attachments, Sends.
    await page.getByRole('checkbox', { name: /Also rotate my account's encryption key/ }).check();
    await page.getByRole('dialog', { name: 'Rotate encryption key' }).getByRole('button', { name: 'Yes' }).click();
    await page.getByRole('button', { name: 'Change master password' }).click();
    await expect(page.getByRole('heading', { name: 'Log in' })).toBeVisible();
    account.password = password;

    await logIn(page, account);
    const dialog = await openItem(page, 'Example login');
    const download = page.waitForEvent('download');
    await dialog.getByRole('button', { name: `Download ${attachment.name}` }).click();
    expect(readFileSync(await (await download).path(), 'utf8')).toBe(attachment.contents);
    await dialog.getByRole('button', { name: 'Close' }).first().click();
    await expect(page.getByRole('row', { name: /Shared login/ }).getByRole('button', { name: /Owner, Example Org/ })).toBeVisible();
    await page.getByRole('link', { name: 'Send', exact: true }).click();
    await expect(page.getByRole('main').getByRole('button', { name: 'Example send', exact: true })).toBeVisible();
    await page.goto('/#/vault');
    await expectVault(page);
});

test('turns on two-step login with an authenticator app', async () => {
    await page.getByRole('button', { name: account.name, exact: true }).click();
    await page.getByRole('menuitem', { name: 'Account settings' }).click();
    await page.getByRole('link', { name: 'Security' }).click();
    await page.getByRole('link', { name: 'Two-step login' }).click();
    await page.locator('bit-item').filter({ hasText: 'Authenticator app' }).getByRole('button', { name: 'Manage' }).click();
    await page.getByRole('textbox', { name: 'Master password * (required)', exact: true }).fill(account.password);
    await page.getByRole('button', { name: 'Continue' }).click();

    const dialog = page.getByRole('dialog', { name: /Authenticator app/ });
    authenticator = new Authenticator(await dialog.getByRole('code').innerText());
    await dialog.getByRole('textbox', { name: /Verification code/ }).fill(await authenticator.nextCode());
    await dialog.getByRole('button', { name: 'Turn on' }).click();
    await expect(page.getByRole('heading', { name: 'Authenticator app Turned on' })).toBeVisible();

    await logOut(page, account);
    await logIn(page, account, authenticator);
});

test('the CLI logs in with the authenticator and decrypts what the web vault made', async () => {
    await cli.run(['config', 'server', process.env.VW_CLIENTS_URL!]);
    const code = await authenticator.nextCode();
    cli.session = (await cli.run(
        ['login', account.email, '--passwordenv', 'BW_TEST_PASSWORD', '--method', '0', '--code', code, '--raw'],
        { BW_TEST_PASSWORD: account.password },
    )).trim();
    expect(cli.session).not.toBe('');
    await cli.run(['sync']);

    const work = named(await cli.json<Named[]>(['list', 'folders']), 'Work');
    const items = await cli.json<Item[]>(['list', 'items']);
    expect(items.map((item) => item.name).sort()).toEqual(['Example card', 'Example login', 'Example note', 'Shared login']);

    const login = named(items, 'Example login');
    expect(login).toMatchObject({
        type: 1,
        folderId: work.id,
        notes: 'Notes of the login',
        login: { username: 'alex@example.com', password: 'second password', uris: [{ uri: 'https://login.example.com' }] },
    });
    expect(login.passwordHistory?.map((entry) => entry.password)).toEqual(['first password']);
    expect(login.attachments?.map((entry) => entry.fileName)).toEqual([attachment.name]);
    const file = join(cli.appData, attachment.name);
    await cli.run(['get', 'attachment', attachment.name, '--itemid', login.id, '--output', file]);
    expect(readFileSync(file, 'utf8')).toBe(attachment.contents);

    expect(named(items, 'Example note')).toMatchObject({ type: 2, folderId: work.id, notes: 'First line\nSecond line' });
    const card = named(items, 'Example card');
    expect(card).toMatchObject({
        type: 3,
        card: { cardholderName: 'Alex Example', brand: 'Visa', number: '4111111111111111', expMonth: '12', expYear: '2030', code: '123' },
    });
    // The CLI leaves out what is empty.
    expect(card.folderId ?? null).toBeNull();

    const trash = await cli.json<Item[]>(['list', 'items', '--trash']);
    expect(trash.map((item) => item.name)).toEqual(['Temporary note']);

    const organization = named(await cli.json<Named[]>(['list', 'organizations']), 'Example Org');
    const collection = named(await cli.json<Named[]>(['list', 'collections']), 'Default collection');
    expect(named(items, 'Shared login')).toMatchObject({
        organizationId: organization.id,
        collectionIds: [collection.id],
        login: { username: 'team@example.com', password: 'team password' },
    });
});

test('the web vault shows what the CLI creates', async () => {
    const work = named(await cli.json<Named[]>(['list', 'folders']), 'Work');
    await cli.run(['create', 'item', Cli.encode({
        type: 1,
        name: 'Created by the CLI',
        folderId: work.id,
        notes: 'Notes from the CLI',
        login: { username: 'cli@example.com', password: 'cli password', uris: [] },
    })]);

    // At once, through the notifications hub.
    await expect(page.getByRole('main').getByRole('button', { name: 'Created by the CLI', exact: true })).toBeVisible();

    await page.reload();
    await unlock(page, account);
    const dialog = await openItem(page, 'Created by the CLI');
    await expect(dialog.getByRole('textbox', { name: 'Username' })).toHaveValue('cli@example.com');
    await expect(dialog.getByRole('textbox', { name: 'Note' })).toHaveValue('Notes from the CLI');
    await dialog.getByRole('button', { name: 'Close' }).first().click();
});

test('the CLI opens Sends and sends what the web vault opens', async ({ browser }) => {
    const sends = await cli.json<Named[]>(['send', 'list']);
    expect(sends.map((send) => send.name)).toEqual(['Example send']);
    expect((await cli.run(['receive', sendUrl])).trim()).toBe('Text of the Send');

    const sent = join(cli.appData, 'sent.txt');
    writeFileSync(sent, 'File sent by the CLI\n');
    const file = await cli.json<{ accessUrl: string }>(['send', '--file', sent, '--name', 'File from the CLI']);
    const text = await cli.json<{ accessUrl: string }>(
        ['send', '--name', 'Protected text', '--password', 'Send password', 'Text behind a password'],
    );

    const other = await newContext(browser);
    const anonymous = await other.newPage();
    await anonymous.goto(file.accessUrl);
    await expect(anonymous.getByText('sent.txt')).toBeVisible();
    const download = anonymous.waitForEvent('download');
    await anonymous.getByRole('button', { name: /Download/ }).click();
    expect(readFileSync(await (await download).path(), 'utf8')).toBe('File sent by the CLI\n');

    await anonymous.goto(text.accessUrl);
    await anonymous.getByRole('textbox', { name: /Password/ }).fill('Send password');
    await anonymous.getByRole('button', { name: 'Continue' }).click();
    await expect(anonymous.getByRole('main').getByRole('textbox')).toHaveValue('Text behind a password');
    await other.close();

    await cli.run(['logout']);
});
