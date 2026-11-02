import { test, expect, type BrowserContext, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Cli, named, type Item, type Named } from './support/cli';
import { link, waitForMail } from './support/mail';
import {
    choose, clearTheWay, createAccount, expectToast, expectVault, newContext, newItem, openItem, type Account,
} from './support/web-vault';

// Two accounts, each in a browser of its own: the owner of an organization, who invites the other as
// a member, makes it an emergency contact and hands it an export of the vault. Invitations go by mail,
// and the accounts follow their links.
test.describe.configure({ mode: 'serial' });

const owner: Account = {
    email: `owner.${Date.now()}@example.com`,
    name: 'Owner Example',
    password: 'Owner master password of the clients test 4e8b',
};
const member: Account = {
    email: `member.${Date.now()}@example.com`,
    name: 'Member Example',
    password: 'Member master password of the clients test 61dc',
};
const cli = new Cli();

let ownerContext: BrowserContext;
let memberContext: BrowserContext;
let ownerPage: Page;
let memberPage: Page;
let membersUrl: string;
let memberFingerprint: string;
let exported: { folders: Named[]; items: Item[] };

test.beforeAll(async ({ browser }) => {
    ownerContext = await newContext(browser);
    memberContext = await newContext(browser);
    for (const context of [ownerContext, memberContext]) {
        await context.tracing.start({ screenshots: true, snapshots: true });
    }
    ownerPage = await ownerContext.newPage();
    memberPage = await memberContext.newPage();
    await clearTheWay(ownerPage);
    await clearTheWay(memberPage);
});

test.afterAll(async () => {
    await ownerContext.tracing.stop({ path: join('test-results', 'sharing-owner-trace.zip') });
    await memberContext.tracing.stop({ path: join('test-results', 'sharing-member-trace.zip') });
    await ownerContext.close();
    await memberContext.close();
});

/** Opens a page of the web vault again, which loads what it shows anew, without a reload that locks the vault. */
async function revisit(page: Page, url: string): Promise<void> {
    await page.goto('/#/vault');
    await expectVault(page);
    await page.goto(url);
}

test('the owner keeps items and an organization', async () => {
    await createAccount(ownerPage, owner);

    let dialog = await newItem(ownerPage, 'Folder');
    await dialog.getByRole('textbox', { name: /Folder name/ }).fill('Personal');
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expectToast(ownerPage, 'Folder saved');

    dialog = await newItem(ownerPage, 'Login');
    await dialog.getByRole('textbox', { name: /Item name/ }).fill('Personal login');
    await choose(ownerPage, dialog.getByRole('combobox', { name: 'Folder' }), 'Personal');
    await dialog.getByRole('textbox', { name: 'Username' }).fill('owner@example.com');
    await dialog.getByRole('textbox', { name: 'Password' }).fill('personal password');
    await dialog.getByRole('textbox', { name: 'Website (URI)' }).fill('https://personal.example.com');
    await dialog.getByRole('textbox', { name: 'Notes' }).fill('Notes of the personal login');
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expect(dialog.getByRole('heading', { name: 'View Login' })).toBeVisible();
    await dialog.getByRole('button', { name: 'Close' }).first().click();

    dialog = await newItem(ownerPage, 'Note');
    await dialog.getByRole('textbox', { name: /Item name/ }).fill('Personal note');
    await dialog.getByRole('textbox', { name: 'Notes' }).fill('Kept for emergencies');
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expect(dialog.getByRole('heading', { name: 'View Note' })).toBeVisible();
    await dialog.getByRole('button', { name: 'Close' }).first().click();

    await ownerPage.getByRole('link', { name: 'New organization' }).click();
    await ownerPage.getByRole('textbox', { name: /Organization name/ }).fill('Sharing Org');
    await ownerPage.getByRole('button', { name: 'Submit' }).click();
    await expect(ownerPage.getByRole('heading', { name: 'Sharing Org collections' })).toBeVisible();
    membersUrl = ownerPage.url().replace(/\/vault$/, '/members');

    await ownerPage.goto('/#/vault');
    await expectVault(ownerPage);
    dialog = await newItem(ownerPage, 'Login');
    await dialog.getByRole('textbox', { name: /Item name/ }).fill('Team login');
    // Encrypted with the organization's key from the start.
    await choose(ownerPage, dialog.getByRole('combobox', { name: 'Owner' }), 'Sharing Org');
    // Which takes the only collection.
    await expect(dialog.getByRole('button', { name: 'Remove Default collection' })).toBeVisible();
    await dialog.getByRole('textbox', { name: 'Username' }).fill('team@example.com');
    await dialog.getByRole('textbox', { name: 'Password' }).fill('team password');
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expect(dialog.getByRole('heading', { name: 'View Login' })).toBeVisible();
    await dialog.getByRole('button', { name: 'Close' }).first().click();
    await expect(ownerPage.getByRole('row', { name: /Team login/ }).getByRole('button', { name: /Owner, Sharing Org/ })).toBeVisible();
});

test('invites a member, who joins with a new account from the mail', async () => {
    await ownerPage.goto(membersUrl);
    await ownerPage.getByRole('main').getByRole('button', { name: /Invite member/ }).click();
    // Since web vault 2026.10 one dialog "Invite members", with the collections under "More settings".
    const dialog = ownerPage.getByRole('dialog', { name: 'Invite members' });
    await dialog.getByRole('textbox', { name: /Email/ }).fill(member.email);
    await dialog.getByRole('button', { name: 'More settings' }).click();
    await choose(ownerPage, dialog.getByRole('combobox', { name: 'Collections' }), 'Default collection');
    // The list stays open for more collections.
    await dialog.getByRole('heading', { name: 'Invite members' }).click();
    await expect(dialog.getByRole('row', { name: /Default collection/ })).toBeVisible();
    await dialog.getByRole('button', { name: 'Invite', exact: true }).click();
    await expectToast(ownerPage, 'User(s) invited');

    // There is no account yet: the link leads to the registration.
    const invitation = await waitForMail(member.email, /^Join Sharing Org$/);
    await memberPage.goto(link(invitation, '/accept-organization'));
    await expect(memberPage.getByRole('heading', { name: 'Join Sharing Org' })).toBeVisible();
    await memberPage.getByRole('textbox', { name: 'Master password * (required)', exact: true }).fill(member.password);
    await memberPage.getByRole('textbox', { name: /Confirm master password/ }).fill(member.password);
    await memberPage.getByRole('checkbox', { name: 'Check known data breaches for this password' }).uncheck();
    await memberPage.getByRole('button', { name: 'Create account' }).click();
    await expectVault(memberPage);
    await expectToast(memberPage, 'Successfully accepted your invitation.');
    await waitForMail(owner.email, /^Invitation to Sharing Org accepted$/);

    // Signing up from an invitation asks for no name.
    await memberPage.goto('/#/settings/account');
    await expect(memberPage.getByRole('textbox', { name: 'Name' })).toHaveValue(member.email);
    await memberPage.getByRole('textbox', { name: 'Name' }).fill(member.name);
    await memberPage.getByRole('main').getByRole('button', { name: 'Save' }).click();
    await expectToast(memberPage, 'Account saved');
    // Derived from the account's own public key.
    memberFingerprint = await memberPage.getByRole('main').getByRole('code').innerText();
});

test('confirms the member, who decrypts the shared item', async () => {
    await revisit(ownerPage, membersUrl);
    // The list sorts its rows once it has them all, which can move the owner's row under the pointer; the
    // filter leaves the member's alone. Its radio buttons hide behind labels that show nothing but a count.
    const filter = ownerPage.getByRole('radiogroup', { name: 'Member status filter' });
    await filter.locator('label[aria-label="Needs confirmation"]').click();
    await expect(filter.getByRole('radio', { name: 'Needs confirmation' })).toBeChecked();
    const row = ownerPage.getByRole('row', { name: new RegExp(member.email) });
    await expect(row.getByText('Needs confirmation')).toBeVisible();
    await row.getByRole('button', { name: 'Options' }).click();
    await ownerPage.getByRole('menuitem', { name: 'Confirm' }).click();
    // The owner encrypts the organization's key with the public key the server hands out for the member.
    const dialog = ownerPage.getByRole('dialog', { name: /Confirm user/ });
    await expect(dialog.getByRole('code')).toHaveText(memberFingerprint);
    await dialog.getByRole('button', { name: 'Confirm' }).click();
    await expectToast(ownerPage, `${member.name} confirmed.`);
    await waitForMail(member.email, /^Invitation to Sharing Org confirmed$/);

    await revisit(memberPage, '/#/vault');
    const item = await openItem(memberPage, 'Team login');
    await expect(item.getByRole('textbox', { name: 'Username' })).toHaveValue('team@example.com');
    await item.getByRole('button', { name: 'Toggle visibility' }).click();
    // Each character in a colour of its kind, followed by what a screen reader reads.
    await expect(item.getByRole('textbox', { name: 'Password' })).toHaveText(/^team password/);
    await item.getByRole('button', { name: 'Close' }).first().click();

    await cli.run(['config', 'server', process.env.VW_CLIENTS_URL!]);
    cli.session = (await cli.run(
        ['login', member.email, '--passwordenv', 'BW_TEST_PASSWORD', '--raw'],
        { BW_TEST_PASSWORD: member.password },
    )).trim();
    expect(cli.session).not.toBe('');
    const organization = named(await cli.json<Named[]>(['list', 'organizations']), 'Sharing Org');
    const items = await cli.json<Item[]>(['list', 'items']);
    expect(items.map((entry) => entry.name)).toEqual(['Team login']);
    expect(items[0]).toMatchObject({
        organizationId: organization.id,
        login: { username: 'team@example.com', password: 'team password' },
    });
});

test('makes the member an emergency contact, who accepts from the mail', async () => {
    await ownerPage.goto('/#/settings/emergency-access');
    await ownerPage.getByRole('button', { name: 'Add emergency contact' }).click();
    const dialog = ownerPage.getByRole('dialog', { name: 'Invite emergency contact' });
    await dialog.getByRole('textbox', { name: /Email/ }).fill(member.email);
    await dialog.getByRole('radio', { name: /^View/ }).check();
    await choose(ownerPage, dialog.getByRole('combobox', { name: /Wait time/ }), '1 day');
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expectToast(ownerPage, 'User(s) invited');

    // The account exists now and is logged in: following the link accepts.
    const invitation = await waitForMail(member.email, new RegExp(`^Emergency access for ${owner.name}$`));
    await memberPage.goto(link(invitation, '/accept-emergency'));
    await expectToast(memberPage, 'Invitation accepted');
    await waitForMail(owner.email, new RegExp(`^Emergency access contact ${member.email} accepted$`));

    await revisit(ownerPage, '/#/settings/emergency-access');
    const row = ownerPage.getByRole('row', { name: new RegExp(member.name) });
    await expect(row.getByText('Needs confirmation')).toBeVisible();
    await row.getByRole('button', { name: 'Options' }).click();
    await ownerPage.getByRole('menuitem', { name: 'Confirm' }).click();
    // The owner encrypts its account key with the contact's public key.
    const confirmation = ownerPage.getByRole('dialog', { name: /Confirm user/ });
    await expect(confirmation.getByRole('code')).toHaveText(memberFingerprint);
    await confirmation.getByRole('button', { name: 'Confirm' }).click();
    await waitForMail(member.email, new RegExp(`^Emergency access contact for ${owner.name} confirmed$`));
});

test('the contact views the vault once the owner approves the request', async () => {
    await memberPage.goto('/#/settings/emergency-access');
    let row = memberPage.getByRole('row', { name: new RegExp(owner.name) });
    await row.getByRole('button', { name: 'Options' }).click();
    await memberPage.getByRole('menuitem', { name: 'Request Access' }).click();
    await memberPage.getByRole('dialog').getByRole('button', { name: 'Request Access' }).click();
    await expect(row.getByText('Emergency access initiated')).toBeVisible();
    await waitForMail(owner.email, new RegExp(`^Emergency access request by ${member.name} initiated$`));

    // The owner need not wait for the day to pass.
    await revisit(ownerPage, '/#/settings/emergency-access');
    row = ownerPage.getByRole('row', { name: new RegExp(member.name) });
    await row.getByRole('button', { name: 'Options' }).click();
    await ownerPage.getByRole('menuitem', { name: 'Approve' }).click();
    await ownerPage.getByRole('dialog').getByRole('button', { name: 'Approve' }).click();
    await expectToast(ownerPage, 'Emergency access approved');
    await waitForMail(member.email, new RegExp(`^Emergency access request for ${owner.name} approved$`));

    await revisit(memberPage, '/#/settings/emergency-access');
    row = memberPage.getByRole('row', { name: new RegExp(owner.name) });
    await row.getByRole('button', { name: 'Options' }).click();
    await memberPage.getByRole('menuitem', { name: 'View' }).click();
    // The owner's own items, decrypted with the account key the confirmation handed over; not the
    // organization's.
    await expect(memberPage.getByRole('heading', { name: 'Vault', level: 1 })).toBeVisible();
    const main = memberPage.getByRole('main');
    await expect(main.getByRole('link', { name: 'Personal login', exact: true })).toBeVisible();
    await expect(main.getByRole('link', { name: 'Personal note', exact: true })).toBeVisible();
    await expect(main.getByRole('row')).toHaveCount(2);
    await main.getByRole('link', { name: 'Personal login', exact: true }).click();
    const item = memberPage.getByRole('dialog');
    await expect(item.getByRole('heading', { name: 'Personal login', exact: true })).toBeVisible();
    await expect(item.getByRole('textbox', { name: 'Username' })).toHaveValue('owner@example.com');
    await item.getByRole('button', { name: 'Toggle visibility' }).click();
    await expect(item.getByRole('textbox', { name: 'Password' })).toHaveText(/^personal password/);
    await item.getByRole('button', { name: 'Close' }).first().click();
});

test('exports the vault as JSON, plain and protected by a password', async () => {
    await ownerPage.goto('/#/tools/export');
    await ownerPage.getByRole('combobox', { name: /File format/ }).selectOption('.json');
    let download = ownerPage.waitForEvent('download');
    await ownerPage.getByRole('main').getByRole('button', { name: 'Export' }).click();
    await confirmExport(ownerPage);
    exported = JSON.parse(readFileSync(await (await download).path(), 'utf8'));
    expect(exported).toMatchObject({ encrypted: false });
    // Only the owner's own items.
    expect(exported.folders.map((folder) => folder.name)).toEqual(['Personal']);
    expect(exported.items.map((item) => item.name).sort()).toEqual(['Personal login', 'Personal note']);
    expect(named(exported.items, 'Personal login')).toMatchObject({
        folderId: exported.folders[0].id,
        notes: 'Notes of the personal login',
        login: { username: 'owner@example.com', password: 'personal password', uris: [{ uri: 'https://personal.example.com' }] },
    });

    await ownerPage.getByRole('combobox', { name: /File format/ }).selectOption('.json (Encrypted)');
    await ownerPage.getByRole('radio', { name: /Password protected/ }).check();
    await ownerPage.getByRole('textbox', { name: /^File password/ }).fill('Export password of the clients test');
    await ownerPage.getByRole('textbox', { name: /Confirm file password/ }).fill('Export password of the clients test');
    download = ownerPage.waitForEvent('download');
    await ownerPage.getByRole('main').getByRole('button', { name: 'Export' }).click();
    await confirmExport(ownerPage);
    const file = join(cli.appData, 'protected-export.json');
    await (await download).saveAs(file);
    expect(JSON.parse(readFileSync(file, 'utf8'))).toMatchObject({ encrypted: true, passwordProtected: true });
});

async function confirmExport(page: Page): Promise<void> {
    const dialog = page.getByRole('dialog', { name: 'Confirm vault export' });
    await dialog.getByRole('textbox', { name: /Master password/ }).fill(owner.password);
    await dialog.getByRole('button', { name: 'Continue' }).click();
}

test('the member imports the protected export, which the CLI lists', async () => {
    await memberPage.goto('/#/tools/import');
    await choose(memberPage, memberPage.getByRole('combobox', { name: /File format/ }), 'Bitwarden (json)');
    await memberPage.locator('input[type=file]').setInputFiles(join(cli.appData, 'protected-export.json'));
    await memberPage.getByRole('main').getByRole('button', { name: 'Import', exact: true }).click();
    const dialog = memberPage.getByRole('dialog', { name: 'Confirm vault import' });
    await dialog.getByRole('textbox', { name: /Confirm file password/ }).fill('Export password of the clients test');
    await dialog.getByRole('button', { name: 'Import' }).click();
    const result = memberPage.getByRole('dialog', { name: 'Data successfully imported' });
    await expect(result.getByText('A total of 2 items were imported.')).toBeVisible();
    await expect(result.getByRole('row', { name: 'Folders 1' })).toBeVisible();
    await result.getByRole('button', { name: 'Ok' }).click();

    await cli.run(['sync']);
    const folders = await cli.json<Named[]>(['list', 'folders']);
    const personal = named(folders, 'Personal');
    const items = await cli.json<Item[]>(['list', 'items', '--organizationid', 'null']);
    expect(items.map((item) => item.name).sort()).toEqual(exported.items.map((item) => item.name).sort());
    for (const item of exported.items) {
        const imported = named(items, item.name);
        expect(imported).toMatchObject({ type: item.type, notes: item.notes });
        expect(imported.folderId ?? null).toBe(item.folderId ? personal.id : null);
        if (item.login) {
            expect(imported.login).toMatchObject({
                username: item.login.username,
                password: item.login.password,
                uris: item.login.uris.map((uri) => ({ uri: uri.uri })),
            });
        }
    }

    await cli.run(['logout']);
});
