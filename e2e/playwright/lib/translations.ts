// The table the phone-width translation checks walk (tests/accessibility/translations.spec.ts and
// translations.system.ts): a row for each language they check, holding its tag, a regional tag
// that reaches it, and the wording the walk expects, written out as the language's readers see it.
// Nothing here is read from the catalogs or the email definitions, so a changed translation fails
// the walk until its row says the new wording.
import type { Page } from "@playwright/test";
import { expect } from "@playwright/test";

export type Translation<Tag extends string = string> = {
  // The language's English name, which titles its tests.
  name: string;
  // The catalog's tag, the page's <html lang> and the ui_locales the walk asks for.
  tag: Tag;
  // A regional tag that reaches the catalog: the browser's Accept-Language and locale.
  regionalTag: `${NoInfer<Tag>}-${string}`;
  // The regional tag's entry in a user's Language and region list: what is typed, and the option.
  region: { typed: string; option: RegExp };
  // The console pages, with a client, a group, a resource and a user of the test's own.
  console: {
    attributeValue: string;
    // Appended to the client's identifier to open the confirmation dialog of a rename.
    renamedSuffix: string;
    cancel: string;
    // 5400 seconds, as the token lifetime's hint formats it.
    tokenLifetime: string;
    wholeSecondsRefusal: string;
    deleteResource: string;
    wrongResourceIdentifier: string;
  };
  // Sign-in, two-factor, consent and the auth server's public pages.
  signIn: {
    signIn: string;
    emailRequired: string;
    verifyOtp: string;
    saveRecoveryCodes: string;
    recoveryCodesShown: string;
    continue: string;
    consentTitle: string;
    allow: string;
    notRedirected: string;
    backToApplication: string;
    twoFactor: string;
    useRecoveryCodeLink: string;
    useRecoveryCodeTitle: string;
    verifyRecoveryCode: string;
    wrongRecoveryCode: string;
    signOut: string;
    signedOut: string;
  };
  // The account's two-factor page, in the page language the user chose.
  accountRecoveryCodes: {
    profileSaved: string;
    saveRecoveryCodes: string;
    recoveryCodes: string;
    tenOfTenUnused: string;
    newRecoveryCodesQuestion: string;
  };
  // The password reset email to a user of the regional tag, its form, and the verification wait.
  passwordReset: {
    sendLink: string;
    checkEmail: string;
    subject: string;
    sentence: string;
    setPassword: string;
    passwordSet: string;
    sendCode: string;
    // A wait of 90 seconds, as the verification page formats it.
    verificationWait: string;
    adminOnly: string;
  };
  // Self-registration, with and without email verification (the system project).
  registration: {
    title: string;
    register: string;
    checkEmail: string;
    activationSubject: string;
    choosePassword: string;
    activate: string;
    accountActivated: string;
    accountCreated: string;
  };
};

// Ties a row's regional tag to its own tag, so a row cannot ask for another language's region.
function row<Tag extends string>(translation: Translation<Tag>): Translation {
  return translation;
}

export const translations: readonly Translation[] = [
  row({
    name: "German",
    tag: "de",
    regionalTag: "de-AT",
    region: { typed: "German (Austria)", option: /German \(Austria\)/ },
    console: {
      attributeValue: "Forschung",
      renamedSuffix: "neu",
      cancel: "Abbrechen",
      tokenLifetime: "1 Stunde, 30 Minuten",
      wholeSecondsRefusal: "Geben Sie eine ganze Anzahl von Sekunden ein.",
      deleteResource: "Ressource löschen",
      wrongResourceIdentifier: "Das ist nicht die Kennung dieser Ressource.",
    },
    signIn: {
      signIn: "Anmelden",
      emailRequired: "Geben Sie eine E-Mail-Adresse ein.",
      verifyOtp: "Bestätigen",
      saveRecoveryCodes: "Speichern Sie Ihre Wiederherstellungscodes",
      recoveryCodesShown: "Ihre Wiederherstellungscodes wurden bereits angezeigt",
      continue: "Weiter",
      consentTitle: "Zugriff erlauben",
      allow: "Erlauben",
      notRedirected: "Sie wurden nicht weitergeleitet",
      backToApplication: "Zurück zur Anwendung",
      twoFactor: "Zwei-Faktor-Authentifizierung",
      useRecoveryCodeLink: "Stattdessen einen Wiederherstellungscode verwenden",
      useRecoveryCodeTitle: "Wiederherstellungscode verwenden",
      verifyRecoveryCode: "Bestätigen",
      wrongRecoveryCode: "Dieser Wiederherstellungscode ist falsch oder wurde bereits verwendet.",
      signOut: "Abmelden",
      signedOut: "Abgemeldet",
    },
    accountRecoveryCodes: {
      profileSaved: "Profil gespeichert.",
      saveRecoveryCodes: "Speichern Sie Ihre Wiederherstellungscodes",
      recoveryCodes: "Wiederherstellungscodes",
      tenOfTenUnused: "10 Ihrer 10 Wiederherstellungscodes sind noch unbenutzt.",
      newRecoveryCodesQuestion: "Neue Wiederherstellungscodes anfordern?",
    },
    passwordReset: {
      sendLink: "Link senden",
      checkEmail: "E-Mails prüfen",
      subject: "Passwort zurücksetzen",
      sentence: "um Ihr Passwort zurückzusetzen",
      setPassword: "Passwort festlegen",
      passwordSet: "Passwort festgelegt",
      sendCode: "Code senden",
      verificationWait: "Warten Sie 1 Minute, 30 Sekunden, bevor Sie einen neuen Code anfordern.",
      adminOnly: "Nur für die Administration",
    },
    registration: {
      title: "Konto erstellen",
      register: "Konto erstellen",
      checkEmail: "E-Mails prüfen",
      activationSubject: "Aktivieren Sie Ihr Konto",
      choosePassword: "Passwort wählen",
      activate: "Konto erstellen",
      accountActivated: "Konto aktiviert",
      accountCreated: "Konto erstellt",
    },
  }),
  row({
    name: "French",
    tag: "fr",
    regionalTag: "fr-CA",
    region: { typed: "French (Canada)", option: /French \(Canada\)/ },
    console: {
      attributeValue: "Recherche",
      renamedSuffix: "nouveau",
      cancel: "Annuler",
      tokenLifetime: "1 heure et 30 minutes",
      wholeSecondsRefusal: "Saisissez un nombre entier de secondes.",
      deleteResource: "Supprimer la ressource",
      wrongResourceIdentifier: "Ce n’est pas l’identifiant de cette ressource.",
    },
    signIn: {
      signIn: "Se connecter",
      emailRequired: "L’adresse e-mail est obligatoire.",
      verifyOtp: "Vérifier",
      saveRecoveryCodes: "Enregistrez vos codes de récupération",
      recoveryCodesShown: "Vos codes de récupération ont déjà été affichés",
      continue: "Continuer",
      consentTitle: "Autoriser l’accès",
      allow: "Autoriser",
      notRedirected: "Vous n’avez été redirigé nulle part",
      backToApplication: "Retour à l’application",
      twoFactor: "Authentification à deux facteurs",
      useRecoveryCodeLink: "Utiliser plutôt un code de récupération",
      useRecoveryCodeTitle: "Utiliser un code de récupération",
      verifyRecoveryCode: "Vérifier",
      wrongRecoveryCode: "Ce code de récupération est incorrect ou a déjà été utilisé.",
      signOut: "Se déconnecter",
      signedOut: "Déconnexion effectuée",
    },
    accountRecoveryCodes: {
      profileSaved: "Profil enregistré.",
      saveRecoveryCodes: "Enregistrez vos codes de récupération",
      recoveryCodes: "Codes de récupération",
      tenOfTenUnused: "10 de vos 10 codes de récupération ne sont pas encore utilisés.",
      newRecoveryCodesQuestion: "Obtenir de nouveaux codes de récupération ?",
    },
    passwordReset: {
      sendLink: "Envoyer le lien",
      checkEmail: "Consultez vos e-mails",
      subject: "Réinitialisation du mot de passe",
      sentence: "Pour réinitialiser votre mot de passe",
      setPassword: "Définir le mot de passe",
      passwordSet: "Mot de passe défini",
      sendCode: "Envoyer le code",
      verificationWait: "Patientez 1 minute et 30 secondes avant de demander un nouveau code.",
      adminOnly: "Accès réservé aux administrateurs",
    },
    registration: {
      title: "Créer un compte",
      register: "Créer le compte",
      checkEmail: "Consultez vos e-mails",
      activationSubject: "Activez votre compte",
      choosePassword: "Choisir votre mot de passe",
      activate: "Créer le compte",
      accountActivated: "Compte activé",
      accountCreated: "Compte créé",
    },
  }),
  row({
    name: "Italian",
    tag: "it",
    regionalTag: "it-CH",
    region: { typed: "Italian (Switzerland)", option: /Italian \(Switzerland\)/ },
    console: {
      attributeValue: "Ricerca",
      renamedSuffix: "nuovo",
      cancel: "Annulla",
      tokenLifetime: "1 ora e 30 minuti",
      wholeSecondsRefusal: "Inserisci un numero intero di secondi.",
      deleteResource: "Elimina risorsa",
      wrongResourceIdentifier: "Questo non è l'identificatore della risorsa.",
    },
    signIn: {
      signIn: "Accedi",
      emailRequired: "L'email è obbligatoria",
      verifyOtp: "Verifica",
      saveRecoveryCodes: "Salva i tuoi codici di recupero",
      recoveryCodesShown: "I tuoi codici di recupero sono già stati mostrati",
      continue: "Continua",
      consentTitle: "Consenti l'accesso",
      allow: "Consenti",
      notRedirected: "Non è stato effettuato alcun reindirizzamento",
      backToApplication: "Ritorno all'applicazione",
      twoFactor: "Autenticazione a due fattori",
      useRecoveryCodeLink: "Usa invece un codice di recupero",
      useRecoveryCodeTitle: "Usa un codice di recupero",
      verifyRecoveryCode: "Verifica",
      wrongRecoveryCode: "Il codice di recupero non è corretto o è già stato usato.",
      signOut: "Esci",
      signedOut: "Disconnessione completata",
    },
    accountRecoveryCodes: {
      profileSaved: "Profilo salvato.",
      saveRecoveryCodes: "Salva i codici di recupero",
      recoveryCodes: "Codici di recupero",
      tenOfTenUnused: "10 dei tuoi 10 codici di recupero non sono ancora stati usati.",
      newRecoveryCodesQuestion: "Ottenere nuovi codici di recupero?",
    },
    passwordReset: {
      sendLink: "Invia il link",
      checkEmail: "Controlla la tua email",
      subject: "Reimpostazione della password",
      sentence: "Per reimpostare la password",
      setPassword: "Imposta password",
      passwordSet: "Password impostata",
      sendCode: "Invia codice",
      verificationWait: "Attendi 1 minuto e 30 secondi prima di richiedere un altro codice.",
      adminOnly: "Solo amministratori",
    },
    registration: {
      title: "Crea un account",
      register: "Crea account",
      checkEmail: "Controlla la tua email",
      activationSubject: "Attiva il tuo account",
      choosePassword: "Scegli la password",
      activate: "Crea account",
      accountActivated: "Account attivato",
      accountCreated: "Account creato",
    },
  }),
  row({
    name: "Indonesian",
    tag: "id",
    regionalTag: "id-ID",
    region: { typed: "Indonesian (Indonesia)", option: /Indonesian \(Indonesia\)/ },
    console: {
      attributeValue: "Penelitian",
      renamedSuffix: "baru",
      cancel: "Batal",
      tokenLifetime: "1 jam, 30 menit",
      wholeSecondsRefusal: "Masukkan bilangan bulat dalam detik.",
      deleteResource: "Hapus sumber daya",
      wrongResourceIdentifier: "Itu bukan pengenal sumber daya ini.",
    },
    signIn: {
      signIn: "Masuk",
      emailRequired: "Email wajib diisi.",
      verifyOtp: "Verifikasi",
      saveRecoveryCodes: "Simpan kode pemulihan Anda",
      recoveryCodesShown: "Kode pemulihan Anda sudah ditampilkan",
      continue: "Lanjutkan",
      consentTitle: "Izinkan akses",
      allow: "Izinkan",
      notRedirected: "Anda tidak dikirim ke mana pun",
      backToApplication: "Mengembalikan Anda ke aplikasi",
      twoFactor: "Autentikasi dua faktor",
      useRecoveryCodeLink: "Gunakan kode pemulihan",
      useRecoveryCodeTitle: "Gunakan kode pemulihan",
      verifyRecoveryCode: "Verifikasi",
      wrongRecoveryCode: "Kode pemulihan itu salah, atau sudah pernah digunakan.",
      signOut: "Keluar",
      signedOut: "Sudah keluar",
    },
    accountRecoveryCodes: {
      profileSaved: "Profil disimpan.",
      saveRecoveryCodes: "Simpan kode pemulihan Anda",
      recoveryCodes: "Kode pemulihan",
      tenOfTenUnused: "10 dari 10 kode pemulihan Anda belum digunakan.",
      newRecoveryCodesQuestion: "Buat kode pemulihan baru?",
    },
    passwordReset: {
      sendLink: "Kirim tautan atur ulang",
      checkEmail: "Periksa email Anda",
      subject: "Atur ulang kata sandi",
      sentence: "mengatur ulang kata sandi Anda",
      setPassword: "Tetapkan kata sandi",
      passwordSet: "Kata sandi ditetapkan",
      sendCode: "Kirim kode",
      verificationWait: "Tunggu 1 menit, 30 detik sebelum meminta kode lain.",
      adminOnly: "Khusus administrator",
    },
    registration: {
      title: "Buat akun",
      register: "Buat akun",
      checkEmail: "Periksa email Anda",
      activationSubject: "Aktifkan akun Anda",
      choosePassword: "Pilih kata sandi Anda",
      activate: "Buat akun",
      accountActivated: "Akun diaktifkan",
      accountCreated: "Akun dibuat",
    },
  }),
];

// The page is in the row's language and fits the viewport: the page does not scroll sideways, and
// no visible button, tab, table header, page title, open dialog or alert overflows, except one
// inside a table that scrolls sideways by design. No untranslated message key shows.
export async function fitsIn(page: Page, translation: Translation) {
  await expect(page.locator("html")).toHaveAttribute("lang", translation.tag);
  await expect(page.locator("h1")).toBeVisible();
  // Let tab-bar wrapping and searchable selects finish their initial layout.
  await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
  const overflow = await page.evaluate(() => {
    const width = document.documentElement.clientWidth;
    const problems: string[] = [];
    if (document.documentElement.scrollWidth > width) problems.push("page scrolls horizontally");
    for (const element of document.querySelectorAll<HTMLElement>("button, .tab-item, th, .page-title, dialog[open], [role=alert]")) {
      if (!element.checkVisibility() || element.closest(".table-scroll") || element.classList.contains("sr-only")) continue;
      const box = element.getBoundingClientRect();
      if (box.right <= 0 || box.width <= 1) continue;
      if (box.left < -1 || box.right > width + 1 || element.scrollWidth > element.clientWidth + 1) {
        problems.push(`${element.tagName}: ${element.textContent?.trim().slice(0, 90)}`);
      }
    }
    return problems;
  });
  expect(overflow, page.url()).toEqual([]);
  await expect(page.locator("body")).not.toContainText(/\b(?:adminconsole|validator|handler)\.[a-z_]+\./);
}
