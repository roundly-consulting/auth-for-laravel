<?php

declare(strict_types=1);

return [
    'code_line' => 'Váš kód: :code',
    'expiry' => 'Platnosť vyprší o :minutes min.',

    'magic_link' => [
        'subject' => 'Váš prihlasovací odkaz do aplikácie :app',
        'intro' => 'Pomocou tlačidla nižšie sa prihláste do aplikácie :app.',
        'action' => 'Prihlásiť sa',
        'outro' => 'Ak ste o to nežiadali, tento e-mail môžete ignorovať.',
    ],
    'email_otp' => [
        'subject' => 'Váš prihlasovací kód do aplikácie :app',
        'intro' => 'Pomocou tohto kódu pokračujte v prihlasovaní do aplikácie :app.',
        'action' => 'Pokračovať',
        'outro' => 'Ak ste o to nežiadali, tento e-mail môžete ignorovať.',
    ],
    'verify_email' => [
        'subject' => 'Overte svoju e-mailovú adresu',
        'intro' => 'Potvrďte, že táto e-mailová adresa patrí vám.',
        'action' => 'Overiť e-mailovú adresu',
        'outro' => 'Ak ste si účet nevytvorili, nie je potrebné nič robiť.',
    ],
    'reset_password' => [
        'subject' => 'Obnovenie hesla do aplikácie :app',
        'intro' => 'Dostali sme žiadosť o obnovenie hesla k vášmu účtu.',
        'action' => 'Obnoviť heslo',
        'outro' => 'Ak ste o obnovenie hesla nežiadali, nie je potrebné nič robiť.',
    ],
    'password_changed' => [
        'subject' => 'Vaše heslo do aplikácie :app bolo zmenené',
        'intro' => 'Heslo k vášmu účtu bolo práve zmenené.',
        'action' => 'Skontrolovať účet',
        'outro' => 'Ak ste to neboli vy, okamžite si obnovte heslo.',
    ],
    'email_change_confirmation' => [
        'subject' => 'Potvrďte svoju novú e-mailovú adresu',
        'intro' => 'Potvrďte, že chcete túto adresu používať pre svoj účet v aplikácii :app.',
        'action' => 'Potvrdiť e-mailovú adresu',
        'outro' => 'Ak ste o túto zmenu nežiadali, tento e-mail môžete ignorovať.',
    ],
    'email_change_requested' => [
        'subject' => 'Žiadosť o zmenu e-mailovej adresy vášho účtu v aplikácii :app',
        'intro' => 'Niekto požiadal o zmenu e-mailovej adresy vášho účtu na :new_email.',
        'action' => 'Skontrolovať účet',
        'outro' => 'Ak ste to neboli vy, zmeňte si heslo a kontaktujte podporu.',
    ],
    'email_changed' => [
        'subject' => 'E-mailová adresa vášho účtu v aplikácii :app bola zmenená',
        'intro' => 'E-mailová adresa vášho účtu bola zmenená na :new_email.',
        'action' => 'Skontrolovať účet',
        'outro' => 'Ak ste to neboli vy, okamžite kontaktujte podporu.',
    ],
    'account_exists' => [
        'subject' => 'V aplikácii :app už máte účet',
        'intro' => 'Niekto sa pokúsil použiť túto e-mailovú adresu pre nový účet alebo pri zmene e-mailu, ale už ju používa existujúci účet.',
        'action' => 'Prihlásiť sa',
        'outro' => 'Ak ste to neboli vy, tento e-mail môžete ignorovať.',
    ],
    'invitation' => [
        'subject' => 'Pozvánka do aplikácie :app',
        'intro' => 'Dostali ste pozvánku na vytvorenie účtu.',
        'action' => 'Prijať pozvánku',
        'outro' => 'Ak ste túto pozvánku nečakali, tento e-mail môžete ignorovať.',
    ],
    'new_device' => [
        'subject' => 'Nové prihlásenie do vášho účtu v aplikácii :app',
        'intro' => 'Do vášho účtu sa práve prihlásilo nové zariadenie (:ip, :user_agent), čas prihlásenia: :time.',
        'action' => 'Skontrolovať relácie',
        'outro' => 'Ak ste to neboli vy, odhláste sa na všetkých zariadeniach a zmeňte si heslo.',
    ],
    'two_factor_enabled' => [
        'subject' => 'Dvojfaktorové overenie bolo zapnuté',
        'intro' => 'Vo vašom účte bolo zapnuté dvojfaktorové overenie.',
        'action' => 'Skontrolovať účet',
        'outro' => 'Ak ste to neboli vy, okamžite kontaktujte podporu.',
    ],
    'two_factor_disabled' => [
        'subject' => 'Dvojfaktorové overenie bolo vypnuté',
        'intro' => 'Vo vašom účte bolo vypnuté dvojfaktorové overenie.',
        'action' => 'Skontrolovať účet',
        'outro' => 'Ak ste to neboli vy, okamžite kontaktujte podporu.',
    ],
    'recovery_code_used' => [
        'subject' => 'Bol použitý záchranný kód',
        'intro' => 'Na prihlásenie do vášho účtu bol práve použitý záchranný kód. Zostávajúce záchranné kódy: :remaining.',
        'action' => 'Skontrolovať účet',
        'outro' => 'Ak ste to neboli vy, okamžite kontaktujte podporu.',
    ],
    'passkey_added' => [
        'subject' => 'K vášmu účtu bol pridaný prístupový kľúč',
        'intro' => 'Na prihlásenie do vášho účtu teraz možno použiť nový prístupový kľúč.',
        'action' => 'Skontrolovať prístupové kľúče',
        'outro' => 'Ak ste to neboli vy, okamžite kontaktujte podporu.',
    ],
    'passkey_removed' => [
        'subject' => 'Z vášho účtu bol odstránený prístupový kľúč',
        'intro' => 'Z vášho účtu bol odstránený prístupový kľúč.',
        'action' => 'Skontrolovať prístupové kľúče',
        'outro' => 'Ak ste to neboli vy, okamžite kontaktujte podporu.',
    ],
    'account_locked' => [
        'subject' => 'Váš účet v aplikácii :app bol zablokovaný',
        'intro' => 'Váš účet bol po príliš veľkom počte neúspešných pokusov o prihlásenie dočasne zablokovaný.',
        'action' => 'Obnoviť heslo',
        'outro' => 'Ak ste tieto pokusy nevykonali vy, zvážte zmenu hesla.',
    ],
    'refresh_token_reuse' => [
        'subject' => 'Podozrivá aktivita vo vašom účte v aplikácii :app',
        'intro' => 'Vo vašom účte sme zaznamenali podozrivú aktivitu (:reason) a dotknutú reláciu sme odhlásili.',
        'action' => 'Skontrolovať relácie',
        'outro' => 'Ak ste to neboli vy, odhláste sa na všetkých zariadeniach a zmeňte si heslo.',
    ],
];
